"""Signed cursors for resuming a cut list (design §7.3, T1 D10).

A cursor is `base64url(payload) + "." + base64url(tag)`, the tag being the first 128 bits of
HMAC-SHA256 over the encoded payload with `MCP_CURSOR_KEY`. The payload binds the caller, tool,
command and a hash of the original args, and holds the resolved path params, the **query string**
of the page the last delivered item came from, and how many of that page's items were delivered.

A cursor never holds a path or a host. On resume the URL is the operation's template expanded
with the cursor's path params (through the same character rule as a first call) on the Okta org,
plus the stored query, so even a cursor signed with a leaked key can't send the service token
off the operation's path. The tag is checked before the payload is decoded.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any, cast

import httpx2

from okta_mcp.exec.params import build_url, path_segment
from okta_mcp.okta.client import on_origin
from okta_mcp.registry.loader import Command
from okta_mcp.registry.schema import InvalidArguments

CURSOR_TTL = 900
"""Seconds a cursor is good for."""
RESUMED_WARNING = "resumed list: items may repeat or be missing if it changed since the first call"
"""For `warnings` on every resumed response."""

_VERSION = 1
_TAG_BYTES = 16
_KEYS = frozenset("vutcapqse")
_INVALID = "cursor is not valid for this call; run the command again without it"
NOT_VALID = _INVALID
"""The message for a cursor that can't be used for this call, whatever the reason."""
_EXPIRED = "cursor has expired; run the command again without it"
_OTHER_ARGS = "cursor was issued for other args; resend the same args, or drop the cursor"


class CursorError(Exception):
    """A cursor that can't be used for this call; nothing was sent to Okta. The message is safe
    to return to the caller (`invalid_arguments`)."""


@dataclass(frozen=True)
class Resume:
    """Where a verified cursor says to continue."""

    path_params: Mapping[str, str]
    """Spec path parameter → resolved value, not yet encoded."""
    query: str
    """Query string of the page to fetch again, as it was sent."""
    skip: int
    """Items of that page already delivered."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _args_hash(args: Mapping[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return _b64(hashlib.sha256(canonical.encode("ascii")).digest()[:16])


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _payload(body: str) -> dict[str, Any] | None:
    """The payload of an authentic cursor, or None if it isn't this version's shape."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (binascii.Error, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    p = cast(dict[str, Any], payload)
    if p.keys() != _KEYS:
        return None
    path_params = p["p"]
    ok = (
        _is_int(p["v"])
        and p["v"] == _VERSION
        and all(isinstance(p[k], str) for k in "utcaq")
        and isinstance(path_params, dict)
        and all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in cast(dict[object, object], path_params).items()
        )
        and _is_int(p["s"])
        and p["s"] >= 0
        and _is_int(p["e"])
    )
    return p if ok else None


class Cursors:
    """Issues and verifies cursors with one key. Rotating the key (new key, restart) voids the
    cursors outstanding, which callers handle by running the command again."""

    def __init__(self, key: bytes, *, clock: Callable[[], float] = time.time) -> None:
        if len(key) < 32:
            raise ValueError("cursor key must be at least 32 bytes")
        self._key = key
        self._clock = clock

    def _tag(self, body: str) -> str:
        return _b64(hmac.digest(self._key, body.encode("ascii"), "sha256")[:_TAG_BYTES])

    def issuer(
        self,
        *,
        uid: str,
        tool: str,
        command: str,
        args: Mapping[str, Any],
        path_params: Mapping[str, str],
    ) -> Callable[[str, int], str]:
        """For one call, the function `list_result` takes as `next_cursor`: given a `page` and
        an item's `index` in it (as `paginate` yields them), the cursor that resumes after that
        item. `args` are the caller's original args; `path_params` (see `path_params`) the
        resolved values the first request was built from. Only the query of `page` is kept."""
        bound: dict[str, Any] = {
            "v": _VERSION,
            "u": uid,
            "t": tool,
            "c": command,
            "a": _args_hash(args),
            "p": dict(path_params),
        }

        def issue(page: str, index: int) -> str:
            payload = bound | {
                "q": page.partition("?")[2],
                "s": index + 1,
                "e": int(self._clock()) + CURSOR_TTL,
            }
            body = _b64(json.dumps(payload, separators=(",", ":")).encode("ascii"))
            return f"{body}.{self._tag(body)}"

        return issue

    def issue(
        self,
        page: str,
        index: int,
        *,
        uid: str,
        tool: str,
        command: str,
        args: Mapping[str, Any],
        path_params: Mapping[str, str],
    ) -> str:
        """One cursor; `issuer(...)(page, index)`."""
        return self.issuer(uid=uid, tool=tool, command=command, args=args, path_params=path_params)(
            page, index
        )

    def open(
        self, cursor: str, *, uid: str, tool: str, command: str, args: Mapping[str, Any]
    ) -> Resume:
        """Verify `cursor` for this caller, tool, command and resent `args`. Raises `CursorError`;
        a forged cursor, another caller's and another command's are told apart from nothing."""
        body, dot, tag = cursor.partition(".")
        # Compared as text: decoding first would accept a tag with other trailing bits.
        if (
            not dot
            or not cursor.isascii()
            or not hmac.compare_digest(tag.encode("ascii"), self._tag(body).encode("ascii"))
        ):
            raise CursorError(_INVALID)
        payload = _payload(body)  # None for an authentic cursor of another format version
        if payload is None or (payload["u"], payload["t"], payload["c"]) != (uid, tool, command):
            raise CursorError(_INVALID)
        if self._clock() >= payload["e"]:
            raise CursorError(_EXPIRED)
        if payload["a"] != _args_hash(args):  # authentic and the caller's own: no secret here
            raise CursorError(_OTHER_ARGS)
        return Resume(payload["p"], payload["q"], payload["s"])


def path_params(command: Command, args: Mapping[str, Any]) -> dict[str, str]:
    """The cursor's `path_params` for `command` called with `args`: spec path parameter → value.
    `args` are the ones the request was built from, so a `resolve: user_id` arg must hold the
    resolved ID, as for `build_request`."""
    return {
        param: args[name]
        for name, arg in command.entry.args.items()
        if (param := arg.path_param) is not None and name in args
    }


def resumable(command: Command, args: Mapping[str, Any]) -> bool:
    """Whether a cut of this list command, called with `args`, gets a cursor (design §7.2). Never
    with an `unpaged_args` arg: Okta doesn't page that call, so there is no page to go back to."""
    entry = command.entry
    if not command.is_list or any(a in args for a in entry.unpaged_args):
        return False
    rule = entry.resumable
    if isinstance(rule, bool):
        return rule
    return not any(a in args for a in rule.unless_args)


def resume_url(command: Command, resume: Resume, org_url: str) -> str:
    """The URL of the page `resume` continues in: `command`'s path template with the cursor's
    path params, on `org_url`, plus the cursor's query. Send it with no `params`. Raises
    `CursorError` if the path params aren't the template's, a value fails the §6.4 rule, or the
    query isn't one the HTTP client sends unchanged."""
    operation = command.operation
    try:
        segments = {
            name: path_segment(name, value, operation.reserved.get(name, frozenset()))
            for name, value in resume.path_params.items()
        }
        url = build_url(org_url, operation.path, segments)
    except (InvalidArguments, RuntimeError):
        url = None
    if url is None:
        raise CursorError(_INVALID)
    if not resume.query:
        return url
    # `paginate` took the query from a URL httpx2 had parsed, so parsing it again changes
    # nothing; a query that does change (`#`, a space, a control character) didn't come from it.
    base = httpx2.URL(org_url)
    full = f"{url}?{resume.query}"
    try:
        parsed = httpx2.URL(full)
    except httpx2.InvalidURL:
        parsed = None
    if (
        parsed is None
        or not resume.query.isascii()
        or not on_origin(parsed, base)
        or parsed.raw_path != httpx2.URL(url).raw_path + b"?" + resume.query.encode("ascii")
    ):
        raise CursorError(_INVALID)
    return full


async def after(
    items: AsyncGenerator[tuple[Any, str, int]], skip: int
) -> AsyncGenerator[tuple[Any, str, int]]:
    """`items` (from `paginate` at `resume_url`) without the first `skip` items of its first
    page: the ones the earlier call delivered. If the page is now shorter, the rest of it is
    skipped and the list goes on at the next page."""
    async with aclosing(items):
        first: str | None = None
        async for item, page, index in items:
            if first is None:
                first = page
            if page == first and index < skip:
                continue
            skip = 0  # A later page with the first one's URL is not skipped again.
            yield item, page, index
