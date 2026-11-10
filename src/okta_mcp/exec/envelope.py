"""Response envelopes and output budgets (design §7.1, §7.2, T1 §3).

A list is consumed one item at a time, each rendered by `output.render`, and stops at the first
of: `limit` items, the next item not fitting `max_bytes`, or the deadline near (resumable commands
only). The result is one compact JSON text whose size, envelope included, never exceeds
`max_bytes`. Envelope fields other than `untrusted` appear only when they differ from the default.
"""

import json
import math
from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import Any, Literal

import anyio

from okta_mcp.exec.output import ScrubRules, render
from okta_mcp.okta.client import UpstreamError
from okta_mcp.okta.paginate import PaginationError
from okta_mcp.okta.ratelimit import RateLimited

Truncated = Literal["max_items", "max_bytes", "deadline", "non_resumable"]

_DEADLINE_HEADROOM = 1.0
"""Time left before the call's deadline when a resumable list stops, to build the response."""
_LONGEST_REASON: Truncated = "non_resumable"


class ResultTooLarge(Exception):
    """The result can't fit `max_bytes`. The message is safe to return to the caller."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"result is over {max_bytes} bytes; use select to choose fewer fields")


def dumps(value: Any) -> str:
    """Compact JSON. ASCII-only, so its length is its size in bytes and a lone surrogate from
    Okta can't fail the encoding later."""
    return json.dumps(value, separators=(",", ":"))


def item_result(
    body: Any, rules: ScrubRules, *, links: bool, cols: tuple[str, ...] | None, max_bytes: int
) -> str:
    """A single resource: `{"untrusted":true,"item":…}`. With `cols`, the item maps each dotted
    path to its value. Raises `ResultTooLarge`."""
    out = render(body, rules, links=links, cols=cols)
    if cols is not None:
        out = dict(zip(cols, out, strict=True))
    text = dumps({"untrusted": True, "item": out})
    if len(text) > max_bytes:
        raise ResultTooLarge(max_bytes)
    return text


def _head(count: int, cols: tuple[str, ...] | None) -> str:
    head = {"untrusted": True, "count": count} | ({} if cols is None else {"cols": list(cols)})
    return dumps(head)[:-1] + (',"items":[' if cols is None else ',"rows":[')


def _tail(truncated: Truncated | None) -> str:
    return "]}" if truncated is None else "]," + dumps({"truncated": truncated})[1:]


async def list_result(
    items: AsyncGenerator[tuple[Any, str, int]],
    rules: ScrubRules,
    *,
    links: bool,
    cols: tuple[str, ...] | None,
    limit: int,
    max_bytes: int,
    resumable: bool,
) -> str:
    """A list from `paginate`'s `items`: `rows` of `cols` cells, or with `cols` `None` whole
    `items`. One item past `limit` is read to tell whether the list is complete, which can cost
    a page fetch when `limit` ends a page; if that read fails or runs into the deadline, the list
    is reported cut at `max_items`. A non-resumable list is never cut by the deadline (the call
    times out instead) and reports any other cut as `non_resumable`. Raises `ResultTooLarge` if
    not even the first item fits, `TimeoutError` if the deadline comes before it, and whatever
    `items` raises."""
    # Reserve the envelope at its largest, so the final text fits whatever count and reason.
    budget = max_bytes - len(_head(limit, cols)) - len(_tail(_LONGEST_REASON))
    if budget < 0:  # A long `select` alone can fill it; fail before any Okta request.
        raise ResultTooLarge(max_bytes)
    rows: list[str] = []
    used = 0
    truncated: Truncated | None = None
    deadline = anyio.current_effective_deadline() - _DEADLINE_HEADROOM if resumable else math.inf
    async with aclosing(items):
        with anyio.CancelScope(deadline=deadline) as scope:
            while truncated is None and len(rows) < limit:
                try:
                    item, _page, _index = await anext(items)
                except StopAsyncIteration:
                    break
                row = dumps(render(item, rules, links=links, cols=cols))
                size = len(row) + (1 if rows else 0)
                if used + size > budget:
                    if not rows:
                        raise ResultTooLarge(max_bytes)
                    truncated = "max_bytes"
                else:
                    rows.append(row)
                    used += size
            if truncated is None and len(rows) == limit:
                truncated = "max_items"
                try:
                    await anext(items)
                except StopAsyncIteration:
                    truncated = None
                except (UpstreamError, RateLimited, PaginationError):
                    pass  # The rows asked for are in hand; a resume meets the error itself.
        if scope.cancelled_caught and truncated is None:
            # An empty cut page would resume at the same item forever.
            if not rows:
                raise TimeoutError("deadline reached before the first item")
            truncated = "deadline"
    if truncated is not None and not resumable:
        truncated = "non_resumable"
    return _head(len(rows), cols) + ",".join(rows) + _tail(truncated)
