"""Response envelopes and output budgets (design §7.1, §7.2, T1 §3).

A list is consumed one item at a time, each rendered by `output.render`, and stops at the first
of: `limit` items, the next item not fitting `max_bytes`, or the deadline near (resumable commands
only). The result is one compact JSON text whose size, envelope included, never exceeds
`max_bytes`. Envelope fields other than `untrusted` appear only when they differ from the default.
A cut resumable list carries `next_cursor`, which points at the last item delivered.
"""

import json
import logging
import math
from collections.abc import AsyncGenerator, Callable, Sequence
from contextlib import aclosing
from typing import Any, Literal

import anyio

from okta_mcp.exec.output import ScrubRules, render
from okta_mcp.logs import event
from okta_mcp.okta.client import UpstreamError
from okta_mcp.okta.paginate import PaginationError
from okta_mcp.okta.ratelimit import RateLimited

log = logging.getLogger(__name__)

Truncated = Literal["max_items", "max_bytes", "deadline", "non_resumable"]

DEADLINE_HEADROOM = 1.0
"""Time left before the call's deadline when a resumable list stops, to build the response.
The executor refuses a call timeout under twice this."""
_LONGEST_REASON: Truncated = "non_resumable"
UNPAGED_WARNING = "Okta doesn't page this query and returned a full page; narrow it to see the rest"
"""For `warnings` when an unpaged query (`unpaged_args`) may have been cut by Okta."""


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


def _cursor_field(cursor: str) -> str:
    return ',"next_cursor":' + dumps(cursor)


def _tail(truncated: Truncated | None, cursor: str | None, warnings: Sequence[str]) -> str:
    fields: dict[str, Any] = {} if truncated is None else {"truncated": truncated}
    if warnings:
        fields["warnings"] = list(warnings)
    tail = "]" if cursor is None or truncated is None else "]" + _cursor_field(cursor)
    return tail + ("," + dumps(fields)[1:] if fields else "}")


def list_budget(
    *, cols: tuple[str, ...] | None, limit: int, max_bytes: int, warnings: Sequence[str]
) -> int:
    """Bytes left for rows once the envelope is reserved at its largest (count = `limit`, the
    longest `truncated` reason, `warnings`). Raises `ResultTooLarge` if the envelope alone
    doesn't fit, which a long `select` can cause: callers check this before any Okta request."""
    budget = max_bytes - len(_head(limit, cols)) - len(_tail(_LONGEST_REASON, None, warnings))
    if budget < 0:
        raise ResultTooLarge(max_bytes)
    return budget


async def list_result(
    items: AsyncGenerator[tuple[Any, str, int]],
    rules: ScrubRules,
    *,
    links: bool,
    cols: tuple[str, ...] | None,
    limit: int,
    max_bytes: int,
    next_cursor: Callable[[str, int], str] | None,
    warnings: Sequence[str] = (),
    cut_by_okta: bool = False,
) -> str:
    """A list from `paginate`'s `items`: `rows` of `cols` cells, or with `cols` `None` whole
    `items`. One item past `limit` is read to tell whether the list is complete, which can cost
    a page fetch when `limit` ends a page; if that read fails or runs into the deadline, the list
    is reported cut at `max_items`.

    The list is resumable if `next_cursor` is given: called with an item's page and index, it
    returns the cursor that resumes after that item (`Cursors.issue`). A cut list then carries
    the last delivered item's cursor as `next_cursor`, and every row is charged for its cursor,
    so a list that only just fits may be cut where it would have been complete. A non-resumable
    list is never cut by the deadline (the call times out instead) and reports any other cut as
    `non_resumable`. `warnings` are added as given.

    `cut_by_okta` says Okta's list is itself known to be cut (an unpaged query, `unpaged_args`,
    that filled its page; the call must not be resumable): the result is reported
    `non_resumable` with `UNPAGED_WARNING` however much of it was delivered.

    Raises `ResultTooLarge` if not even the first item fits, `TimeoutError` if the deadline
    comes before it, and whatever `items` raises."""
    resumable = next_cursor is not None
    if resumable and cut_by_okta:
        raise ValueError("a list Okta cut can't be resumable")
    if cut_by_okta:
        warnings = (*warnings, UNPAGED_WARNING)
    # Reserve the envelope at its largest, so the final text fits whatever count and reason.
    budget = list_budget(cols=cols, limit=limit, max_bytes=max_bytes, warnings=warnings)
    rows: list[str] = []
    used = 0
    cursor: str | None = None
    truncated: Truncated | None = None
    deadline = anyio.current_effective_deadline() - DEADLINE_HEADROOM if resumable else math.inf
    async with aclosing(items):
        with anyio.CancelScope(deadline=deadline) as scope:
            while truncated is None and len(rows) < limit:
                try:
                    item, page, index = await anext(items)
                except StopAsyncIteration:
                    break
                row = dumps(render(item, rules, links=links, cols=cols))
                size = len(row) + (1 if rows else 0)
                here = None if next_cursor is None else next_cursor(page, index)
                if used + size + (0 if here is None else len(_cursor_field(here))) > budget:
                    if not rows:
                        raise ResultTooLarge(max_bytes)
                    truncated = "max_bytes"
                else:
                    rows.append(row)
                    used += size
                    cursor = here
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
    if cut_by_okta or (truncated is not None and not resumable):
        truncated = "non_resumable"
    if truncated is not None:
        log.info(
            "list truncated (%s) after %d items",
            truncated,
            len(rows),
            extra=event("result_truncated", reason=truncated, items=len(rows)),
        )
    return _head(len(rows), cols) + ",".join(rows) + _tail(truncated, cursor, warnings)
