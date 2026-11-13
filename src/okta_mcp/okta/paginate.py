"""Pagination over Okta list responses (design §6.5, §7.2).

`paginate` yields a list command's items one at a time with the page they came from, so the
envelope builder can stop mid-page and a cursor can resume there. Every page is one
`OktaClient.get` (a fresh DPoP proof each); next links go out with no `params`, so Okta's link is
sent as given. A next link is followed only if it is on the first request's origin and its path,
after RFC 3986 normalisation, equals the first request's path; anything else fails the call.
"""

import re
from collections.abc import AsyncGenerator, Mapping
from typing import Any, Literal, cast

import httpx2

from okta_mcp.okta.client import OktaClient, on_origin

Mode = Literal["link", "body_links", "link_or_body", "none"]

_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class PaginationError(Exception):
    """Okta's response isn't the expected list, or its next link is off the operation's path or
    repeats the page; nothing more was fetched. The message is safe to return to the caller."""


def normalise_path(raw_path: str) -> str:
    """The path of `raw_path` (path and query, percent-encoded) with percent-escapes upper-cased
    and unreserved characters decoded (RFC 3986 §6.2.2.1, §6.2.2.2). Reserved escapes such as `%2F`
    stay encoded, so they never compare equal to a `/`."""

    def escape(m: re.Match[str]) -> str:
        char = chr(int(m[1], 16))
        return char if char in _UNRESERVED else "%" + m[1].upper()

    return _ESCAPE.sub(escape, raw_path.partition("?")[0])


def _raw_path(url: httpx2.URL) -> str:
    return url.raw_path.decode("ascii")


def _items(body: Any, items_key: str | None, null_items: bool) -> list[Any]:
    if items_key is not None:
        wrapper = cast(dict[str, Any], body) if isinstance(body, dict) else {}
        # Only where the registry says so (`response_override: wrapped`; okta-skills saw
        # `{"keys": null}`) is a null list empty. A missing key always fails: a wrong
        # `items_key` must not read as an empty list forever.
        if null_items and items_key in wrapper and wrapper[items_key] is None:
            return []
        body = wrapper.get(items_key)
    if not isinstance(body, list):
        raise PaginationError("Okta's response is not the expected list")
    return cast(list[Any], body)


def _next_href(response: httpx2.Response, body: Any, mode: Mode) -> str | None:
    if mode in ("link", "link_or_body"):
        href = response.links.get("next", {}).get("url")
        if href or mode == "link":
            return href or None
    if mode in ("body_links", "link_or_body"):
        match body:
            case {"_links": {"next": {"href": str(href)}}} if href:
                return href
            case _:
                return None
    return None


async def paginate(
    client: OktaClient,
    url: str,
    params: Mapping[str, str | list[str]] | None = None,
    *,
    mode: Mode,
    items_key: str | None = None,
    null_items: bool = False,
) -> AsyncGenerator[tuple[Any, str, int]]:
    """Yield `(item, page, index_in_page)` from `url` with `params` and, by `mode`, the pages
    after it. `page` is the relative path and query that fetched the item's page. Stops at the
    first page with no items or no next link. With `null_items`, a wrapper whose `items_key`
    is null is a page with no items. Raises `PaginationError`, and whatever
    `OktaClient.get` raises."""
    response = await client.get(url, params)
    first = response.url
    path = normalise_path(_raw_path(first))
    while True:
        try:
            body = response.json()
        except (ValueError, UnicodeDecodeError):
            body = None
        items = _items(body, items_key, null_items)
        page = _raw_path(response.url)
        for i, item in enumerate(items):
            yield item, page, i
        href = _next_href(response, body, mode) if items else None
        if href is None:
            return
        try:
            target = response.url.join(href)
        except httpx2.InvalidURL:
            target = None
        if (
            target is None
            or not on_origin(target, first)
            or normalise_path(_raw_path(target)) != path
        ):
            raise PaginationError("Okta's next link is not on the operation's path")
        if target == response.url:
            raise PaginationError("Okta's next link repeats the page")
        response = await client.get(str(target))
