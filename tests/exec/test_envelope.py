import json
from collections.abc import AsyncGenerator
from typing import Any

import anyio
import httpx2
import pytest

from okta_mcp.exec import envelope
from okta_mcp.exec.envelope import ResultTooLarge, dumps, item_result, list_result
from okta_mcp.exec.output import REDACTED, load_scrub
from okta_mcp.okta.client import OktaClient, UpstreamError, new_http_client
from okta_mcp.okta.paginate import PaginationError, paginate
from okta_mcp.okta.ratelimit import RateLimited
from okta_mcp.okta.token import ServiceToken

RULES = load_scrub()
ORG = "https://example.okta.com"
GROUPS = ORG + "/api/v1/groups"
COLS = ("id", "profile.name")


def group(n: int, name: str = "Sales") -> dict[str, Any]:
    return {"id": f"00g{n}", "profile": {"name": name}, "_links": {"self": {"href": GROUPS}}}


def cursor(page: str, index: int) -> str:
    return f"{page}#{index}"


async def gen(items: list[Any], *, then_sleep: float = 0) -> AsyncGenerator[tuple[Any, str, int]]:
    for i, item in enumerate(items):
        yield item, "/api/v1/groups", i
    await anyio.sleep(then_sleep)


async def result(items: list[Any], *, then_sleep: float = 0, **kw: Any) -> dict[str, Any]:
    opts: dict[str, Any] = {
        "links": False,
        "cols": COLS,
        "limit": 50,
        "max_bytes": 65536,
        "next_cursor": cursor,
    }
    text = await list_result(gen(items, then_sleep=then_sleep), RULES, **(opts | kw))
    assert len(text) <= (opts | kw)["max_bytes"]
    return json.loads(text)


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass


class Okta:
    """Answers with `pages` in order, each linking to the next."""

    def __init__(self, *pages: list[Any]) -> None:
        self.pages = pages
        self.requests = 0

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests += 1
        n = self.requests
        headers = {"Link": f'<{GROUPS}?after={n}>; rel="next"'} if n < len(self.pages) else {}
        return httpx2.Response(200, json=self.pages[n - 1], headers=headers)


def okta_items(okta: Okta) -> AsyncGenerator[tuple[Any, str, int]]:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    return paginate(client, GROUPS, {"limit": "200"}, mode="link")


@pytest.mark.anyio
async def test_complete_list_is_a_table_with_sparse_envelope() -> None:
    got = await result([group(1), group(2, "Okta Admins")])
    assert got == {
        "untrusted": True,
        "count": 2,
        "cols": ["id", "profile.name"],
        "rows": [["00g1", "Sales"], ["00g2", "Okta Admins"]],
    }


@pytest.mark.anyio
async def test_whole_objects_are_items_pruned_without_links() -> None:
    got = await result([group(1) | {"description": None}], cols=None)
    assert got == {
        "untrusted": True,
        "count": 1,
        "items": [{"id": "00g1", "profile": {"name": "Sales"}}],
    }


@pytest.mark.anyio
async def test_links_kept_when_asked() -> None:
    got = await result([group(1)], cols=None, links=True)
    assert got["items"][0]["_links"] == {"self": {"href": GROUPS}}


@pytest.mark.anyio
async def test_empty_list() -> None:
    assert await result([]) == {"untrusted": True, "count": 0, "cols": list(COLS), "rows": []}


@pytest.mark.anyio
async def test_items_are_scrubbed() -> None:
    app = {"id": "0oa1", "credentials": {"oauthClient": {"client_secret": "s3cr3t"}}}
    got = await result([app], cols=("id", "credentials.oauthClient.client_secret"))
    assert got["rows"] == [["0oa1", REDACTED]]


@pytest.mark.anyio
async def test_item_cap_mid_page_fetches_one_page() -> None:
    okta = Okta([group(i) for i in range(5)], [group(9)])
    text = await list_result(
        okta_items(okta),
        RULES,
        links=False,
        cols=COLS,
        limit=2,
        max_bytes=65536,
        next_cursor=cursor,
    )
    got = json.loads(text)
    assert (got["count"], got["truncated"]) == (2, "max_items")
    assert [r[0] for r in got["rows"]] == ["00g0", "00g1"]
    assert okta.requests == 1


@pytest.mark.anyio
async def test_item_cap_at_page_end_reads_next_page_to_decide() -> None:
    okta = Okta([group(0), group(1)], [group(2)])
    text = await list_result(
        okta_items(okta),
        RULES,
        links=False,
        cols=COLS,
        limit=2,
        max_bytes=65536,
        next_cursor=cursor,
    )
    assert json.loads(text)["truncated"] == "max_items"
    assert okta.requests == 2


@pytest.mark.anyio
async def test_item_cap_equal_to_list_is_complete() -> None:
    okta = Okta([group(0), group(1)])
    text = await list_result(
        okta_items(okta),
        RULES,
        links=False,
        cols=COLS,
        limit=2,
        max_bytes=65536,
        next_cursor=cursor,
    )
    assert "truncated" not in json.loads(text)


@pytest.mark.anyio
async def test_items_across_pages_in_order() -> None:
    okta = Okta([group(0), group(1)], [group(2)], [group(3)])
    got = json.loads(
        await list_result(
            okta_items(okta),
            RULES,
            links=False,
            cols=("id",),
            limit=50,
            max_bytes=65536,
            next_cursor=cursor,
        )
    )
    assert got["rows"] == [["00g0"], ["00g1"], ["00g2"], ["00g3"]]
    assert "truncated" not in got


@pytest.mark.anyio
@pytest.mark.parametrize("max_bytes", range(145, 435, 7))
async def test_byte_cap_never_exceeded_and_keeps_a_prefix(max_bytes: int) -> None:
    items = [group(i, "x" * (i * 5)) for i in range(20)]
    got = await result(items, max_bytes=max_bytes)  # `result` asserts the size
    assert got["rows"] == [[f"00g{i}", "x" * (i * 5)] for i in range(got["count"])]
    assert got["truncated"] == "max_bytes"


@pytest.mark.anyio
async def test_byte_cap_measured_after_select() -> None:
    # Whole objects are far over the cap; the selected column fits.
    items = [group(i) | {"profile": {"name": "n", "description": "d" * 5000}} for i in range(3)]
    got = await result(items, cols=("id",), max_bytes=1000)
    assert got["count"] == 3 and "truncated" not in got


@pytest.mark.anyio
async def test_rows_that_fit_exactly_are_all_kept() -> None:
    items = [group(i) for i in range(3)]
    full = await list_result(
        gen(items), RULES, links=False, cols=COLS, limit=3, max_bytes=65536, next_cursor=cursor
    )
    # The budget reserves the longest `truncated` reason and the last row's cursor: a complete
    # list fits in that much more.
    reserve = len(',"truncated":"non_resumable"') + len(',"next_cursor":"/api/v1/groups#2"')
    got = await result(items, limit=3, max_bytes=len(full) + reserve)
    assert got["count"] == 3 and "truncated" not in got
    got = await result(items, limit=3, max_bytes=len(full) + reserve - 1)
    assert (got["count"], got["truncated"]) == (2, "max_bytes")
    assert got["next_cursor"] == "/api/v1/groups#1"


@pytest.mark.anyio
async def test_non_resumable_rows_are_not_charged_for_a_cursor() -> None:
    items = [group(i) for i in range(3)]
    full = await list_result(
        gen(items), RULES, links=False, cols=COLS, limit=3, max_bytes=65536, next_cursor=None
    )
    reserve = len(',"truncated":"non_resumable"')
    got = await result(items, limit=3, max_bytes=len(full) + reserve, next_cursor=None)
    assert got["count"] == 3 and "truncated" not in got


@pytest.mark.anyio
async def test_complete_list_has_no_cursor() -> None:
    got = await result([group(1), group(2)], limit=2)
    assert "next_cursor" not in got and "truncated" not in got


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kw", "reason"), [({"limit": 2}, "max_items"), ({"max_bytes": 180}, "max_bytes")]
)
async def test_cut_list_carries_cursor_of_last_delivered_item(
    kw: dict[str, Any], reason: str
) -> None:
    okta = Okta([group(0)], [group(1), group(2), group(3)], [group(4)])
    opts: dict[str, Any] = {"limit": 50, "max_bytes": 65536} | kw
    text = await list_result(
        okta_items(okta), RULES, links=False, cols=COLS, next_cursor=cursor, **opts
    )
    got = json.loads(text)
    # Item 1 is index 0 of the second page, whose URL is Okta's next link as sent.
    assert (got["count"], got["truncated"]) == (2, reason)
    assert got["next_cursor"] == "/api/v1/groups?after=1#0"
    assert list(got) == ["untrusted", "count", "cols", "rows", "next_cursor", "truncated"]


@pytest.mark.anyio
@pytest.mark.usefixtures("headroom")
async def test_deadline_cut_carries_cursor() -> None:
    with anyio.fail_after(2.1):
        got = await result([group(1), group(2)], then_sleep=10)
    assert got["next_cursor"] == "/api/v1/groups#1"


@pytest.mark.anyio
async def test_failed_read_past_limit_still_carries_cursor() -> None:
    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        yield group(1), "/p", 0
        raise UpstreamError(500, "boom")

    text = await list_result(
        items(), RULES, links=False, cols=COLS, limit=1, max_bytes=65536, next_cursor=cursor
    )
    assert json.loads(text)["next_cursor"] == "/p#0"


@pytest.mark.anyio
async def test_non_resumable_cut_has_no_cursor() -> None:
    got = await result([group(1), group(2)], limit=1, next_cursor=None)
    assert got["truncated"] == "non_resumable" and "next_cursor" not in got


@pytest.mark.anyio
async def test_warnings_only_when_given() -> None:
    assert "warnings" not in await result([group(1)])
    got = await result([group(1)], warnings=("the list may have changed",))
    assert got["warnings"] == ["the list may have changed"]
    assert list(got)[-1] == "warnings"
    got = await result([group(1), group(2)], limit=1, warnings=("w",))
    assert list(got)[-3:] == ["next_cursor", "truncated", "warnings"]


@pytest.mark.anyio
@pytest.mark.parametrize("max_bytes", range(200, 520, 9))
async def test_byte_cap_holds_with_cursor_and_warnings(max_bytes: int) -> None:
    # A cursor that grows with the index, as a real one does with Okta's `after` token.
    def growing(page: str, index: int) -> str:
        return "c" * (20 + 7 * index)

    items = [group(i, "x" * (i * 3)) for i in range(20)]
    got = await result(items, max_bytes=max_bytes, next_cursor=growing, warnings=("resumed",))
    assert got["truncated"] == "max_bytes"
    assert got["next_cursor"] == "c" * (20 + 7 * (got["count"] - 1))


@pytest.mark.anyio
async def test_first_item_and_its_cursor_over_budget_is_result_too_large() -> None:
    assert (await result([group(1)], max_bytes=150))["count"] == 1
    with pytest.raises(ResultTooLarge):
        await result([group(1)], max_bytes=150, next_cursor=lambda page, index: "c" * 100)


@pytest.mark.anyio
async def test_envelope_over_budget_is_result_too_large_before_any_read() -> None:
    read = False

    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        nonlocal read
        read = True
        yield group(1), "/p", 0

    cols = tuple(f"profile.attribute_{i:02d}" for i in range(60))
    with pytest.raises(ResultTooLarge):
        await list_result(
            items(), RULES, links=False, cols=cols, limit=1000, max_bytes=1024, next_cursor=cursor
        )
    assert not read


@pytest.mark.anyio
async def test_first_item_over_budget_is_result_too_large() -> None:
    with pytest.raises(ResultTooLarge, match="use select"):
        await result([group(1, "x" * 500)], max_bytes=200)


@pytest.fixture
def headroom(monkeypatch: pytest.MonkeyPatch) -> None:
    # The list stops 0.1 s into a 2.1 s call, leaving 2 s before `fail_after` would fire.
    monkeypatch.setattr(envelope, "_DEADLINE_HEADROOM", 2.0)


@pytest.mark.anyio
@pytest.mark.usefixtures("headroom")
async def test_deadline_stops_resumable_list_with_partial_rows() -> None:
    with anyio.fail_after(2.1):
        got = await result([group(1), group(2)], then_sleep=10)
    assert (got["count"], got["truncated"]) == (2, "deadline")


@pytest.mark.anyio
@pytest.mark.usefixtures("headroom")
async def test_deadline_before_first_item_times_out() -> None:
    with pytest.raises(TimeoutError, match="before the first item"), anyio.fail_after(2.1):
        await result([], then_sleep=10)


@pytest.mark.anyio
async def test_deadline_already_within_headroom_times_out_without_rows() -> None:
    with pytest.raises(TimeoutError, match="before the first item"), anyio.fail_after(0.5):
        await result([], then_sleep=0.1)


@pytest.mark.anyio
@pytest.mark.usefixtures("headroom")
async def test_deadline_during_read_past_limit_is_max_items() -> None:
    with anyio.fail_after(2.1):
        got = await result([group(1), group(2)], then_sleep=10, limit=2)
    assert (got["count"], got["truncated"]) == (2, "max_items")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "error",
    [UpstreamError(500, "boom"), RateLimited("slow down"), PaginationError("off path")],
    ids=["upstream", "rate_limited", "pagination"],
)
async def test_failed_read_past_limit_keeps_rows(error: Exception) -> None:
    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        yield group(1), "/p", 0
        yield group(2), "/p", 1
        raise error

    text = await list_result(
        items(), RULES, links=False, cols=COLS, limit=2, max_bytes=65536, next_cursor=cursor
    )
    got = json.loads(text)
    assert (got["count"], got["truncated"]) == (2, "max_items")


@pytest.mark.anyio
async def test_deadline_on_non_resumable_list_times_out() -> None:
    with pytest.raises(TimeoutError):
        with anyio.fail_after(0.2):
            await list_result(
                gen([group(1)], then_sleep=10),
                RULES,
                links=False,
                cols=COLS,
                limit=50,
                max_bytes=65536,
                next_cursor=None,
            )


@pytest.mark.anyio
@pytest.mark.parametrize(("kw", "count"), [({"limit": 1}, 1), ({"max_bytes": 120}, 1)])
async def test_non_resumable_cut_is_reported_as_such(kw: dict[str, Any], count: int) -> None:
    got = await result([group(1), group(2)], next_cursor=None, **kw)
    assert (got["count"], got["truncated"]) == (count, "non_resumable")


@pytest.mark.anyio
async def test_generator_is_closed_when_cut() -> None:
    closed = False

    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        nonlocal closed
        try:
            for i in range(10):
                yield group(i), "/p", i
        finally:
            closed = True

    await list_result(
        items(), RULES, links=False, cols=COLS, limit=2, max_bytes=65536, next_cursor=cursor
    )
    assert closed


@pytest.mark.anyio
async def test_error_mid_list_propagates() -> None:
    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        yield group(1), "/p", 0
        raise UpstreamError(500, "boom")

    with pytest.raises(UpstreamError):
        await list_result(
            items(), RULES, links=False, cols=COLS, limit=50, max_bytes=65536, next_cursor=cursor
        )


@pytest.mark.anyio
async def test_output_is_ascii_and_survives_lone_surrogate() -> None:
    text = await list_result(
        gen([group(1, "Zoë \ud800")]),
        RULES,
        links=False,
        cols=COLS,
        limit=50,
        max_bytes=65536,
        next_cursor=cursor,
    )
    assert text.isascii()
    assert json.loads(text)["rows"] == [["00g1", "Zoë \ud800"]]


def test_item_result_whole_object() -> None:
    text = item_result(
        group(1) | {"lastLogin": None}, RULES, links=False, cols=None, max_bytes=65536
    )
    assert json.loads(text) == {
        "untrusted": True,
        "item": {"id": "00g1", "profile": {"name": "Sales"}},
    }


def test_item_result_with_cols_maps_paths() -> None:
    text = item_result(
        group(1), RULES, links=False, cols=("id", "profile.name", "absent"), max_bytes=65536
    )
    assert json.loads(text) == {
        "untrusted": True,
        "item": {"id": "00g1", "profile.name": "Sales", "absent": None},
    }


def test_item_result_is_scrubbed() -> None:
    app = {"id": "0oa1", "credentials": {"oauthClient": {"client_secret": "s3cr3t"}}}
    text = item_result(app, RULES, links=False, cols=None, max_bytes=65536)
    assert "s3cr3t" not in text and REDACTED in text


def test_item_result_over_max_bytes() -> None:
    body = group(1, "x" * 100)
    size = len(dumps({"untrusted": True, "item": {"id": "00g1", "profile": {"name": "x" * 100}}}))
    assert item_result(body, RULES, links=False, cols=None, max_bytes=size)
    with pytest.raises(ResultTooLarge, match="over 99 bytes"):
        item_result(body, RULES, links=False, cols=None, max_bytes=99)


# --- a list Okta itself cut (an unpaged query that filled its page) ---


@pytest.mark.anyio
@pytest.mark.parametrize("limit", [3, 5, 50])
async def test_cut_by_okta_is_reported_wherever_reading_stops(limit: int) -> None:
    out = await result(
        [group(i) for i in range(5)], next_cursor=None, cut_by_okta=True, limit=limit
    )
    assert out["count"] == min(limit, 5)
    assert out["truncated"] == "non_resumable"
    assert out["warnings"] == [envelope.UNPAGED_WARNING]


@pytest.mark.anyio
async def test_not_cut_by_okta_has_no_warning() -> None:
    out = await result([group(i) for i in range(4)], next_cursor=None)
    assert out["count"] == 4 and "truncated" not in out and "warnings" not in out


@pytest.mark.anyio
async def test_cut_by_okta_warning_keeps_other_warnings_and_fits_the_budget() -> None:
    items = [group(i, "x" * 30) for i in range(40)]
    for max_bytes in range(1024, 3000, 97):
        out = await result(
            items, next_cursor=None, cut_by_okta=True, max_bytes=max_bytes, warnings=["first"]
        )
        assert out["warnings"] == ["first", envelope.UNPAGED_WARNING]
        assert out["truncated"] == "non_resumable"


@pytest.mark.anyio
async def test_cut_by_okta_cant_be_resumable() -> None:
    with pytest.raises(ValueError, match="resumable"):
        await result([group(1)], cut_by_okta=True)
