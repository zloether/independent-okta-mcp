import json
from typing import Any

import httpx2
import jwt
import pytest
from _fakes import FakeTokenProvider
from jwt.algorithms import ECAlgorithm

from okta_mcp.okta.client import OktaClient, OriginError, UpstreamError, new_http_client
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.paginate import Mode, PaginationError, normalise_path, paginate
from okta_mcp.okta.token import ServiceToken

ORG = "https://example.okta.com"
GROUPS = ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/groups"
PAGE2 = GROUPS + "?after=00g2&limit=2"
PAGE3 = GROUPS + "?after=00g4&limit=2"


def page(body: Any, next_href: str | None = None, *, status: int = 200) -> httpx2.Response:
    headers = [("Link", f'<{GROUPS}?limit=2>; rel="self"')]
    if next_href is not None:
        headers.append(("Link", f'<{next_href}>; rel="next"'))
    return httpx2.Response(status, json=body, headers=headers)


def wrapped(items: list[Any], next_href: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"resource-sets": items}
    if next_href is not None:
        body["_links"] = {"next": {"href": next_href}}
    return body


class Okta:
    """Records requests and answers them from `responses` in order."""

    def __init__(self, *responses: httpx2.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.responses[len(self.requests) - 1]

    def raw(self, i: int) -> str:
        return self.requests[i].url.raw_path.decode()


def client(okta: Okta, dpop: DPoP | None = None) -> OktaClient:
    tokens = FakeTokenProvider(ServiceToken("eyJ.dpop.sig", "DPoP") if dpop else None)
    return OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=tokens,
        dpop=dpop,
        max_inflight=10,
        rate_limit_max_wait=10,
    )


async def collect(
    okta: Okta,
    *,
    mode: Mode,
    url: str = GROUPS,
    items_key: str | None = None,
    dpop: DPoP | None = None,
) -> list[tuple[Any, str, int]]:
    return [
        x
        async for x in paginate(
            client(okta, dpop), url, {"limit": "2"}, mode=mode, items_key=items_key
        )
    ]


@pytest.mark.anyio
async def test_link_follows_next_header_and_reports_pages() -> None:
    okta = Okta(
        page([{"id": "a"}, {"id": "b"}], PAGE2),
        page([{"id": "c"}, {"id": "d"}], PAGE3),
        page([{"id": "e"}]),
    )
    got = await collect(okta, mode="link")
    p1, p2, p3 = (u.removeprefix(ORG) for u in (GROUPS + "?limit=2", PAGE2, PAGE3))
    assert got == [
        ({"id": "a"}, p1, 0),
        ({"id": "b"}, p1, 1),
        ({"id": "c"}, p2, 0),
        ({"id": "d"}, p2, 1),
        ({"id": "e"}, p3, 0),
    ]
    # Next links go out exactly as Okta sent them: no `params` merged in.
    assert [okta.raw(i) for i in range(3)] == [p1, p2, p3]


@pytest.mark.anyio
async def test_each_hop_has_a_fresh_dpop_proof() -> None:
    okta = Okta(page([1], PAGE2), page([2], PAGE3), page([3]))
    await collect(okta, mode="link", dpop=DPoP())
    proofs = []
    for request in okta.requests:
        proof = request.headers["DPoP"]
        jwk = ECAlgorithm.from_jwk(json.dumps(jwt.get_unverified_header(proof)["jwk"]))
        proofs.append(jwt.decode(proof, jwk, algorithms=["ES256"]))  # pyright: ignore[reportArgumentType]
    assert len({p["jti"] for p in proofs}) == 3
    assert {p["htu"] for p in proofs} == {GROUPS}


@pytest.mark.anyio
async def test_link_ignores_body_links() -> None:
    okta = Okta(page(wrapped([{"id": "a"}], PAGE2)))
    got = await collect(okta, mode="link", items_key="resource-sets")
    assert [item for item, _, _ in got] == [{"id": "a"}]
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_body_links_follows_body_and_ignores_header() -> None:
    okta = Okta(
        page(wrapped([{"id": "a"}], PAGE2), next_href=PAGE3),
        page(wrapped([{"id": "b"}])),
    )
    got = await collect(okta, mode="body_links", items_key="resource-sets")
    assert [(item, i) for item, _, i in got] == [({"id": "a"}, 0), ({"id": "b"}, 0)]
    assert okta.raw(1) == PAGE2.removeprefix(ORG)


@pytest.mark.anyio
async def test_link_or_body_prefers_header_then_falls_back_to_body() -> None:
    okta = Okta(
        page(wrapped([{"id": "a"}], PAGE3), next_href=PAGE2),
        page(wrapped([{"id": "b"}], PAGE3)),
        page(wrapped([{"id": "c"}])),
    )
    got = await collect(okta, mode="link_or_body", items_key="resource-sets")
    assert [item["id"] for item, _, _ in got] == ["a", "b", "c"]
    assert [okta.raw(i) for i in (1, 2)] == [PAGE2.removeprefix(ORG), PAGE3.removeprefix(ORG)]


@pytest.mark.anyio
async def test_link_or_body_with_plain_list_and_no_header_stops() -> None:
    okta = Okta(page([{"id": "a"}]))
    assert len(await collect(okta, mode="link_or_body")) == 1


@pytest.mark.anyio
async def test_none_does_not_follow() -> None:
    okta = Okta(page([{"id": "a"}], PAGE2))
    assert len(await collect(okta, mode="none")) == 1
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_wrapped_response_with_link_header() -> None:
    okta = Okta(page(wrapped([{"id": "a"}], None), PAGE2), page(wrapped([{"id": "b"}])))
    got = await collect(okta, mode="link", items_key="resource-sets")
    assert [item["id"] for item, _, _ in got] == ["a", "b"]


@pytest.mark.anyio
async def test_wrapped_null_list_is_empty() -> None:
    # okta-skills saw `{"keys": null}` for an app without keys; the link is not followed.
    okta = Okta(page({"resource-sets": None, "_links": {"next": {"href": PAGE2}}}))
    assert await collect(okta, mode="link_or_body", items_key="resource-sets") == []
    assert len(okta.requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("body", [{}, {"keys": []}, {"resource-sets": {"id": "a"}}, [], None])
async def test_wrapper_without_the_list_fails(body: Any) -> None:
    # A missing key is a wrong `items_key` or a changed shape, not an empty list.
    with pytest.raises(PaginationError, match="not the expected list"):
        await collect(Okta(page(body)), mode="none", items_key="resource-sets")


@pytest.mark.anyio
async def test_empty_page_stops_even_with_next_link() -> None:
    okta = Okta(page([], PAGE2))
    assert await collect(okta, mode="link") == []
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_empty_next_link_stops() -> None:
    okta = Okta(page([1], ""))
    assert len(await collect(okta, mode="link")) == 1
    assert len(okta.requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["link", "body_links"])
async def test_next_link_repeating_the_page_raises(mode: Mode) -> None:
    if mode == "link":
        okta, items_key = Okta(page([1], PAGE2), page([2], PAGE2)), None
    else:
        okta, items_key = (
            Okta(page(wrapped([1], PAGE2)), page(wrapped([2], PAGE2))),
            "resource-sets",
        )
    got: list[Any] = []
    with pytest.raises(PaginationError):
        async for item, _, _ in paginate(client(okta), GROUPS, mode=mode, items_key=items_key):
            got.append(item)
    assert got == [1, 2]
    assert len(okta.requests) == 2


@pytest.mark.anyio
async def test_relative_next_link_resolves_against_page() -> None:
    okta = Okta(page([1], PAGE2.removeprefix(ORG)), page([2]))
    assert len(await collect(okta, mode="link")) == 2
    assert str(okta.requests[1].url) == PAGE2


@pytest.mark.anyio
@pytest.mark.parametrize(
    "first, link",
    [
        # Unreserved characters percent-encoded, and lower-case escapes, are the same path.
        (GROUPS, ORG + "/api/v1/%75sers/00u1abcDEFghiJKLm0h7/groups?after=x"),
        (GROUPS, ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/gr%6Fups?after=x"),
        (ORG + "/api/v1/users/a%3Ab/groups", ORG + "/api/v1/users/a%3ab/groups?after=x"),
        (GROUPS, "HTTPS://EXAMPLE.OKTA.COM/api/v1/users/00u1abcDEFghiJKLm0h7/groups?after=x"),
        (GROUPS, "https://example.okta.com:443/api/v1/users/00u1abcDEFghiJKLm0h7/groups?a=1"),
    ],
)
async def test_equivalent_next_link_is_followed(first: str, link: str) -> None:
    okta = Okta(page([1], link), page([2]))
    assert len(await collect(okta, mode="link", url=first)) == 2


BAD_LINKS = [
    "https://evil.example.com/api/v1/users/00u1abcDEFghiJKLm0h7/groups?after=x",
    "http://example.okta.com/api/v1/users/00u1abcDEFghiJKLm0h7/groups?after=x",
    "https://example.okta.com:8443/api/v1/users/00u1abcDEFghiJKLm0h7/groups?after=x",
    "https://user:pw@example.okta.com/api/v1/users/00u1abcDEFghiJKLm0h7/groups?after=x",
    "https://example.okta.com.example.com/api/v1/users/00u1abcDEFghiJKLm0h7/groups",
    "//evil.example.com/api/v1/users/00u1abcDEFghiJKLm0h7/groups",
    ORG + "/api/v1/apps?after=x",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/groups/",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/groups/x",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/groups/../../00u2/groups",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7/groups/%2e%2e/groups",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7%2Fgroups",
    ORG + "/api/v1/users/00u1abcDEFghiJKLm0h7%2fgroups",
    ORG + "/api/v1/users/00U1ABCDEFGHIJKLM0H7/groups",
    "/api/v1/apps",
    "after=x",
    "https://[::1/x",
]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["link", "body_links"])
@pytest.mark.parametrize("link", BAD_LINKS)
async def test_off_path_next_link_raises_and_is_not_followed(mode: Mode, link: str) -> None:
    if mode == "link":
        okta, items_key = Okta(page([1], link)), None
    else:
        okta, items_key = Okta(page(wrapped([1], link))), "resource-sets"
    with pytest.raises(PaginationError):
        await collect(okta, mode=mode, items_key=items_key)
    assert len(okta.requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body, items_key",
    [
        ({"id": "a"}, None),
        ("text", None),
        (None, None),
        ([{"id": "a"}], "resource-sets"),
        ({"other": []}, "resource-sets"),
        ({"resource-sets": {"id": "a"}}, "resource-sets"),
    ],
)
async def test_unexpected_shape_raises(body: Any, items_key: str | None) -> None:
    with pytest.raises(PaginationError):
        await collect(Okta(page(body)), mode="link", items_key=items_key)


@pytest.mark.anyio
async def test_non_json_body_raises() -> None:
    okta = Okta(httpx2.Response(200, content=b"<html>"))
    with pytest.raises(PaginationError):
        await collect(okta, mode="link")


@pytest.mark.anyio
async def test_error_on_later_page_propagates_after_earlier_items() -> None:
    okta = Okta(page([1], PAGE2), page({"errorSummary": "boom"}, status=500))
    got: list[Any] = []
    with pytest.raises(UpstreamError):
        async for item, _, _ in paginate(client(okta), GROUPS, mode="link"):
            got.append(item)
    assert got == [1]


@pytest.mark.anyio
async def test_first_url_off_org_is_refused_by_client() -> None:
    okta = Okta()
    with pytest.raises(OriginError):
        await collect(okta, mode="link", url="https://evil.example.com/api/v1/users")
    assert okta.requests == []


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/api/v1/users?after=%2F", "/api/v1/users"),
        ("/api/v1/%75sers", "/api/v1/users"),
        ("/a%2fb", "/a%2Fb"),
        ("/a%7e%2E%2d%5F", "/a~.-_"),
        ("/a%3ab%40c", "/a%3Ab%40c"),
        ("/a%2", "/a%2"),
    ],
)
def test_normalise_path(raw: str, expected: str) -> None:
    assert normalise_path(raw) == expected
