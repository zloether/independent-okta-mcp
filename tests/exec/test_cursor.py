import base64
import dataclasses
import hashlib
import hmac
import json
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import parse_qs

import httpx2
import pytest

from okta_mcp.exec.cursor import (
    CURSOR_TTL,
    RESUMED_WARNING,
    CursorError,
    Cursors,
    Resume,
    after,
    path_params,
    resumable,
    resume_url,
)
from okta_mcp.exec.envelope import list_result
from okta_mcp.exec.output import load_scrub
from okta_mcp.exec.params import build_request
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.paginate import paginate
from okta_mcp.okta.token import ServiceToken
from okta_mcp.registry.loader import Command, Registry, load_registry
from okta_mcp.registry.spec import load_spec

RULES = load_scrub()
ORG = "https://example.okta.com"
KEY = bytes(range(32))
GROUP = "00g1emaKYZTWRYYRRTSK"
MEMBERS = f"/api/v1/groups/{GROUP}/users"
BOUND: dict[str, Any] = {
    "uid": "00u1abcDEFghiJKLm0h7",
    "tool": "okta_groups",
    "command": "get-members",
    "args": {"group": GROUP},
}
ISSUED: dict[str, Any] = BOUND | {"path_params": {"groupId": GROUP}}
PAGE = MEMBERS + "?after=00u9&limit=200"


def merged(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    return base | over


class Clock:
    def __init__(self) -> None:
        self.now = 1_760_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(load_spec())


@pytest.fixture(scope="module")
def members(registry: Registry) -> Command:
    return registry.domains["groups"].commands["get-members"]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cursors(clock: Clock) -> Cursors:
    return Cursors(KEY, clock=clock)


def payload_of(cursor: str) -> dict[str, Any]:
    body = cursor.partition(".")[0]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def sign(payload: Any, key: bytes = KEY) -> str:
    """A cursor with a valid tag over any payload: what a holder of the key could make."""
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    tag = hmac.digest(key, body.encode(), "sha256")[:16]
    return body + "." + base64.urlsafe_b64encode(tag).rstrip(b"=").decode()


# --- format ---


def test_round_trip(cursors: Cursors) -> None:
    cursor = cursors.issue(PAGE, 36, **ISSUED)
    assert cursors.open(cursor, **BOUND) == Resume({"groupId": GROUP}, "after=00u9&limit=200", 37)


def test_payload_is_compact_and_holds_no_path_or_host(cursors: Cursors, clock: Clock) -> None:
    cursor = cursors.issue(PAGE, 36, **ISSUED)
    payload = payload_of(cursor)
    assert payload == {
        "v": 1,
        "u": BOUND["uid"],
        "t": "okta_groups",
        "c": "get-members",
        "a": payload["a"],
        "p": {"groupId": GROUP},
        "q": "after=00u9&limit=200",
        "s": 37,
        "e": int(clock.now) + CURSOR_TTL,
    }
    assert len(base64.urlsafe_b64decode(payload["a"] + "==")) == 16
    assert "/api/" not in json.dumps(payload) and "example.okta.com" not in json.dumps(payload)
    tag = cursor.partition(".")[2]
    assert len(base64.urlsafe_b64decode(tag + "==")) == 16
    assert cursor.isascii() and "=" not in cursor
    assert len(cursor) < 300  # T1 D10: about 290 characters for a call like this one


def test_args_hash_is_canonical_and_covers_original_args(cursors: Cursors) -> None:
    args = {"group": GROUP, "search": 'profile.lastName eq "Brock"'}
    cursor = cursors.issue(PAGE, 0, **merged(ISSUED, {"args": args}))
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()[:16]).rstrip(b"=")
    assert payload_of(cursor)["a"] == expected.decode()
    # Key order doesn't matter.
    assert cursors.open(cursor, **merged(BOUND, {"args": dict(reversed(args.items()))}))


def test_first_page_cursor_keeps_initial_query(cursors: Cursors) -> None:
    cursor = cursors.issue(MEMBERS + "?limit=200", 0, **ISSUED)
    assert cursors.open(cursor, **BOUND) == Resume({"groupId": GROUP}, "limit=200", 1)


def test_page_without_query(cursors: Cursors) -> None:
    assert cursors.open(cursors.issue(MEMBERS, 4, **ISSUED), **BOUND).query == ""


def test_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        Cursors(b"k" * 31)


# --- verification ---


def test_tampered_payload_is_rejected(cursors: Cursors) -> None:
    body, _, tag = cursors.issue(PAGE, 0, **ISSUED).partition(".")
    payload = payload_of(body) | {"p": {"groupId": "00g2emaKYZTWRYYRRTSK"}}
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(f"{forged}.{tag}", **BOUND)


def test_every_single_character_change_is_rejected(cursors: Cursors) -> None:
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    for i, c in enumerate(cursor):
        changed = cursor[:i] + ("A" if c != "A" else "B") + cursor[i + 1 :]
        with pytest.raises(CursorError, match="not valid"):
            cursors.open(changed, **BOUND)


def test_tag_with_other_trailing_bits_is_rejected(cursors: Cursors) -> None:
    # 16 bytes are 22 base64 characters whose last carries 4 unused bits: a decoder ignores them.
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    twin = cursor[:-1] + alphabet[alphabet.index(cursor[-1]) ^ 1]
    assert base64.urlsafe_b64decode(twin[-22:] + "==") == base64.urlsafe_b64decode(
        cursor[-22:] + "=="
    )
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(twin, **BOUND)


@pytest.mark.parametrize(
    "cursor",
    ["", ".", "abc", "abc.", ".abc", "a.b.c", "é.é", "eyJ2IjoxfQ", "\x00.\x00", "a" * 5000],
)
def test_malformed_cursor_is_rejected(cursors: Cursors, cursor: str) -> None:
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(cursor, **BOUND)


def test_wrong_key_is_rejected(cursors: Cursors, clock: Clock) -> None:
    other = Cursors(bytes(range(1, 33)), clock=clock)
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(other.issue(PAGE, 0, **ISSUED), **BOUND)


def test_full_length_tag_is_not_accepted(cursors: Cursors) -> None:
    body = cursors.issue(PAGE, 0, **ISSUED).partition(".")[0]
    full = base64.urlsafe_b64encode(hmac.digest(KEY, body.encode(), "sha256")).rstrip(b"=")
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(f"{body}.{full.decode()}", **BOUND)


@pytest.mark.parametrize(
    "other",
    [{"uid": "00u2abcDEFghiJKLm0h7"}, {"tool": "okta_users"}, {"command": "get-apps"}],
    ids=["uid", "tool", "command"],
)
def test_other_caller_tool_or_command_is_rejected(cursors: Cursors, other: dict[str, str]) -> None:
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(cursor, **merged(BOUND, other))


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"group": "00g2emaKYZTWRYYRRTSK"},
        {"group": GROUP, "search": "x"},
        {"group": GROUP, "expand": "login-status-info"},
    ],
)
def test_other_args_are_rejected(cursors: Cursors, args: dict[str, Any]) -> None:
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    with pytest.raises(CursorError, match="other args"):
        cursors.open(cursor, **merged(BOUND, {"args": args}))


def test_arg_types_are_told_apart(cursors: Cursors) -> None:
    cursor = cursors.issue(PAGE, 0, **merged(ISSUED, {"args": {"n": 1}}))
    for other in ("1", True, 1.0):
        with pytest.raises(CursorError, match="other args"):
            cursors.open(cursor, **merged(BOUND, {"args": {"n": other}}))


def test_expiry(cursors: Cursors, clock: Clock) -> None:
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    clock.now += CURSOR_TTL - 1
    assert cursors.open(cursor, **BOUND)
    clock.now += 1
    with pytest.raises(CursorError, match="expired"):
        cursors.open(cursor, **BOUND)


def test_ttl_is_fifteen_minutes() -> None:
    assert CURSOR_TTL == 900


def test_expired_cursor_of_another_caller_says_only_invalid(cursors: Cursors, clock: Clock) -> None:
    cursor = cursors.issue(PAGE, 0, **ISSUED)
    clock.now += CURSOR_TTL
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(cursor, **merged(BOUND, {"uid": "00u2abcDEFghiJKLm0h7"}))


GOOD: dict[str, Any] = {
    "v": 1,
    "u": BOUND["uid"],
    "t": "okta_groups",
    "c": "get-members",
    "a": "x",
    "p": {"groupId": GROUP},
    "q": "",
    "s": 0,
    "e": 2_000_000_000,
}


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"\xff\xfe",
        [],
        "text",
        {},
        {k: v for k, v in GOOD.items() if k != "q"},
        GOOD | {"x": 1},
        GOOD | {"v": 2},
        GOOD | {"v": True},
        GOOD | {"v": 1.0},
        GOOD | {"u": 1},
        GOOD | {"a": None},
        b"[" * 100_000,
        GOOD | {"p": []},
        GOOD | {"p": {"groupId": 1}},
        GOOD | {"p": {"groupId": ["a"]}},
        GOOD | {"q": None},
        GOOD | {"s": -1},
        GOOD | {"s": "1"},
        GOOD | {"s": True},
        GOOD | {"s": 1.5},
        GOOD | {"e": "2000000000"},
        GOOD | {"e": True},
    ],
)
def test_signed_but_malformed_payload_is_rejected(cursors: Cursors, payload: Any) -> None:
    # Only reachable with the key (an older version's cursor); still fails closed.
    with pytest.raises(CursorError, match="not valid"):
        cursors.open(sign(payload), **BOUND)


def test_signed_payload_with_lone_surrogate_hash_is_a_cursor_error(cursors: Cursors) -> None:
    with pytest.raises(CursorError, match="other args"):
        cursors.open(sign(GOOD | {"a": "\ud800"}), **BOUND)


def test_messages_never_echo_the_cursor(cursors: Cursors) -> None:
    with pytest.raises(CursorError) as e:
        cursors.open("c2VjcmV0.c2VjcmV0", **BOUND)
    assert "c2VjcmV0" not in str(e.value)


# --- the resume URL ---


def test_resume_url_is_template_plus_query(members: Command) -> None:
    resume = Resume({"groupId": GROUP}, "after=00u9&limit=200", 3)
    assert resume_url(members, resume, ORG) == ORG + PAGE


def test_resume_url_without_query(members: Command) -> None:
    assert resume_url(members, Resume({"groupId": GROUP}, "", 3), ORG) == ORG + MEMBERS


def test_resume_url_encodes_path_values(members: Command) -> None:
    url = resume_url(members, Resume({"groupId": 'a@b:c"d'}, "limit=1", 0), ORG)
    assert url == ORG + "/api/v1/groups/a@b:c%22d/users?limit=1"


@pytest.mark.parametrize(
    "value",
    [
        "..",
        ".",
        "",
        "a/b",
        "a/../b",
        "a%2F..%2Fb",
        "%2e%2e",
        "a\\b",
        "a?b=c",
        "a#b",
        "a b",
        "a\x00b",
        "00g1emaKYZTWRYYRRTSK\n",
        "A" * 300,
        "\N{FULLWIDTH FULL STOP}\N{FULLWIDTH FULL STOP}",
        "rules",  # a sibling endpoint: /api/v1/groups/rules
        "https://evil.example.com",
        "//evil.example.com",
    ],
)
def test_resume_url_refuses_bad_path_values(members: Command, value: str) -> None:
    with pytest.raises(CursorError, match="not valid"):
        resume_url(members, Resume({"groupId": value}, "limit=200", 0), ORG)


@pytest.mark.parametrize(
    "params",
    [{}, {"userId": GROUP}, {"groupId": GROUP, "userId": "00u1abcDEFghiJKLm0h7"}],
    ids=["none", "other", "extra"],
)
def test_resume_url_needs_exactly_the_template_params(
    members: Command, params: dict[str, str]
) -> None:
    with pytest.raises(CursorError, match="not valid"):
        resume_url(members, Resume(params, "limit=200", 0), ORG)


@pytest.mark.parametrize(
    "query",
    [
        "a=b#frag",
        "a=b c",
        "a=b\n",
        "a=b\x00",
        "a=é",
        'a="b"',
        "a=<b>",
        "#",
        "\N{FULLWIDTH QUESTION MARK}",
    ],
)
def test_resume_url_refuses_a_query_that_would_be_rewritten(members: Command, query: str) -> None:
    with pytest.raises(CursorError, match="not valid"):
        resume_url(members, Resume({"groupId": GROUP}, query, 0), ORG)


@pytest.mark.parametrize(
    "query",
    [
        "https://evil.example.com/",
        "//evil.example.com/x",
        "@evil.example.com",
        "/../../api/v1/users",
        "?x=1",
        "..%2F..%2Fusers",
    ],
)
def test_query_can_not_change_host_or_path(members: Command, query: str) -> None:
    # Whatever a signed query holds, it stays a query on the operation's path.
    url = httpx2.URL(resume_url(members, Resume({"groupId": GROUP}, query, 0), ORG))
    assert (url.scheme, url.host, url.port, url.userinfo) == (
        "https",
        "example.okta.com",
        None,
        b"",
    )
    assert url.path == MEMBERS
    assert url.query == query.encode()


def test_absolute_url_in_forged_payload_never_leaves_the_org(
    cursors: Cursors, members: Command
) -> None:
    # A holder of the key puts absolute URLs wherever the payload has room.
    evil = "https://evil.example.com/api/v1/groups"
    as_param = sign(payload_of(cursors.issue(PAGE, 0, **ISSUED)) | {"p": {"groupId": evil}})
    with pytest.raises(CursorError):
        resume_url(members, cursors.open(as_param, **BOUND), ORG)
    as_query = sign(payload_of(cursors.issue(PAGE, 0, **ISSUED)) | {"q": evil})
    url = httpx2.URL(resume_url(members, cursors.open(as_query, **BOUND), ORG))
    assert (url.host, url.path) == ("example.okta.com", MEMBERS)


def test_path_params_are_keyed_by_spec_parameter(registry: Registry, members: Command) -> None:
    assert path_params(members, {"group": GROUP, "search": "x"}) == {"groupId": GROUP}
    assert path_params(registry.domains["groups"].commands["list"], {"search": "x"}) == {}


def test_issuer_matches_issue(cursors: Cursors) -> None:
    assert cursors.issuer(**ISSUED)(PAGE, 36) == cursors.issue(PAGE, 36, **ISSUED)


@pytest.mark.parametrize(
    "search",
    [
        "profile.lastName eq \"Brock\" and status eq 'ACTIVE'",
        "a+b c&d=e;f",
        "Zo\u00eb \u65e5\u672c",
        "100% %zz %41",
        "a#b?c/d\\e",
        "".join(chr(i) for i in range(32, 127)),
        "[x]{y}|^`<>",
    ],
)
def test_query_of_a_real_request_survives_resume_url(members: Command, search: str) -> None:
    # The check in `resume_url` relies on httpx2 parsing its own output back unchanged.
    url, params = build_request(members, {"group": GROUP, "search": search}, ORG)
    sent = httpx2.URL(url).copy_merge_params(params)
    query = sent.raw_path.decode().partition("?")[2]
    assert resume_url(members, Resume({"groupId": GROUP}, query, 1), ORG) == str(sent)


@pytest.mark.parametrize(
    "href",
    ['?after=x&search=a%20eq%20"b"', "?after=a b", "?after=\u00e9", "?a=b'c(d)*!~", "?a=%7e%2F%zz"],
)
def test_query_of_a_followed_next_link_survives_resume_url(members: Command, href: str) -> None:
    followed = httpx2.URL(str(httpx2.URL(ORG + MEMBERS + "?limit=200").join(href)))
    query = followed.raw_path.decode().partition("?")[2]
    assert resume_url(members, Resume({"groupId": GROUP}, query, 1), ORG) == str(followed)


# --- resumable ---


def test_resumable_by_registry_rule(registry: Registry) -> None:
    groups = registry.domains["groups"].commands
    assert resumable(groups["get-members"], {"group": GROUP})
    assert resumable(groups["list"], {})
    assert resumable(groups["list"], {"search": 'profile.name sw "A"'})
    assert not resumable(groups["list"], {"q": "Sales"})  # `unless_args: [q]`
    assert not resumable(groups["get"], {"group": GROUP})  # not a list


def test_never_resumable_with_an_unpaged_arg(registry: Registry) -> None:
    command = registry.domains["groups"].commands["list"]
    entry = command.entry.model_copy(update={"resumable": True})
    command = dataclasses.replace(command, entry=entry)
    assert resumable(command, {}) and not resumable(command, {"q": "Sales"})


# --- end to end: cut, resume, cut again ---


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass


class Okta:
    """A group's members in pages of `page_size`, linked with `after`. Records every URL."""

    def __init__(self, total: int, page_size: int) -> None:
        self.users = [
            {"id": f"00u{i:017d}", "status": "ACTIVE", "profile": {"login": f"u{i}@example.com"}}
            for i in range(total)
        ]
        self.page_size = page_size
        self.urls: list[str] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.urls.append(str(request.url))
        assert request.url.host == "example.okta.com" and request.url.path == MEMBERS
        query = parse_qs(request.url.query.decode())
        assert query["limit"] == ["200"]
        start = int(query.get("after", ["0"])[0])
        end = start + self.page_size
        link = f'<{ORG}{MEMBERS}?after={end}&limit=200>; rel="next"'
        headers = {"Link": link} if end < len(self.users) else {}
        return httpx2.Response(200, json=self.users[start:end], headers=headers)


def client_for(okta: Okta) -> OktaClient:
    return OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )


async def call(
    okta: Okta,
    cursors: Cursors,
    command: Command,
    cursor: str | None,
    *,
    limit: int,
    max_bytes: int,
    bound: dict[str, Any] = BOUND,
) -> dict[str, Any]:
    """What the executor (2.10) does with a list call, first or resumed."""
    client = client_for(okta)
    items: AsyncGenerator[tuple[Any, str, int]]
    if cursor is None:
        url, params = build_request(command, bound["args"], ORG)
        items = paginate(client, url, params, mode="link")
        warnings: tuple[str, ...] = ()
    else:
        resume = cursors.open(cursor, **bound)
        items = after(paginate(client, resume_url(command, resume, ORG), mode="link"), resume.skip)
        warnings = (RESUMED_WARNING,)

    issue = cursors.issuer(path_params=path_params(command, bound["args"]), **bound)

    text = await list_result(
        items,
        RULES,
        links=False,
        cols=("id", "profile.login"),
        limit=limit,
        max_bytes=max_bytes,
        next_cursor=issue,
        warnings=warnings,
    )
    assert len(text) <= max_bytes
    return json.loads(text)


async def drain(
    okta: Okta, cursors: Cursors, command: Command, *, limit: int, max_bytes: int
) -> list[str]:
    ids: list[str] = []
    cursor: str | None = None
    for _ in range(1000):
        got = await call(okta, cursors, command, cursor, limit=limit, max_bytes=max_bytes)
        ids += [row[0] for row in got["rows"]]
        assert ("warnings" in got) == (cursor is not None)
        assert ("next_cursor" in got) == ("truncated" in got)
        if "next_cursor" not in got:
            return ids
        assert got["rows"], "a cut page with no rows would never advance"
        cursor = got["next_cursor"]
    raise AssertionError("never finished")


@pytest.mark.anyio
@pytest.mark.parametrize("page_size", [1, 3, 7, 50])
@pytest.mark.parametrize("limit", [1, 2, 3, 6, 7, 8, 21, 50])
async def test_resume_yields_every_item_once_across_item_caps(
    cursors: Cursors, members: Command, page_size: int, limit: int
) -> None:
    okta = Okta(23, page_size)
    ids = await drain(okta, cursors, members, limit=limit, max_bytes=65536)
    assert ids == [u["id"] for u in okta.users]


@pytest.mark.anyio
@pytest.mark.parametrize("page_size", [1, 4, 50])
@pytest.mark.parametrize("max_bytes", [520, 600, 777, 1024, 2000])
async def test_resume_yields_every_item_once_across_byte_caps(
    cursors: Cursors, members: Command, page_size: int, max_bytes: int
) -> None:
    okta = Okta(23, page_size)
    ids = await drain(okta, cursors, members, limit=50, max_bytes=max_bytes)
    assert ids == [u["id"] for u in okta.users]


@pytest.mark.anyio
async def test_first_page_truncation_resumes_in_the_first_page(
    cursors: Cursors, members: Command
) -> None:
    okta = Okta(10, 50)
    first = await call(okta, cursors, members, None, limit=4, max_bytes=65536)
    assert first["truncated"] == "max_items"
    payload = payload_of(first["next_cursor"])
    assert (payload["q"], payload["s"]) == ("limit=200", 4)
    second = await call(okta, cursors, members, first["next_cursor"], limit=50, max_bytes=65536)
    assert [r[0] for r in second["rows"]] == [u["id"] for u in okta.users[4:]]
    assert second["warnings"] == [RESUMED_WARNING]
    assert "truncated" not in second and "next_cursor" not in second
    # The resume fetched the same first page again, as it was first sent.
    assert okta.urls == [ORG + MEMBERS + "?limit=200"] * 2


@pytest.mark.anyio
async def test_resume_sends_okta_next_link_unchanged(cursors: Cursors, members: Command) -> None:
    okta = Okta(10, 3)
    first = await call(okta, cursors, members, None, limit=5, max_bytes=65536)
    okta.urls.clear()
    second = await call(okta, cursors, members, first["next_cursor"], limit=2, max_bytes=65536)
    # Item 4, the last delivered, is index 1 of the page after=3: the resume starts there.
    assert okta.urls[0] == ORG + MEMBERS + "?after=3&limit=200"
    assert [r[0] for r in second["rows"]] == [u["id"] for u in okta.users[5:7]]


@pytest.mark.anyio
async def test_resume_with_other_args_makes_no_request(cursors: Cursors, members: Command) -> None:
    okta = Okta(10, 3)
    first = await call(okta, cursors, members, None, limit=5, max_bytes=65536)
    okta.urls.clear()
    other = merged(BOUND, {"args": {"group": "00g2emaKYZTWRYYRRTSK"}})
    with pytest.raises(CursorError):
        await call(
            okta, cursors, members, first["next_cursor"], limit=5, max_bytes=65536, bound=other
        )
    assert okta.urls == []


@pytest.mark.anyio
async def test_resume_when_the_page_shrank_goes_on_at_the_next_page(
    cursors: Cursors, members: Command
) -> None:
    okta = Okta(9, 3)
    first = await call(okta, cursors, members, None, limit=3, max_bytes=65536)
    del okta.users[1:3]  # The first page's window now holds users 0, 3, 4.
    second = await call(okta, cursors, members, first["next_cursor"], limit=50, max_bytes=65536)
    # Users 3 and 4 moved into the delivered window and are missed, as the warning says.
    assert [r[0] for r in second["rows"]] == [u["id"] for u in okta.users[3:]]


@pytest.mark.anyio
async def test_after_skips_only_in_the_first_page_and_closes_its_source() -> None:
    closed = False

    async def items() -> AsyncGenerator[tuple[Any, str, int]]:
        nonlocal closed
        try:
            for page in ("/p?a=1", "/p?a=2", "/p?a=1"):
                for i in range(3):
                    yield f"{page}:{i}", page, i
        finally:
            closed = True

    skipped = after(items(), 2)
    got = [item async for item, _, _ in skipped]
    assert got == [
        "/p?a=1:2",
        "/p?a=2:0",
        "/p?a=2:1",
        "/p?a=2:2",
        "/p?a=1:0",
        "/p?a=1:1",
        "/p?a=1:2",
    ]
    assert closed

    closed = False
    skipped = after(items(), 1)
    assert (await anext(skipped))[0] == "/p?a=1:1"
    await skipped.aclose()
    assert closed
