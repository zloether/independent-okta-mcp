"""The executor end to end against a mocked Okta (plan 2.10): order of checks, every §5.5 code,
cursor wiring, the resolver and the unpaged `q` rule."""

import copy
import json
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, unquote

import anyio
import httpx2
import pytest
import yaml

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.cursor import RESUMED_WARNING, Cursors
from okta_mcp.exec.envelope import UNPAGED_WARNING
from okta_mcp.exec.executor import (
    EXPRESSION,
    FORBIDDEN,
    INTERNAL,
    UNAVAILABLE,
    Call,
    Code,
    Executor,
    Failure,
    Success,
    tool_name,
)
from okta_mcp.exec.resolve import UserResolver
from okta_mcp.okta import ratelimit
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.ratelimit import RequestLimiter
from okta_mcp.okta.token import ServiceToken, TokenError
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import REGISTRY, Registry, UniqueKeyLoader, build_registry
from okta_mcp.registry.spec import SpecIndex, load_spec


class FakeTokenProvider:
    def __init__(self, token: ServiceToken | None = None) -> None:
        self._token = token or ServiceToken("fake-token", "Bearer")

    async def token(self) -> ServiceToken:
        return self._token

    def invalidate(self, token: ServiceToken) -> None:
        pass


ORG = "https://example.okta.com"
KEY = bytes(range(32))
CALLER = "00u1caller0000000000"
ALICE = "00u1alice00000000000"
GROUP = "00g1emaKYZTWRYYRRTSK"
OTHER_GROUP = "00g2emaKYZTWRYYRRTSK"
ZONE = "nzo1emaKYZTWRYYRRTSK"
READERS, ANALYSTS, ADMINS = "00g1readers000000000", "00g1secanalyst000000", "00g1abc2defGHI3jkL45"
NOBODY = "00g9nobody0000000000"
SCOPES = frozenset(
    {"okta.groups.read", "okta.roles.read", "okta.networkZones.read", "okta.users.read"}
)

# Pilot registries plus a `users` domain with resolved commands (no shipped registry has one).
USERS: dict[str, Any] = {
    "domain": "users",
    "description": "Users.",
    "commands": {
        "get": {
            "operation": "getUser",
            "summary": "Get a user",
            "args": {"user": {"path_param": "id"}},
            "data_classes": ["pii"],
        },
        "get-groups": {
            "operation": "listUserGroups",
            "summary": "Groups the user belongs to",
            "args": {"user": {"path_param": "id", "resolve": "user_id"}},
            "paginate": "link",
            "page_size": 200,
            "view": ["id", "type", "profile.name"],
            "data_classes": ["pii"],
        },
        "get-enrollments": {
            "operation": "listAuthenticatorEnrollments",
            "summary": "Authenticator enrollments",
            "args": {
                "user": {"path_param": "userId", "resolve": "user_id"},
                "disclose_identifiers": {
                    "query": "discloseIdentifiers",
                    "arg_rule": {"raises_sensitivity_to": "sensitive"},
                },
            },
            "response_override": {"kind": "list", "reason": "V8"},
            "view": ["id", "type", "status", "name"],
            "data_classes": ["pii"],
        },
    },
}

ROLES: dict[str, Any] = {
    "reader": {
        "groups": [READERS],
        "allow": {"groups": ["*"], "network-zones": ["*"], "users": ["*"]},
        "search_attributes": ["profile.name", "type"],
    },
    "analyst": {
        "groups": [ANALYSTS],
        "allow": {"groups": ["*"], "users": ["*"]},
        "include_sensitive": ["groups", "users"],
        "search_attributes": ["*"],
    },
    "admin": {"groups": [ADMINS], "allow": {"*": ["*"]}, "include_sensitive": ["*"]},
}


def who(*groups: str, uid: str = CALLER) -> Principal:
    return Principal(uid=uid, sub="caller@example.com", groups=frozenset(groups))


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def registry(spec: SpecIndex) -> Registry:
    docs: dict[str, Any] = {
        f.name: yaml.load(f.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
        for f in REGISTRY.iterdir()
        if f.name.endswith(".yaml")
    }
    return build_registry(docs | {"users.yaml": USERS}, spec)


def _user(i: int) -> dict[str, Any]:
    return {
        "id": f"00u{i:017d}",
        "status": "ACTIVE",
        "profile": {"login": f"u{i}@example.com"},
        "_links": {"self": {"href": f"{ORG}/api/v1/users/00u{i:017d}"}},
    }


def _group(i: int, name: str | None = None) -> dict[str, Any]:
    return {
        "id": f"00g{i:017d}",
        "type": "OKTA_GROUP",
        "profile": {"name": name or f"Group {i}", "apiKey": "s3cr3t"},
    }


def _not_found() -> httpx2.Response:
    return httpx2.Response(404, json={"errorSummary": "Not found: Resource not found"})


class Okta:
    """A small mocked org. Records every request; `page` overrides the page size of paged
    lists, so a few items span several pages."""

    def __init__(self, *, members: int = 10, groups: int = 10, page: int | None = None) -> None:
        self.requests: list[httpx2.Request] = []
        self.members = [_user(i) for i in range(members)]
        self.groups = [_group(i) for i in range(groups)]
        self.page = page
        self.alice = {
            "id": ALICE,
            "status": "ACTIVE",
            "profile": {"login": "Alice@Example.com", "email": "alice@example.com"},
        }
        self.override: Callable[[httpx2.Request], httpx2.Response | None] | None = None

    @property
    def paths(self) -> list[str]:
        return [unquote(r.url.path) for r in self.requests]

    def _paged(self, request: httpx2.Request, items: list[Any]) -> httpx2.Response:
        query = parse_qs(request.url.query.decode())
        size = self.page or int(query["limit"][0])
        start = int(query.get("after", ["0"])[0])
        end = start + size
        headers = {}
        if end < len(items):
            nxt = request.url.copy_merge_params({"after": str(end)})
            headers["Link"] = f'<{nxt}>; rel="next"'
        return httpx2.Response(200, json=items[start:end], headers=headers)

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        assert request.method == "GET"
        assert request.url.host == "example.okta.com"
        if self.override is not None and (response := self.override(request)) is not None:
            return response
        parts = request.url.raw_path.decode().partition("?")[0].split("/")[3:]
        parts = [unquote(p) for p in parts]
        query = parse_qs(request.url.query.decode())
        match parts:
            case ["groups"]:
                if "q" in query:
                    hits = [
                        g for g in self.groups if g["profile"]["name"].startswith(query["q"][0])
                    ]
                    return httpx2.Response(200, json=hits[: int(query["limit"][0])])
                return self._paged(request, self.groups)
            case ["groups", gid]:
                found = [g for g in self.groups if g["id"] == gid]
                return httpx2.Response(200, json=found[0]) if found else _not_found()
            case ["groups", _, "users"]:
                return self._paged(request, self.members)
            case ["groups", _, "roles"]:
                return httpx2.Response(200, json=[{"id": "r1", "type": "SUPER_ADMIN"}])
            case ["zones"]:
                return self._paged(request, [{"id": ZONE, "name": "Office", "type": "IP"}])
            case ["zones", zid]:
                return httpx2.Response(200, json={"id": zid, "name": "Office", "type": "IP"})
            case ["users", key]:
                if key == "me":
                    return httpx2.Response(200, json={"id": "00u1serviceowner0000"})
                login = self.alice["profile"]["login"].lower()
                if key in (ALICE, login) or key.lower() in (login, login.split("@")[0]):
                    return httpx2.Response(200, json=self.alice)  # shortnames too, like Okta
                return _not_found()
            case ["users", uid, "groups"]:
                assert uid.startswith("00u"), "a login reached a resolved path"
                return self._paged(request, self.groups)
            case ["users", uid, "authenticator-enrollments"]:
                assert uid.startswith("00u")
                return httpx2.Response(200, json=[{"id": "e1", "type": "email", "status": "x"}])
            case _:
                return _not_found()


def make(
    registry: Registry,
    okta: Okta,
    *,
    roles: dict[str, Any] | None = None,
    scopes: frozenset[str] = SCOPES,
    tokens: Any = None,
    executor_org: str = ORG,
    max_bytes: int = 65536,
    call_timeout: float = 30,
    on_request: Callable[[], None] | None = None,
    engine: Engine | None = None,
    spec: SpecIndex | None = None,
    with_resolver: bool = True,
) -> Executor:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=tokens or FakeTokenProvider(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
        on_request=on_request,
    )
    policy = build_policy({"version": 1, "roles": copy.deepcopy(roles or ROLES)}, registry)
    get_user = (spec or load_spec()).operations["getUser"]
    return Executor(
        registry=registry,
        engine=engine or Engine(policy, registry, scopes),
        client=client,
        cursors=Cursors(KEY),
        resolver=UserResolver(client, executor_org, get_user) if with_resolver else None,
        org_url=executor_org,
        default_limit=50,
        max_items=1000,
        max_bytes=max_bytes,
        call_timeout=call_timeout,
    )


@pytest.fixture
def okta() -> Okta:
    return Okta()


@pytest.fixture
def ex(registry: Registry, okta: Okta, spec: SpecIndex) -> Executor:
    return make(registry, okta, spec=spec)


async def run(ex: Executor, principal: Principal, domain: str, command: str, **kw: Any) -> Any:
    """The parsed envelope, or the `Failure`."""
    out = await ex.execute(Call(principal, domain, command, **kw))
    if isinstance(out, Failure):
        return out
    assert isinstance(out, Success)
    return json.loads(out.text)


def failed(out: Any, code: Code) -> Failure:
    assert isinstance(out, Failure), out
    assert out.code is code, out
    return out


# --- pilot commands end to end ---


@pytest.mark.anyio
async def test_groups_list_default_view(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "groups", "list")
    assert out == {
        "untrusted": True,
        "count": 10,
        "cols": ["id", "type", "profile.name"],
        "rows": [[g["id"], "OKTA_GROUP", g["profile"]["name"]] for g in okta.groups],
    }
    [request] = okta.requests
    assert str(request.url) == f"{ORG}/api/v1/groups?limit=200"


@pytest.mark.anyio
async def test_groups_get_whole_object_is_scrubbed(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "groups", "get", args={"group": okta.groups[3]["id"]})
    assert out == {
        "untrusted": True,
        "item": {
            "id": okta.groups[3]["id"],
            "type": "OKTA_GROUP",
            "profile": {"name": "Group 3", "apiKey": "[redacted]"},
        },
    }


@pytest.mark.anyio
async def test_groups_get_with_select(ex: Executor, okta: Okta) -> None:
    out = await run(
        ex, who(READERS), "groups", "get", args={"group": okta.groups[0]["id"]}, select="id"
    )
    assert out == {"untrusted": True, "item": {"id": okta.groups[0]["id"]}}


@pytest.mark.anyio
async def test_get_members_links_and_select_star(ex: Executor, okta: Okta) -> None:
    out = await run(
        ex, who(READERS), "groups", "get-members", args={"group": GROUP}, select="*", links=True
    )
    assert out["items"][0] == okta.members[0]
    out = await run(ex, who(READERS), "groups", "get-members", args={"group": GROUP}, select="*")
    assert "_links" not in out["items"][0]


@pytest.mark.anyio
async def test_network_zones(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "network-zones", "list", args={"filter": 'usage eq "x"'})
    assert out["rows"] == [[ZONE, "Office", "IP", None, None]]
    assert parse_qs(okta.requests[0].url.query.decode())["filter"] == ['usage eq "x"']
    out = await run(ex, who(READERS), "network-zones", "get", args={"zone": ZONE})
    assert out["item"]["id"] == ZONE


@pytest.mark.anyio
async def test_sensitive_command_for_a_role_that_has_it(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(ANALYSTS), "groups", "list-roles", args={"group": GROUP})
    assert out["rows"] == [["r1", "SUPER_ADMIN", None, None, None]]


@pytest.mark.anyio
async def test_search_within_the_roles_attributes(ex: Executor, okta: Okta) -> None:
    search = 'profile.name sw "G" and type eq "OKTA_GROUP"'
    out = await run(ex, who(READERS), "groups", "list", args={"search": search})
    assert out["count"] == 10
    assert parse_qs(okta.requests[0].url.query.decode())["search"] == [search]


@pytest.mark.anyio
async def test_limit_cuts_and_issues_a_cursor(ex: Executor) -> None:
    out = await run(ex, who(READERS), "groups", "list", limit=3)
    assert out["count"] == 3 and out["truncated"] == "max_items" and "next_cursor" in out


# --- order: nothing reaches Okta before the policy allows it ---


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("principal", "command", "args"),
    [
        (who(), "get-groups", {"user": "alice@example.com"}),  # no role at all
        (who(NOBODY), "get-groups", {"user": "alice@example.com"}),  # unknown group
        (who(NOBODY), "get-groups", {"user": "nobody@example.com"}),
        # Permitted command, but `disclose_identifiers` raises it beyond the reader's grant.
        (
            who(READERS),
            "get-enrollments",
            {"user": "alice@example.com", "disclose_identifiers": ["phone"]},
        ),
    ],
)
async def test_forbidden_call_sends_nothing_not_even_the_resolver(
    registry: Registry, okta: Okta, principal: Principal, command: str, args: dict[str, Any]
) -> None:
    ex = make(registry, okta)
    out = failed(await run(ex, principal, "users", command, args=args), Code.FORBIDDEN_BY_POLICY)
    assert out.message == FORBIDDEN
    assert okta.requests == []


@pytest.mark.anyio
async def test_no_resolver_oracle(ex: Executor, okta: Okta) -> None:
    # A login that exists and one that doesn't get the same answer, and nothing is sent.
    a = await run(ex, who(NOBODY), "users", "get-groups", args={"user": "alice@example.com"})
    b = await run(ex, who(NOBODY), "users", "get-groups", args={"user": "zed@example.com"})
    assert a == b and okta.requests == []


@pytest.mark.anyio
async def test_forbidden_before_args_are_read(ex: Executor, okta: Okta) -> None:
    # A command the caller may not use doesn't name its args through invalid_arguments.
    out = await run(ex, who(NOBODY), "groups", "get", args={"nope": 1}, select=5, limit=0)
    assert failed(out, Code.FORBIDDEN_BY_POLICY).message == FORBIDDEN
    out = await run(ex, who(NOBODY), "groups", "list", cursor="garbage")
    failed(out, Code.FORBIDDEN_BY_POLICY)


@pytest.mark.anyio
@pytest.mark.parametrize(("domain", "command"), [("groups", "nope"), ("nope", "list"), ("", "")])
async def test_unknown_command_is_forbidden(ex: Executor, domain: str, command: str) -> None:
    failed(await run(ex, who(ADMINS), domain, command), Code.FORBIDDEN_BY_POLICY)


@pytest.mark.anyio
async def test_typo_is_invalid_not_forbidden(ex: Executor, okta: Okta) -> None:
    # `check` would call an unknown arg name forbidden; validation comes first.
    out = failed(
        await run(ex, who(READERS), "groups", "get", args={"grp": GROUP}), Code.INVALID_ARGUMENTS
    )
    assert "group" in out.message and okta.requests == []


@pytest.mark.anyio
async def test_path_rule_runs_before_the_policy_check_and_resolver(
    ex: Executor, okta: Okta
) -> None:
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": "a/../b"})
    failed(out, Code.INVALID_ARGUMENTS)
    assert okta.requests == []


class _Stub(Engine):
    def __init__(self, inner: Engine, verdict: Any) -> None:
        self.__dict__.update(inner.__dict__)
        self._verdict = verdict

    def check(self, *args: Any, **kwargs: Any) -> Any:
        return self._verdict


@pytest.mark.anyio
@pytest.mark.parametrize("verdict", [None, "allowed", True, 0])
async def test_only_allowed_proceeds(
    registry: Registry, okta: Okta, spec: SpecIndex, verdict: Any
) -> None:
    base = make(registry, okta, spec=spec)
    ex = make(registry, okta, spec=spec, engine=_Stub(base._engine, verdict))  # pyright: ignore[reportPrivateUsage]
    out = await run(ex, who(READERS), "groups", "list")
    failed(out, Code.INTERNAL_ERROR)
    assert okta.requests == []
    # The stub does reach Okta when it does say ALLOWED.
    ex = make(registry, okta, spec=spec, engine=_Stub(base._engine, Verdict.ALLOWED))  # pyright: ignore[reportPrivateUsage]
    assert (await run(ex, who(), "groups", "list")) is not None
    assert okta.requests == []  # `permitted` still says no for a principal without roles
    assert (await run(ex, who(READERS), "groups", "list"))["count"] == 10


# --- every §5.5 code ---


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kw",
    [
        {"args": {"group": "00g1"}},
        {"args": "group"},
        {"args": {"group": GROUP}, "select": "a,,b"},
        {"args": {"group": GROUP}, "select": 5},
        {"args": {"group": GROUP}, "links": "yes"},
        {"args": {"group": GROUP}, "limit": 0},
        {"args": {"group": GROUP}, "limit": 1001},
        {"args": {"group": GROUP}, "limit": True},
        {"args": {"group": GROUP}, "limit": 5.0},
        {"args": {"group": GROUP}, "cursor": 5},
        {"args": {"group": GROUP}, "cursor": "not.a.cursor"},
    ],
)
async def test_invalid_arguments(ex: Executor, okta: Okta, kw: dict[str, Any]) -> None:
    failed(await run(ex, who(READERS), "groups", "get-members", **kw), Code.INVALID_ARGUMENTS)
    assert okta.requests == []


@pytest.mark.anyio
async def test_unreadable_expression_says_what_may_be_named(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "groups", "list", args={"search": "profile.name sw 'G'"})
    out = failed(out, Code.INVALID_ARGUMENTS)
    assert out.message.startswith(EXPRESSION)
    assert out.message.endswith("expressions may name only: profile.name, type")
    out = await run(ex, who(ANALYSTS), "groups", "list", args={"sort_by": "a b"})
    assert failed(out, Code.INVALID_ARGUMENTS).message.endswith("don't redact")
    assert okta.requests == []


@pytest.mark.anyio
async def test_forbidden_attribute_says_what_may_be_named(ex: Executor, okta: Okta) -> None:
    args = {"search": 'profile.description sw "a"'}
    out = failed(await run(ex, who(READERS), "groups", "list", args=args), Code.FORBIDDEN_BY_POLICY)
    assert out.message == f"{FORBIDDEN}; expressions may name only: profile.name, type"
    # Redacted for everyone, `*` included.
    args = {"search": 'profile.apiKey sw "a"'}
    out = failed(
        await run(ex, who(ANALYSTS), "groups", "list", args=args), Code.FORBIDDEN_BY_POLICY
    )
    assert out.message.endswith("any attribute that results don't redact")
    # No search_attributes at all (admin role).
    args = {"search": 'profile.name sw "a"'}
    out = failed(await run(ex, who(ADMINS), "groups", "list", args=args), Code.FORBIDDEN_BY_POLICY)
    assert out.message.endswith("no search, filter or sort expression on this command")
    # A refusal with no expression arg is the one fixed sentence.
    out = await run(ex, who(READERS), "groups", "list", args={"expand": "stats"})
    assert failed(out, Code.FORBIDDEN_BY_POLICY).message == FORBIDDEN
    assert okta.requests == []


@pytest.mark.anyio
async def test_many_search_attributes_are_capped(
    registry: Registry, okta: Okta, spec: SpecIndex
) -> None:
    names = [f"profile.a{i:02d}" for i in range(25)]
    roles = {"r": {"groups": [READERS], "allow": {"groups": ["list"]}, "search_attributes": names}}
    ex = make(registry, okta, roles=roles, spec=spec)
    out = await run(ex, who(READERS), "groups", "list", args={"search": 'profile.b eq "x"'})
    message = failed(out, Code.FORBIDDEN_BY_POLICY).message
    assert message.endswith("profile.a19 (+5)") and "profile.a20" not in message


@pytest.mark.anyio
async def test_unavailable(registry: Registry, okta: Okta, spec: SpecIndex) -> None:
    ex = make(registry, okta, scopes=SCOPES - {"okta.roles.read"}, spec=spec)
    out = await run(ex, who(ANALYSTS), "groups", "list-roles", args={"group": GROUP})
    assert failed(out, Code.UNAVAILABLE).message == UNAVAILABLE
    # The gate is after the policy: without the grant it's forbidden, scopes unseen.
    out = await run(ex, who(READERS), "groups", "list-roles", args={"group": GROUP})
    failed(out, Code.FORBIDDEN_BY_POLICY)
    assert okta.requests == []


@pytest.mark.anyio
async def test_not_found(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": "zed@example.com"})
    assert failed(out, Code.NOT_FOUND).message == "no user has that ID or exact login"
    assert "zed" not in out.message
    assert okta.paths == ["/api/v1/users/zed@example.com"]


@pytest.mark.anyio
async def test_upstream_error(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "groups", "get", args={"group": OTHER_GROUP})
    message = failed(out, Code.UPSTREAM_ERROR).message
    assert message == "Okta returned HTTP 404: Not found: Resource not found"


@pytest.mark.anyio
async def test_upstream_error_for_a_bad_next_link(ex: Executor, okta: Okta) -> None:
    def evil(request: httpx2.Request) -> httpx2.Response:
        link = '<https://evil.example.com/api/v1/groups?after=1>; rel="next"'
        return httpx2.Response(200, json=[_group(1)], headers={"Link": link})

    okta.override = evil
    out = await run(ex, who(READERS), "groups", "list", limit=5)
    assert "not on the operation's path" in failed(out, Code.UPSTREAM_ERROR).message
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_upstream_error_for_a_non_json_item(ex: Executor, okta: Okta) -> None:
    okta.override = lambda request: httpx2.Response(200, text="<html>")
    out = await run(ex, who(READERS), "groups", "get", args={"group": GROUP})
    assert failed(out, Code.UPSTREAM_ERROR).message == "Okta's response is not JSON"


@pytest.mark.anyio
async def test_token_failure_is_upstream_error(
    registry: Registry, okta: Okta, spec: SpecIndex
) -> None:
    class Broken(FakeTokenProvider):
        async def token(self) -> ServiceToken:
            raise TokenError("hint for the operator: key s3cr3t")

    ex = make(registry, okta, tokens=Broken(), spec=spec)
    out = await run(ex, who(READERS), "groups", "list")
    assert "credentials are unavailable" in failed(out, Code.UPSTREAM_ERROR).message
    assert "s3cr3t" not in out.message


@pytest.mark.anyio
async def test_rate_limited_by_okta(ex: Executor, okta: Okta) -> None:
    okta.override = lambda request: httpx2.Response(429)
    out = await run(ex, who(READERS), "groups", "get", args={"group": GROUP})
    failed(out, Code.RATE_LIMITED)


@pytest.mark.anyio
async def test_rate_limited_per_principal(registry: Registry, okta: Okta, spec: SpecIndex) -> None:
    limiter = RequestLimiter(2)
    ex = make(registry, okta, on_request=limiter.charge, spec=spec)
    for _ in range(2):
        assert (await run(ex, who(READERS), "groups", "get", args={"group": okta.groups[0]["id"]}))[
            "item"
        ]
    failed(
        await run(ex, who(READERS), "groups", "get", args={"group": okta.groups[0]["id"]}),
        Code.RATE_LIMITED,
    )
    # Charged to the caller of each call: another principal is not limited.
    other = who(READERS, uid="00u1other00000000000")
    assert (await run(ex, other, "groups", "get", args={"group": okta.groups[0]["id"]}))["item"]
    assert ratelimit.principal.get() is None  # reset after each call


@pytest.mark.anyio
async def test_timeout(registry: Registry, okta: Okta, spec: SpecIndex) -> None:
    async def slow(request: httpx2.Request) -> httpx2.Response:
        await anyio.sleep(20)
        return httpx2.Response(200, json={})

    ex = make(registry, okta, call_timeout=2, spec=spec)
    ex._client._http = new_http_client(httpx2.MockTransport(slow))  # pyright: ignore[reportPrivateUsage]
    with anyio.fail_after(8):
        out = await run(ex, who(READERS), "groups", "get", args={"group": GROUP})
    assert failed(out, Code.TIMEOUT).message == "the call took longer than 2 s"


@pytest.mark.anyio
async def test_timeout_covers_the_resolver(registry: Registry, okta: Okta, spec: SpecIndex) -> None:
    async def slow(request: httpx2.Request) -> httpx2.Response:
        await anyio.sleep(20)
        return httpx2.Response(200, json={})

    ex = make(registry, okta, call_timeout=2, spec=spec)
    ex._client._http = new_http_client(httpx2.MockTransport(slow))  # pyright: ignore[reportPrivateUsage]
    with anyio.fail_after(8):
        out = await run(ex, who(READERS), "users", "get-groups", args={"user": "a@example.com"})
    failed(out, Code.TIMEOUT)


@pytest.mark.anyio
async def test_result_too_large(registry: Registry, okta: Okta, spec: SpecIndex) -> None:
    okta.groups[0]["profile"]["description"] = "x" * 2000
    ex = make(registry, okta, max_bytes=1024, spec=spec)
    out = await run(ex, who(READERS), "groups", "get", args={"group": okta.groups[0]["id"]})
    assert "select" in failed(out, Code.RESULT_TOO_LARGE).message


@pytest.mark.anyio
async def test_internal_error_for_a_dpop_token_without_a_key(
    registry: Registry, okta: Okta, spec: SpecIndex, caplog: pytest.LogCaptureFixture
) -> None:
    tokens = FakeTokenProvider(ServiceToken("tok-s3cr3t", "DPoP"))
    ex = make(registry, okta, tokens=tokens, spec=spec)
    with caplog.at_level(logging.ERROR):
        out = await run(ex, who(READERS), "groups", "list")
    assert failed(out, Code.INTERNAL_ERROR).message == INTERNAL
    assert okta.requests == []
    assert "RuntimeError" in caplog.text and "tok-s3cr3t" not in caplog.text


@pytest.mark.anyio
async def test_internal_error_logs_no_exception_message(
    registry: Registry, okta: Okta, spec: SpecIndex, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "-".join(["body", "s3cr3t"])  # not a literal, so the logged source line lacks it

    def boom(request: httpx2.Request) -> httpx2.Response:
        raise KeyError(secret)  # e.g. a bug that puts Okta data in an exception

    okta.override = boom
    ex = make(registry, okta, spec=spec)
    with caplog.at_level(logging.ERROR):
        out = await run(ex, who(READERS), "groups", "list")
    assert failed(out, Code.INTERNAL_ERROR).message == INTERNAL
    assert "KeyError" in caplog.text and "body-s3cr3t" not in caplog.text


@pytest.mark.anyio
async def test_internal_error_for_a_url_off_the_org(
    registry: Registry, okta: Okta, spec: SpecIndex
) -> None:
    # The executor and the client disagree on the org: the client's origin check refuses.
    ex = make(registry, okta, executor_org="https://other.example.com", spec=spec)
    failed(await run(ex, who(READERS), "groups", "list"), Code.INTERNAL_ERROR)
    failed(
        await run(ex, who(READERS), "users", "get-groups", args={"user": "a@example.com"}),
        Code.INTERNAL_ERROR,
    )
    assert okta.requests == []


@pytest.mark.anyio
async def test_internal_error_for_a_principal_without_uid(ex: Executor, okta: Okta) -> None:
    failed(await run(ex, who(ADMINS, uid=""), "groups", "list"), Code.INTERNAL_ERROR)
    assert okta.requests == []


def test_failure_envelope() -> None:
    text = Failure(Code.NOT_FOUND, "no user").text("a1b2c3d4")
    assert text == '{"error":{"code":"not_found","message":"no user","request_id":"a1b2c3d4"}}'


def test_codes_are_the_design_codes() -> None:
    assert {c.value for c in Code} == {
        "invalid_arguments",
        "forbidden_by_policy",
        "unavailable",
        "not_found",
        "upstream_error",
        "rate_limited",
        "timeout",
        "result_too_large",
        "internal_error",
    }
    assert {v.value for v in Verdict} - {"allowed"} <= {c.value for c in Code}


def test_tool_name() -> None:
    assert tool_name("network-zones") == "okta_network_zones"
    assert tool_name("groups") == "okta_groups"


def test_default_limit_must_fit(registry: Registry, okta: Okta) -> None:
    ex = make(registry, okta)
    with pytest.raises(ValueError, match="default_limit"):
        Executor(
            registry=registry,
            engine=ex._engine,  # pyright: ignore[reportPrivateUsage]
            client=ex._client,  # pyright: ignore[reportPrivateUsage]
            cursors=Cursors(KEY),
            resolver=None,
            org_url=ORG,
            default_limit=51,
            max_items=50,
            max_bytes=65536,
            call_timeout=30,
        )


# --- resolver ---


@pytest.mark.anyio
async def test_login_is_resolved_then_used(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": "alice@EXAMPLE.com"})
    assert out["count"] == 10
    assert okta.paths == ["/api/v1/users/alice@EXAMPLE.com", f"/api/v1/users/{ALICE}/groups"]


@pytest.mark.anyio
async def test_user_id_short_circuits(ex: Executor, okta: Okta) -> None:
    await run(ex, who(READERS), "users", "get-groups", args={"user": ALICE})
    assert okta.paths == [f"/api/v1/users/{ALICE}/groups"]


@pytest.mark.anyio
async def test_shortname_is_not_an_exact_login(ex: Executor, okta: Okta) -> None:
    # Okta answers getUser for a login shortname; the resolver wants the exact login.
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": "alice"})
    failed(out, Code.NOT_FOUND)
    assert okta.paths == ["/api/v1/users/alice"]


@pytest.mark.anyio
@pytest.mark.parametrize("value", ["me", "ME", "Me", "\N{FULLWIDTH LATIN SMALL LETTER M}e"])
async def test_resolver_refuses_me(ex: Executor, okta: Okta, value: str) -> None:
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": value})
    failed(out, Code.INVALID_ARGUMENTS)
    assert okta.requests == []


@pytest.mark.anyio
async def test_me_refused_on_an_unresolved_user_path_too(ex: Executor, okta: Okta) -> None:
    out = await run(ex, who(READERS), "users", "get", args={"user": "me"})
    failed(out, Code.INVALID_ARGUMENTS)
    assert okta.requests == []


@pytest.mark.anyio
async def test_raised_call_with_the_grant_is_resolved(ex: Executor, okta: Okta) -> None:
    args = {"user": "alice@example.com", "disclose_identifiers": ["phone"]}
    out = await run(ex, who(ANALYSTS), "users", "get-enrollments", args=args)
    assert out["rows"] == [["e1", "email", "x", None]]
    assert okta.paths[-1] == f"/api/v1/users/{ALICE}/authenticator-enrollments"
    assert okta.requests[-1].url.query == b"discloseIdentifiers=phone"


# --- cursors ---


async def pages(ex: Executor, principal: Principal, domain: str, command: str, **kw: Any) -> Any:
    out = await run(ex, principal, domain, command, **kw)
    assert not isinstance(out, Failure), out
    return out


@pytest.mark.anyio
async def test_resume_delivers_the_rest(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(members=23, page=5)
    ex = make(registry, okta, spec=spec)
    args = {"group": GROUP}
    ids: list[str] = []
    cursor = None
    for _ in range(20):
        kw: dict[str, Any] = {"args": args, "limit": 7}
        if cursor:
            kw["cursor"] = cursor
        out = await pages(ex, who(READERS), "groups", "get-members", **kw)
        assert (out.get("warnings") == [RESUMED_WARNING]) == (cursor is not None)
        ids += [r[0] for r in out["rows"]]
        cursor = out.get("next_cursor")
        if cursor is None:
            break
    assert ids == [u["id"] for u in okta.members]


@pytest.mark.anyio
async def test_resume_does_not_call_the_resolver(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=9, page=4)
    ex = make(registry, okta, spec=spec)
    args = {"user": "alice@example.com"}
    first = await pages(ex, who(READERS), "users", "get-groups", args=args, limit=4)
    lookup, groups = "/api/v1/users/alice@example.com", f"/api/v1/users/{ALICE}/groups"
    assert okta.paths == [lookup, groups, groups]  # one past the limit reads page 2
    okta.requests.clear()
    second = await pages(
        ex, who(READERS), "users", "get-groups", args=args, limit=4, cursor=first["next_cursor"]
    )
    assert okta.paths and set(okta.paths) == {groups}
    assert [r[0] for r in second["rows"]] == [g["id"] for g in okta.groups[4:8]]


@pytest.mark.anyio
async def test_role_change_between_pages_is_enforced(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(members=30, page=10)
    ex = make(registry, okta, spec=spec)
    args = {"group": GROUP, "search": 'profile.login sw "u"'}  # an analyst's search
    first = await pages(ex, who(ANALYSTS), "groups", "get-members", args=args, limit=5)
    cursor = first["next_cursor"]
    okta.requests.clear()
    # Same user, now only a reader: get-members is still allowed, the expression is not.
    out = await run(ex, who(READERS), "groups", "get-members", args=args, cursor=cursor)
    failed(out, Code.FORBIDDEN_BY_POLICY)
    # Same user, no role left at all.
    out = await run(ex, who(NOBODY), "groups", "get-members", args=args, cursor=cursor)
    failed(out, Code.FORBIDDEN_BY_POLICY)
    assert okta.requests == []
    # The analyst role back: the cursor still works.
    out = await pages(ex, who(ANALYSTS), "groups", "get-members", args=args, cursor=cursor)
    assert out["rows"][0][0] == okta.members[5]["id"]


@pytest.mark.anyio
async def test_role_change_on_a_raised_command(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta()
    ex = make(registry, okta, spec=spec)
    first = await pages(ex, who(ANALYSTS), "groups", "list", args={"expand": "stats"}, limit=2)
    out = await run(
        ex, who(READERS), "groups", "list", args={"expand": "stats"}, cursor=first["next_cursor"]
    )
    failed(out, Code.FORBIDDEN_BY_POLICY)


@pytest.mark.anyio
async def test_cursor_resent_with_other_args(ex: Executor, okta: Okta) -> None:
    first = await pages(ex, who(READERS), "groups", "list", limit=2)
    out = await run(
        ex,
        who(READERS),
        "groups",
        "list",
        args={"filter": 'type eq "x"'},
        cursor=first["next_cursor"],
    )
    assert "other args" in failed(out, Code.INVALID_ARGUMENTS).message
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_cursor_of_another_caller_command_or_tool(ex: Executor, okta: Okta) -> None:
    first = await pages(ex, who(READERS), "groups", "get-members", args={"group": GROUP}, limit=2)
    cursor = first["next_cursor"]
    other = who(READERS, uid="00u1other00000000000")
    out = await run(ex, other, "groups", "get-members", args={"group": GROUP}, cursor=cursor)
    failed(out, Code.INVALID_ARGUMENTS)
    out = await run(ex, who(READERS), "groups", "get-apps", args={"group": GROUP}, cursor=cursor)
    failed(out, Code.INVALID_ARGUMENTS)
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_cursor_on_a_single_resource_or_non_resumable_call(ex: Executor, okta: Okta) -> None:
    first = await pages(ex, who(READERS), "groups", "list", limit=2)
    cursor = first["next_cursor"]
    out = await run(ex, who(READERS), "groups", "get", args={"group": GROUP}, cursor=cursor)
    assert "not valid" in failed(out, Code.INVALID_ARGUMENTS).message
    out = await run(ex, who(READERS), "groups", "list", args={"q": "G"}, cursor=cursor)
    failed(out, Code.INVALID_ARGUMENTS)
    assert len(okta.requests) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(("command", "args"), [("list", {"q": "Group"}), ("get", {"group": GROUP})])
async def test_authentic_cursor_on_a_call_that_is_never_resumed(
    ex: Executor, okta: Okta, command: str, args: dict[str, Any]
) -> None:
    # Signed with the server's key, for this caller, command and args: still refused, since
    # such a call never issues one.
    cursor = Cursors(KEY).issue(
        "/api/v1/groups?limit=200",
        0,
        uid=CALLER,
        tool="okta_groups",
        command=command,
        args=args,
        path_params={"groupId": GROUP} if "group" in args else {},
    )
    out = await run(ex, who(READERS), "groups", command, args=args, cursor=cursor)
    assert "not valid" in failed(out, Code.INVALID_ARGUMENTS).message
    assert okta.requests == []


@pytest.mark.anyio
async def test_cursor_open_comes_before_the_policy_check(
    registry: Registry, okta: Okta, spec: SpecIndex
) -> None:
    # A permitted command with a refused arg and a bad cursor: the cursor is refused first.
    ex = make(registry, okta, spec=spec)
    out = await run(ex, who(READERS), "groups", "list", args={"expand": "stats"}, cursor="x.y")
    failed(out, Code.INVALID_ARGUMENTS)


@pytest.mark.anyio
async def test_non_resumable_cut_has_no_cursor(ex: Executor) -> None:
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"}, limit=3)
    assert out["truncated"] == "non_resumable" and "next_cursor" not in out


# --- groups list with q: Okta doesn't page it ---


@pytest.mark.anyio
async def test_q_over_a_page_is_reported_cut(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=250)
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"}, limit=1000)
    assert out["count"] == 200
    assert out["truncated"] == "non_resumable"
    assert out["warnings"] == [UNPAGED_WARNING]
    assert "next_cursor" not in out
    [request] = okta.requests
    assert parse_qs(request.url.query.decode()) == {"q": ["Group"], "limit": ["200"]}


@pytest.mark.anyio
async def test_q_ignoring_limit_is_reported_cut(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=250)
    okta.override = lambda request: httpx2.Response(200, json=okta.groups)  # all 250
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"}, limit=1000)
    assert out["count"] == 250 and out["truncated"] == "non_resumable"
    assert out["warnings"] == [UNPAGED_WARNING]


@pytest.mark.anyio
async def test_q_under_a_page_is_complete(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=150)
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"}, limit=1000)
    assert out["count"] == 150 and "truncated" not in out and "warnings" not in out


@pytest.mark.anyio
async def test_q_ignores_a_next_link(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=5)

    def linked(request: httpx2.Request) -> httpx2.Response:
        link = f'<{ORG}/api/v1/groups?q=G&after=x&limit=200>; rel="next"'
        return httpx2.Response(200, json=okta.groups, headers={"Link": link})

    okta.override = linked
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "G"}, limit=1000)
    assert out["count"] == 5 and len(okta.requests) == 1


@pytest.mark.anyio
async def test_without_q_the_list_pages(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=250)
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", limit=1000)
    assert out["count"] == 250 and "truncated" not in out and len(okta.requests) == 2


# --- 2.10 review ---


@pytest.mark.anyio
async def test_q_full_page_warns_with_the_default_limit(
    registry: Registry, spec: SpecIndex
) -> None:
    # C1: the warning follows Okta's page length, not where the limit stopped reading.
    okta = Okta(groups=250)
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"})
    assert out["count"] == 50 and out["truncated"] == "non_resumable"
    assert out["warnings"] == [UNPAGED_WARNING]


@pytest.mark.anyio
async def test_q_full_page_warns_on_a_byte_cut(registry: Registry, spec: SpecIndex) -> None:
    okta = Okta(groups=250)
    ex = make(registry, okta, spec=spec, max_bytes=1024)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"}, limit=1000)
    assert out["count"] < 200 and out["truncated"] == "non_resumable"
    assert out["warnings"] == [UNPAGED_WARNING]


@pytest.mark.anyio
async def test_q_short_page_cut_by_limit_has_no_warning(
    registry: Registry, spec: SpecIndex
) -> None:
    okta = Okta(groups=150)
    ex = make(registry, okta, spec=spec)
    out = await pages(ex, who(READERS), "groups", "list", args={"q": "Group"})
    assert out["truncated"] == "non_resumable" and "warnings" not in out


@pytest.mark.parametrize("timeout", [0.2, 1.0, 1.9])
def test_call_timeout_must_exceed_the_list_headroom(
    registry: Registry, okta: Okta, timeout: float
) -> None:
    # C3: at or under the 1 s soft stop every list would time out or come back cut.
    with pytest.raises(ValueError, match="call_timeout"):
        make(registry, okta, call_timeout=timeout)


def test_resolver_required_when_a_command_resolves(registry: Registry, okta: Okta) -> None:
    # C4: fail at startup, not per call.
    with pytest.raises(ValueError, match="resolver"):
        make(registry, okta, with_resolver=False)


@pytest.mark.anyio
async def test_hint_only_when_the_expression_is_the_cause(ex: Executor, okta: Okta) -> None:
    # C5: `expand=stats` needs a raise the reader lacks; the search itself is fine.
    args = {"expand": "stats", "search": 'profile.name sw "G"'}
    out = failed(await run(ex, who(READERS), "groups", "list", args=args), Code.FORBIDDEN_BY_POLICY)
    assert out.message == FORBIDDEN
    assert okta.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("domain", "command"),
    [(["groups"], "list"), ("groups", ["list"]), ({"a": 1}, "list"), (None, None), (5, "get")],
)
async def test_non_string_names_are_refused_like_unknown_ones(
    ex: Executor, okta: Okta, caplog: pytest.LogCaptureFixture, domain: Any, command: Any
) -> None:
    # S2: the same fixed refusal as an unknown command, nothing sent, nothing logged.
    with caplog.at_level(logging.DEBUG, logger="okta_mcp"):
        out = await run(ex, who(ADMINS), domain, command)
    assert failed(out, Code.FORBIDDEN_BY_POLICY).message == FORBIDDEN
    assert okta.requests == [] and caplog.text == ""


@pytest.mark.anyio
async def test_log_lines_carry_no_unbounded_caller_data(
    ex: Executor, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR):
        out = await run(ex, who(ADMINS, uid=""), "d" * 5000, "c" * 5000)
    failed(out, Code.INTERNAL_ERROR)
    assert caplog.text.count("c") < 200 and caplog.text.count("d") < 200


@pytest.mark.anyio
@pytest.mark.parametrize("value", ["me.json", "me.", "ME;x", "me;", "a;b@example.com"])
async def test_me_with_a_suffix_or_matrix_param_is_refused(
    ex: Executor, okta: Okta, value: str
) -> None:
    # S1: in case Okta matches `/users/me.json` or `/users/me;x` as `/users/me`.
    for command in ("get", "get-groups"):
        out = await run(ex, who(READERS), "users", command, args={"user": value})
        failed(out, Code.INVALID_ARGUMENTS)
    assert okta.requests == []


@pytest.mark.anyio
async def test_login_with_dots_still_resolves(ex: Executor, okta: Okta) -> None:
    okta.alice["profile"]["login"] = "alice.mel@example.com"
    okta_login = "alice.mel@example.com"

    def answer(request: httpx2.Request) -> httpx2.Response | None:
        if unquote(request.url.path) == f"/api/v1/users/{okta_login}":
            return httpx2.Response(200, json=okta.alice)
        return None

    okta.override = answer
    out = await run(ex, who(READERS), "users", "get-groups", args={"user": okta_login})
    assert out["count"] == 10


# --- 2.10 review, round 2 ---


@pytest.mark.anyio
@pytest.mark.parametrize(
    "args",
    [
        {"q": "G" * 65536},
        {"q": "G" * 4097},
        {"search": 'profile.name eq "' + "a" * 70000 + '"'},
        {"filter": "x" * 10_000},
        {1: "x"},
        {("t",): "x"},
        {"q": "\ud800"},  # a lone surrogate can't be sent (UTF-8)
        {"filter": 'type eq "\udfff"'},
    ],
)
async def test_oversized_or_odd_args_are_invalid_not_internal(
    ex: Executor, okta: Okta, caplog: pytest.LogCaptureFixture, args: dict[Any, Any]
) -> None:
    # R1: caller input never reaches `internal_error`, and nothing is sent.
    with caplog.at_level(logging.ERROR):
        out = await run(ex, who(ANALYSTS), "groups", "list", args=args)
    failed(out, Code.INVALID_ARGUMENTS)
    assert okta.requests == [] and caplog.text == ""


@pytest.mark.anyio
async def test_a_url_too_long_after_validation_is_invalid(
    registry: Registry, okta: Okta, spec: SpecIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    # R1, residual: should the bounds ever allow a URL httpx2 refuses, it is still the args.
    monkeypatch.setattr(httpx2._urlparse, "MAX_URL_LENGTH", 100)  # pyright: ignore[reportPrivateUsage]
    ex = make(registry, okta, spec=spec)
    out = await run(ex, who(ANALYSTS), "groups", "list", args={"q": "G" * 200})
    assert "too long" in failed(out, Code.INVALID_ARGUMENTS).message
    assert okta.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("q", [None, "G"])
async def test_envelope_alone_too_large_sends_nothing(
    registry: Registry, okta: Okta, spec: SpecIndex, q: str | None
) -> None:
    # R2: with or without the unpaged `q`, and before the resolver too.
    ex = make(registry, okta, spec=spec, max_bytes=1024)
    select = ",".join(f"profile.attribute{i}" for i in range(60))
    args = {} if q is None else {"q": q}
    failed(
        await run(ex, who(READERS), "groups", "list", args=args, select=select),
        Code.RESULT_TOO_LARGE,
    )
    out = await run(
        ex, who(READERS), "users", "get-groups", args={"user": "a@example.com"}, select=select
    )
    failed(out, Code.RESULT_TOO_LARGE)
    assert okta.requests == []


def test_resolver_refuses_a_get_user_without_me_reserved(spec: SpecIndex, okta: Okta) -> None:
    # R5: a hand-built or changed operation fails at startup, not open.
    import dataclasses
    from types import MappingProxyType

    bare = dataclasses.replace(spec.operations["getUser"], reserved=MappingProxyType({}))
    with pytest.raises(ValueError, match="me"):
        UserResolver(object(), ORG, bare)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


@pytest.mark.anyio
async def test_hint_when_only_the_expression_is_refused(ex: Executor, okta: Okta) -> None:
    # R7: the positive case of `test_hint_only_when_the_expression_is_the_cause`, same fixture.
    args = {"filter": 'type eq "OKTA_GROUP"', "search": 'profile.description sw "G"'}
    out = failed(await run(ex, who(READERS), "groups", "list", args=args), Code.FORBIDDEN_BY_POLICY)
    assert out.message == f"{FORBIDDEN}; expressions may name only: profile.name, type"
