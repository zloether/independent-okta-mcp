"""The handler `Context` and the executor's handler path (design §5.6): only declared
operations, GET only through the one client, the §6.4 path rule, server-owned paging, optional
scopes, and the startup check that every handler command has a handler."""

import copy
import json
from collections.abc import Mapping
from typing import Any

import httpx2
import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.composite import Context, Unavailable
from okta_mcp.exec.cursor import Cursors
from okta_mcp.exec.executor import INTERNAL, Call, Code, Executor, Failure, Success
from okta_mcp.exec.resolve import UserResolver
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.policy.engine import Engine
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry, build_registry
from okta_mcp.registry.schema import InvalidArguments
from okta_mcp.registry.spec import SpecIndex, load_spec

ORG = "https://example.okta.com"
UID = "00u1alice00000000000"
GROUP = "00g1readers000000000"
SCOPES = frozenset({"okta.users.read"})
DOC: dict[str, Any] = {
    "domain": "users",
    "description": "Users.",
    "commands": {
        "probe": {
            "handler": "probe",
            "summary": "Probe a user",
            "args": {"user": {"required": True, "description": "User ID or login"}},
            "uses": {"required": ["getUser"], "optional": ["listUserGroups", "listLogEvents"]},
            "data_classes": ["pii"],
        }
    },
}


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass

    def ready(self) -> bool:
        return True


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def registry(spec: SpecIndex) -> Registry:
    return build_registry({"users.yaml": copy.deepcopy(DOC)}, spec)


class Org:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path == f"/api/v1/users/{UID}":
            return httpx2.Response(200, json={"id": UID, "profile": {"login": "a@example.com"}})
        if path == f"/api/v1/users/{UID}/groups":
            after = request.url.params.get("after")
            if after is None:
                nxt = request.url.copy_merge_params({"after": "2"})
                return httpx2.Response(
                    200, json=[{"id": "g0"}, {"id": "g1"}], headers={"Link": f'<{nxt}>; rel="next"'}
                )
            return httpx2.Response(200, json=[{"id": "g2"}])
        return httpx2.Response(404, json={})


def make(
    registry: Registry,
    spec: SpecIndex,
    org: Org,
    handlers: Mapping[str, Any],
    scopes: frozenset[str] = SCOPES,
) -> Executor:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(org)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    roles = {"r": {"groups": [GROUP], "allow": {"users": ["*"]}}}
    policy = build_policy({"version": 1, "roles": roles}, registry)
    return Executor(
        registry=registry,
        engine=Engine(policy, registry, scopes),
        client=client,
        cursors=Cursors(bytes(range(32))),
        resolver=UserResolver(client, ORG, spec.operations["getUser"]),
        org_url=ORG,
        default_limit=50,
        max_items=1000,
        max_bytes=65536,
        call_timeout=30,
        handlers=handlers,
    )


async def call(ex: Executor) -> Success | Failure:
    who = Principal(uid="00u1caller0000000000", sub="c", groups=frozenset({GROUP}))
    return await ex.execute(Call(who, "users", "probe", args={"user": UID}))


def test_a_handler_command_without_a_handler_fails_startup(
    registry: Registry, spec: SpecIndex
) -> None:
    with pytest.raises(ValueError, match="no handler for users probe"):
        make(registry, spec, Org(), handlers={})


@pytest.mark.anyio
async def test_the_handler_s_result_is_an_untrusted_scrubbed_item(
    registry: Registry, spec: SpecIndex
) -> None:
    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        user = await ctx.user("user", args["user"])
        return {"id": user["id"], "secret": "s3cr3t", "nested": {"client_secret": "x"}}

    out = await call(make(registry, spec, Org(), {"probe": probe}))
    assert isinstance(out, Success)
    body = json.loads(out.text)
    assert body == {
        "untrusted": True,
        "item": {"id": UID, "secret": "[redacted]", "nested": {"client_secret": "[redacted]"}},
    }


@pytest.mark.anyio
async def test_an_undeclared_operation_is_an_internal_error(
    registry: Registry, spec: SpecIndex
) -> None:
    org = Org()

    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        await ctx.get("listUsers")
        return {}

    out = await call(make(registry, spec, org, {"probe": probe}))
    assert isinstance(out, Failure) and out.code is Code.INTERNAL_ERROR
    assert out.message == INTERNAL
    assert org.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("param", ["after", "nope", "id"])
async def test_server_owned_or_unknown_params_are_refused(
    registry: Registry, spec: SpecIndex, param: str
) -> None:
    org = Org()

    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        await ctx.items("listUserGroups", {"id": UID}, {param: "x"}, mode="link", max_items=5)
        return {}

    out = await call(make(registry, spec, org, {"probe": probe}))
    assert isinstance(out, Failure) and out.code is Code.INTERNAL_ERROR
    assert org.requests == []


@pytest.mark.anyio
async def test_items_follow_next_links_and_stop_at_max(registry: Registry, spec: SpecIndex) -> None:
    seen: dict[str, Any] = {}

    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        seen["all"] = await ctx.items("listUserGroups", {"id": UID}, mode="link", max_items=10)
        seen["cut"] = await ctx.items("listUserGroups", {"id": UID}, mode="link", max_items=2)
        return {}

    org = Org()
    await call(make(registry, spec, org, {"probe": probe}))
    assert seen["all"] == ([{"id": "g0"}, {"id": "g1"}, {"id": "g2"}], False)
    assert seen["cut"] == ([{"id": "g0"}, {"id": "g1"}], True)


@pytest.mark.anyio
async def test_the_path_rule_applies(registry: Registry, spec: SpecIndex) -> None:
    raised: list[type[Exception]] = []
    org = Org()

    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        for value in ("me", "../x", "a/b"):
            try:
                await ctx.get("listUserGroups", {"id": value})
            except InvalidArguments as e:
                raised.append(type(e))
        return {}

    await call(make(registry, spec, org, {"probe": probe}))
    assert raised == [InvalidArguments] * 3
    assert org.requests == []


@pytest.mark.anyio
async def test_an_optional_operation_without_scopes(registry: Registry, spec: SpecIndex) -> None:
    found: dict[str, Any] = {}
    org = Org()

    async def probe(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
        found["available"] = ctx.available("listLogEvents"), ctx.available("listUserGroups")
        found["needs"] = ctx.needs("listLogEvents")
        try:
            await ctx.get("listLogEvents")
        except Unavailable as e:
            found["error"] = str(e)
        return {}

    await call(make(registry, spec, org, {"probe": probe}))
    assert found == {
        "available": (False, True),
        "needs": "okta.logs.read",
        "error": "listLogEvents needs okta.logs.read",
    }
    assert org.requests == []


def test_a_context_is_only_for_handler_commands(spec: SpecIndex) -> None:
    simple = {
        "domain": "users",
        "description": "Users.",
        "commands": {
            "get": {
                "operation": "getUser",
                "summary": "Get",
                "args": {"user": {"path_param": "id"}},
                "data_classes": ["pii"],
            }
        },
    }
    command = build_registry({"users.yaml": simple}, spec).domains["users"].commands["get"]
    client: Any = None
    with pytest.raises(RuntimeError):
        Context(command=command, client=client, engine=client, resolver=client, org_url=ORG)
