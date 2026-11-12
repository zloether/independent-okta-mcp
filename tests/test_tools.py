"""The per-principal tool surface (plan 3.3, design §5.1-5.3, §5.5)."""

import copy
import dataclasses
import json
from types import MappingProxyType
from typing import Any

import httpx2
import pytest
from jsonschema import Draft202012Validator

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.cursor import Cursors
from okta_mcp.exec.executor import (
    CURSOR_MAX,
    FORBIDDEN,
    UNAVAILABLE,
    Code,
    Executor,
    Failure,
    Success,
)
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.policy.engine import Engine
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Domain, Registry, load_registry
from okta_mcp.registry.schema import help_text
from okta_mcp.registry.spec import load_spec
from okta_mcp.tools import NO_ROLES, Text, Tools

ORG = "https://example.okta.com"
ZONE = "nzo1emaKYZTWRYYRRTSK"
READERS = "00g1readers000000000"
ANALYSTS = "00g1secanalyst000000"
ZONERS = "00g1zoneonly00000000"
NOBODY = "00g9nobody0000000000"
ALL_SCOPES = frozenset({"okta.groups.read", "okta.roles.read", "okta.networkZones.read"})

ROLES: dict[str, Any] = {
    "reader": {
        "groups": [READERS],
        "allow": {"groups": ["list", "get", "get-members"], "network-zones": ["*"]},
        "search_attributes": ["profile.name", "type"],
    },
    "analyst": {
        "groups": [ANALYSTS],
        "allow": {"groups": ["*"]},
        "include_sensitive": ["groups"],
        "search_attributes": ["*"],
    },
    "zoner": {"groups": [ZONERS], "allow": {"network-zones": ["*"]}},
}


class FakeTokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass

    def ready(self) -> bool:
        return True


class Okta:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/zones"):
            return httpx2.Response(200, json=[{"id": ZONE, "name": "Office", "type": "IP"}])
        if "/zones/" in path:
            return httpx2.Response(200, json={"id": ZONE, "name": "Office", "type": "IP"})
        if path.endswith("/groups"):
            return httpx2.Response(
                200,
                json=[
                    {"id": "00g1emaKYZTWRYYRRTSK", "type": "OKTA_GROUP", "profile": {"name": "G"}}
                ],
            )
        return httpx2.Response(404, json={"errorSummary": "Not found"})


def who(*groups: str) -> Principal:
    return Principal(uid="00u1caller0000000000", sub="caller@example.com", groups=frozenset(groups))


def build(
    registry: Registry,
    okta: Okta,
    *,
    scopes: frozenset[str] = ALL_SCOPES,
    guides: frozenset[str] = frozenset(),
) -> Tools:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=FakeTokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    policy = build_policy({"version": 1, "roles": copy.deepcopy(ROLES)}, registry)
    engine = Engine(policy, registry, scopes)
    executor = Executor(
        registry=registry,
        engine=engine,
        client=client,
        cursors=Cursors(bytes(range(32))),
        resolver=None,
        org_url=ORG,
        default_limit=50,
        max_items=1000,
        max_bytes=65536,
        call_timeout=30,
    )
    return Tools(registry=registry, engine=engine, executor=executor, max_items=1000, guides=guides)


@pytest.fixture(scope="module")
def registry() -> Registry:
    """The shipped pilot domains, which these tests assert on; they need no resolver."""
    shipped = load_registry(load_spec())
    return Registry(MappingProxyType({d: shipped.domains[d] for d in ("groups", "network-zones")}))


@pytest.fixture
def okta() -> Okta:
    return Okta()


@pytest.fixture
def tools(registry: Registry, okta: Okta) -> Tools:
    return build(registry, okta)


def by_name(listed: list[Any]) -> dict[str, Any]:
    return {t.name: t for t in listed}


def enum_of(tool: Any) -> list[str]:
    return tool.input_schema["properties"]["command"]["enum"]


def failed(out: Any, code: Code, message: str | None = None) -> Failure:
    assert isinstance(out, Failure), out
    assert out.code is code, out
    if message is not None:
        assert out.message == message
    return out


# --- 1. per-principal lists ---------------------------------------------------------------


def test_different_roles_get_different_tools(tools: Tools) -> None:
    reader = by_name(tools.list_tools(who(READERS)))
    zoner = by_name(tools.list_tools(who(ZONERS)))
    assert list(reader) == ["okta_groups", "okta_network_zones", "okta_help", "okta_status"]
    assert list(zoner) == ["okta_network_zones", "okta_help", "okta_status"]
    assert enum_of(reader["okta_groups"]) == ["list", "get", "get-members"]
    analyst = by_name(tools.list_tools(who(ANALYSTS)))
    assert list(analyst) == ["okta_groups", "okta_help", "okta_status"]
    assert len(enum_of(analyst["okta_groups"])) == 11
    assert enum_of(analyst["okta_groups"])[:3] == ["list", "get", "get-members"]


def test_synopsis_lines_match_enum(tools: Tools, registry: Registry) -> None:
    for principal in (who(READERS), who(ANALYSTS)):
        tool = by_name(tools.list_tools(principal))["okta_groups"]
        enum = enum_of(tool)
        lines = tool.description.splitlines()
        listed = lines[lines.index("Commands:") + 1 : -2]
        listed = [ln for ln in listed if ln.startswith("  ")]
        assert len(listed) == len(enum)
        for line, name in zip(listed, enum, strict=True):
            c = registry.domains["groups"].commands[name]
            assert line.strip().startswith(c.synopsis.strip())
            assert line.rstrip().endswith(c.entry.summary)
        # registry order
        order = list(registry.domains["groups"].commands)
        assert enum == [n for n in order if n in enum]


def test_partial_role_hides_other_commands(tools: Tools, registry: Registry) -> None:
    tool = by_name(tools.list_tools(who(READERS)))["okta_groups"]
    for hidden in ("get-apps", "list-roles", "get-rule"):
        assert hidden not in enum_of(tool)
        assert registry.domains["groups"].commands[hidden].synopsis not in tool.description
    assert 'okta_help(tool="okta_groups", command="list")' in tool.description
    assert tool.description.startswith(registry.domains["groups"].description)


# --- 2. annotations and schemas -----------------------------------------------------------


def test_annotations_and_schemas(tools: Tools) -> None:
    for principal in (who(READERS), who(ANALYSTS), who(ZONERS), who(NOBODY)):
        for tool in tools.list_tools(principal):
            a = tool.annotations
            assert a is not None
            assert a.read_only_hint is True
            assert a.open_world_hint is True
            assert a.destructive_hint is False
            assert tool.input_schema["type"] == "object"
            assert tool.input_schema["additionalProperties"] is False
            Draft202012Validator.check_schema(tool.input_schema)
            if tool.name.startswith("okta_") and "cursor" in tool.input_schema["properties"]:
                # 2.9 carry-over; the executor enforces the same bound.
                assert tool.input_schema["properties"]["cursor"]["maxLength"] == CURSOR_MAX


# --- 3. unavailable -----------------------------------------------------------------------


def test_unavailable_left_out_but_help_and_status_explain(registry: Registry, okta: Okta) -> None:
    t = build(registry, okta, scopes=frozenset({"okta.groups.read", "okta.networkZones.read"}))
    p = who(ANALYSTS)
    tool = by_name(t.list_tools(p))["okta_groups"]
    assert not {"list-roles", "get-role"} & set(enum_of(tool))
    assert "list-roles" not in tool.description
    assert "list" in enum_of(tool)

    out = t.help(p, "okta_groups", "list-roles")
    assert isinstance(out, Text)
    assert out.text.startswith(help_text(registry.domains["groups"].commands["list-roles"]))
    assert out.text.splitlines()[-1] == f"Unavailable: {UNAVAILABLE}."
    ok = t.help(p, "okta_groups", "list")
    assert isinstance(ok, Text)
    assert "Unavailable:" not in ok.text

    status = t.status(p)
    unavailable = json.loads(status.text)["tools"]["okta_groups"]["unavailable"]
    assert set(unavailable) == {
        "list-roles",
        "get-role",
        "list-role-app-targets",
        "list-role-group-targets",
    }
    assert unavailable["list-roles"] == "the service app needs okta.roles.read"
    assert "list-roles" not in json.loads(status.text)["tools"]["okta_groups"]["commands"]


@pytest.mark.anyio
async def test_domain_with_only_unavailable_commands_has_no_tool(
    registry: Registry, okta: Okta
) -> None:
    t = build(registry, okta, scopes=frozenset({"okta.groups.read", "okta.roles.read"}))
    p = who(ZONERS)
    assert [x.name for x in t.list_tools(p)] == ["okta_help", "okta_status"]
    helped = by_name(t.list_tools(p))["okta_help"]
    assert helped.input_schema["properties"]["tool"]["enum"] == ["okta_network_zones"]
    out = t.help(p, "okta_network_zones", "get")
    assert isinstance(out, Text) and "Unavailable:" in out.text
    status = json.loads(t.status(p).text)
    assert status["tools"]["okta_network_zones"]["commands"] == []
    assert "okta.networkZones.read" in status["tools"]["okta_network_zones"]["unavailable"]["get"]
    # a stale client still gets the executor's unavailable answer, with no request sent
    call = {"command": "get", "args": {"zone": ZONE}}
    failed(await t.call(p, "okta_network_zones", call), Code.UNAVAILABLE, UNAVAILABLE)
    assert okta.requests == []


# --- 4. no roles --------------------------------------------------------------------------


def test_no_roles(tools: Tools) -> None:
    p = who(NOBODY)
    assert [t.name for t in tools.list_tools(p)] == ["okta_status"]
    status = tools.status(p)
    assert json.loads(status.text) == {
        "user": "caller@example.com",
        "roles": [],
        "tools": {},
        "note": NO_ROLES,
    }


# --- 5. okta_help -------------------------------------------------------------------------


def test_help_refusals_identical(tools: Tools) -> None:
    p = who(READERS)
    forbidden = tools.help(p, "okta_groups", "get-apps")
    unknown_cmd = tools.help(p, "okta_groups", "nonexistent")
    unknown_tool = tools.help(p, "okta_nonexistent", "list")
    unpermitted_tool = tools.help(who(ZONERS), "okta_groups", "list")
    odd = [tools.help(p, 5, "list"), tools.help(p, "okta_groups", 5), tools.help(p, None, None)]
    expected = Failure(Code.FORBIDDEN_BY_POLICY, FORBIDDEN)
    for r in [forbidden, unknown_cmd, unknown_tool, unpermitted_tool, *odd]:
        assert r == expected
    assert FORBIDDEN == "the command or an argument is not permitted by policy"


def test_help_text_and_search_line(tools: Tools, registry: Registry) -> None:
    p = who(READERS)
    groups = registry.domains["groups"]
    for name in ("list", "get-members"):
        out = tools.help(p, "okta_groups", name)
        assert isinstance(out, Text)
        assert out.text.startswith(help_text(groups.commands[name]))
        assert out.text.splitlines()[-1] == "Search: expressions may name only: profile.name, type."
        assert "expressions may name only: profile.name, type" in out.text
    out = tools.help(p, "okta_groups", "get")
    assert isinstance(out, Text)
    assert out.text == help_text(groups.commands["get"])
    assert "Search:" not in out.text
    wide = tools.help(who(ANALYSTS), "okta_groups", "list")
    assert isinstance(wide, Text) and "any attribute" in wide.text


@pytest.mark.anyio
async def test_help_call_argument_shapes(tools: Tools) -> None:
    p = who(READERS)
    ok = await tools.call(p, "okta_help", {"tool": "okta_groups", "command": "list"})
    assert isinstance(ok, Text)
    for bad in ({"tool": "okta_groups"}, {"command": "list"}, {}, [], "x", 5):
        failed(await tools.call(p, "okta_help", bad), Code.INVALID_ARGUMENTS)
    extra = await tools.call(
        p, "okta_help", {"tool": "okta_groups", "command": "list", "zzsecretkey": 1}
    )
    failed(extra, Code.INVALID_ARGUMENTS)
    assert "zzsecretkey" not in extra.message  # pyright: ignore[reportAttributeAccessIssue]
    failed(await tools.call(p, "okta_help", None), Code.INVALID_ARGUMENTS)
    failed(
        await tools.call(p, "okta_help", {"tool": "okta_groups", "command": "get-apps"}),
        Code.FORBIDDEN_BY_POLICY,
        FORBIDDEN,
    )


# --- 6. okta_status -----------------------------------------------------------------------


def test_status_reveals_only_caller(tools: Tools) -> None:
    text = tools.status(who(READERS)).text
    data = json.loads(text)
    assert data["roles"] == ["reader"]
    assert data["tools"] == {
        "okta_groups": {"commands": ["list", "get", "get-members"]},
        "okta_network_zones": {"commands": ["list", "get"]},
    }
    assert "note" not in data
    for leak in ("analyst", "zoner", ANALYSTS, ZONERS, NOBODY, "get-apps", "list-roles"):
        assert leak not in text


def test_status_same_roles_same_output(tools: Tools) -> None:
    a = Principal("00u1caller0000000000", "a@example.com", frozenset({READERS}))
    b = Principal("00u1other00000000000", "b@example.com", frozenset({READERS, NOBODY}))
    da, db = json.loads(tools.status(a).text), json.loads(tools.status(b).text)
    assert da.pop("user") == "a@example.com"
    assert db.pop("user") == "b@example.com"
    assert da == db


@pytest.mark.anyio
async def test_status_arguments(tools: Tools) -> None:
    p = who(READERS)
    failed(await tools.call(p, "okta_status", {"x": 1}), Code.INVALID_ARGUMENTS)
    assert isinstance(await tools.call(p, "okta_status", None), Success)
    assert isinstance(await tools.call(p, "okta_status", {}), Success)
    assert isinstance(await tools.call(who(NOBODY), "okta_status", {}), Success)


# --- 7. dispatch --------------------------------------------------------------------------


@pytest.mark.anyio
async def test_call_reaches_executor(tools: Tools, okta: Okta) -> None:
    out = await tools.call(
        who(READERS), "okta_network_zones", {"command": "get", "args": {"zone": ZONE}}
    )
    assert isinstance(out, Success)
    assert ZONE in out.text
    [req] = okta.requests
    assert req.url.path.endswith(f"/zones/{ZONE}")

    out = await tools.call(who(READERS), "okta_groups", {"command": "list", "limit": 5})
    assert isinstance(out, Success)
    assert json.loads(out.text)["count"] == 1


@pytest.mark.anyio
async def test_call_passes_fields_through(tools: Tools, okta: Okta) -> None:
    p = who(READERS)
    failed(
        await tools.call(p, "okta_groups", {"command": "list", "limit": 5000}),
        Code.INVALID_ARGUMENTS,
    )
    failed(
        await tools.call(p, "okta_groups", {"command": "list", "args": "x"}),
        Code.INVALID_ARGUMENTS,
    )
    failed(
        await tools.call(p, "okta_groups", {"command": "list", "select": 5}),
        Code.INVALID_ARGUMENTS,
    )
    failed(
        await tools.call(p, "okta_groups", {"command": "list", "cursor": "garbage"}),
        Code.INVALID_ARGUMENTS,
    )
    out = await tools.call(p, "okta_groups", {"command": "list", "select": "id", "links": True})
    assert isinstance(out, Success)
    assert json.loads(out.text)["cols"] == ["id"]
    assert len(okta.requests) == 1


@pytest.mark.anyio
async def test_call_refusals_send_nothing(tools: Tools, okta: Okta) -> None:
    p = who(ZONERS)
    expected = Failure(Code.FORBIDDEN_BY_POLICY, FORBIDDEN)
    unknown = await tools.call(p, "okta_nope", {"command": "list"})
    nonstring = await tools.call(p, 7, {"command": "list"})
    no_command_in_tool = await tools.call(p, "okta_groups", {"command": "list"})
    garbage_args = await tools.call(p, "okta_groups", ["junk"])
    assert unknown == nonstring == no_command_in_tool == garbage_args == expected
    # forbidden command in a tool the caller has
    forbidden = await tools.call(who(READERS), "okta_groups", {"command": "get-apps", "args": {}})
    failed(forbidden, Code.FORBIDDEN_BY_POLICY, FORBIDDEN)
    nonexistent = await tools.call(who(READERS), "okta_groups", {"command": "zzz"})
    assert nonexistent == forbidden
    assert okta.requests == []


@pytest.mark.anyio
async def test_call_shape_errors_send_nothing(tools: Tools, okta: Okta) -> None:
    p = who(READERS)
    for bad in ({}, {"args": {}}, {"command": "list", "zzsecret": 1}, [], "x", 3):
        out = failed(await tools.call(p, "okta_groups", bad), Code.INVALID_ARGUMENTS)
        assert "zzsecret" not in out.message
    failed(await tools.call(p, "okta_groups", None), Code.INVALID_ARGUMENTS)
    assert okta.requests == []


# --- 8. reserved names --------------------------------------------------------------------


@pytest.mark.parametrize("name", ["help", "status"])
def test_reserved_domain_names_rejected(registry: Registry, okta: Okta, name: str) -> None:
    extra = Domain(name, "x", registry.domains["network-zones"].commands)
    reg = Registry(MappingProxyType({**registry.domains, name: extra}))
    with pytest.raises(ValueError, match="shadow"):
        build(reg, okta)
    assert dataclasses.is_dataclass(extra)


# --- 9. guides ----------------------------------------------------------------------------


def test_guides_line_only_for_listed_domains(registry: Registry, okta: Okta) -> None:
    t = build(registry, okta, guides=frozenset({"groups"}))
    listed = by_name(t.list_tools(who(READERS)))
    assert "okta://guide/groups" in listed["okta_groups"].description
    assert "okta://guide/" not in listed["okta_network_zones"].description
    plain = by_name(build(registry, okta).list_tools(who(READERS)))
    assert "okta://guide/" not in plain["okta_groups"].description
