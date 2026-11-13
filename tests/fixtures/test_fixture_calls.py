"""Every shipped command runs through the real executor against its committed fixture."""

import json
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

import httpx2
import pytest
from _samples import SAMPLES

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.cursor import Cursors
from okta_mcp.exec.executor import Call, Executor, Failure, Success
from okta_mcp.exec.resolve import UserResolver
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.policy.engine import Engine
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Command, load_registry
from okta_mcp.registry.spec import load_spec

FIXTURES = Path(__file__).parent
ORG = "https://example.okta.com"
GROUP = "00g1emaKYZTWRYYRRTSK"
USER_ID = "00u1emaKYZTWRYYRRTSK"
LOGIN = "alice@example.com"

SPEC = load_spec()
REGISTRY = load_registry(SPEC)
COMMANDS = [c for d in REGISTRY.domains.values() for c in d.commands.values()]
SCOPES = frozenset(s for c in COMMANDS for ss in c.scope_sets for s in ss)


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass

    def ready(self) -> bool:
        return True


def _value(command: Command, name: str) -> Any:
    arg = command.entry.args[name]
    prop = command.schema["properties"][name]
    if "enum" in prop:
        return prop["enum"][0]
    if arg.resolve == "user_id":
        return USER_ID
    if arg.pattern is not None:
        return SAMPLES[arg.pattern]
    if prop.get("type") == "integer":
        return 1
    if prop.get("type") == "boolean":
        return True
    return LOGIN


def _args(command: Command) -> dict[str, Any]:
    required = set(command.schema.get("required", []))
    return {
        name: _value(command, name)
        for name, arg in command.entry.args.items()
        if arg.path_param is not None or name in required
    }


def _fixture(command: Command) -> Any:
    path = FIXTURES / command.domain / f"{command.name}.json"
    return json.loads(path.read_text())["body"]


def _single_page(body: Any) -> Any:
    """Without a body `next` link. A fixture's link names the fixture's own IDs, which are not
    the args this test sends, and the paginator refuses a link off the request's path."""
    if isinstance(body, dict):
        body = dict(cast(dict[str, Any], body))
        links = body.get("_links")
        if isinstance(links, dict):
            body["_links"] = {k: v for k, v in cast(dict[str, Any], links).items() if k != "next"}
    return body


def _template(command: Command) -> re.Pattern[str]:
    parts = re.split(r"\{[^}]+\}", command.operation.path)
    return re.compile("[^/]+".join(re.escape(p) for p in parts) + "$")


class Okta:
    def __init__(self, routes: list[tuple[re.Pattern[str], Any]]) -> None:
        self.routes = routes
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = unquote(request.url.path)
        for pattern, body in self.routes:
            if request.method == "GET" and pattern.fullmatch(path):
                return httpx2.Response(200, json=body)
        return httpx2.Response(404, json={"errorSummary": "Not found"})


def _executor(okta: Okta) -> tuple[Executor, Principal]:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
        on_request=None,
    )
    group = "00g1testgroup0000000"
    policy = build_policy(
        {
            "version": 1,
            "roles": {
                "all": {
                    "groups": [group],
                    "allow": {"*": ["*"]},
                    "include_sensitive": ["*"],
                    "search_attributes": ["*"],
                }
            },
        },
        REGISTRY,
    )
    executor = Executor(
        registry=REGISTRY,
        engine=Engine(policy, REGISTRY, SCOPES),
        client=client,
        cursors=Cursors(bytes(range(32))),
        resolver=UserResolver(client, ORG, SPEC.operations["getUser"]),
        org_url=ORG,
        default_limit=50,
        max_items=1000,
        max_bytes=10_000_000,
        call_timeout=30,
    )
    principal = Principal(
        uid="00u1caller0000000000", sub="c@example.com", groups=frozenset({group})
    )
    return executor, principal


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: f"{c.domain}-{c.name}")
@pytest.mark.anyio
async def test_command_runs_against_its_fixture(command: Command) -> None:
    body = _fixture(command)
    okta = Okta([(_template(command), _single_page(body))])
    executor, principal = _executor(okta)
    out = await executor.execute(Call(principal, command.domain, command.name, args=_args(command)))
    assert not isinstance(out, Failure), out
    assert isinstance(out, Success)
    envelope = json.loads(out.text)
    assert envelope
    [request] = okta.requests
    assert request.method == "GET"
    assert _template(command).fullmatch(unquote(request.url.path))
    if command.is_list:
        entry = command.entry
        items = cast(dict[str, Any], body)[entry.items_key] if entry.items_key is not None else body
        assert envelope["count"] == len(items)
    else:
        assert "item" in envelope


@pytest.mark.anyio
async def test_login_is_resolved_before_the_command_request() -> None:
    command = REGISTRY.domains["users"].commands["get-groups"]
    user = {"id": USER_ID, "profile": {"login": LOGIN}}
    okta = Okta(
        [(re.compile(r"/api/v1/users/[^/]+"), user), (_template(command), _fixture(command))]
    )
    executor, principal = _executor(okta)
    out = await executor.execute(Call(principal, "users", "get-groups", args={"user": LOGIN}))
    assert isinstance(out, Success), out
    assert [unquote(r.url.path) for r in okta.requests] == [
        f"/api/v1/users/{LOGIN}",
        f"/api/v1/users/{USER_ID}/groups",
    ]


RS_KEYS = REGISTRY.domains["authorization-servers"].commands["list-resource-server-keys"]


async def _run_rs_keys(body: Any) -> Success | Failure:
    okta = Okta([(_template(RS_KEYS), body)])
    executor, principal = _executor(okta)
    call = Call(principal, RS_KEYS.domain, RS_KEYS.name, args=_args(RS_KEYS))
    return await executor.execute(call)


@pytest.mark.anyio
async def test_wrapped_override_reads_items_under_the_key() -> None:
    # V8: Okta wraps the list the spec declares bare.
    out = await _run_rs_keys({"keys": [{"id": "apk1", "kid": "k1", "status": "ACTIVE"}]})
    assert isinstance(out, Success), out
    envelope = json.loads(out.text)
    assert envelope["count"] == 1
    out = await _run_rs_keys({"keys": None})
    assert isinstance(out, Success), out
    assert json.loads(out.text)["count"] == 0


@pytest.mark.anyio
@pytest.mark.parametrize("body", [[{"id": "apk1", "kid": "k1"}], {}, {"jwks": {"keys": []}}])
async def test_wrapped_override_refuses_other_shapes(body: Any) -> None:
    # The spec's bare array, or another wrapper, is not the recorded shape: fail, don't guess.
    out = await _run_rs_keys(body)
    assert isinstance(out, Failure) and "not the expected list" in out.message
