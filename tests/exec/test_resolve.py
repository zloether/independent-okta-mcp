from typing import Any
from urllib.parse import unquote

import httpx2
import pytest
from test_params import PAYLOADS

from okta_mcp.exec.resolve import USER_ID, NotFound, UserResolver
from okta_mcp.okta.client import OktaClient, UpstreamError, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.registry.loader import Command, build_registry
from okta_mcp.registry.schema import InvalidArguments
from okta_mcp.registry.spec import SpecIndex, load_spec

ORG = "https://example.okta.com"
ALICE = "00u1alice00000000000"
LOGIN = "Alice@Example.com"


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass

    def ready(self) -> bool:
        return True


class Okta:
    def __init__(self, response: httpx2.Response | None = None) -> None:
        self.response = response
        self.paths: list[str] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.raw_path.decode())
        if self.response is not None:
            return self.response
        key = unquote(request.url.path.rsplit("/", 1)[1]).lower()
        if key in (LOGIN.lower(), "alice"):  # Okta answers a login shortname too
            return httpx2.Response(200, json={"id": ALICE, "profile": {"login": LOGIN}})
        return httpx2.Response(404, json={"errorSummary": "Not found"})


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def get_groups(spec: SpecIndex) -> Command:
    registry = build_registry(
        {
            "users.yaml": {
                "domain": "users",
                "description": "Users.",
                "commands": {
                    "get-groups": {
                        "operation": "listUserGroups",
                        "summary": "Groups",
                        "args": {"user": {"path_param": "id", "resolve": "user_id"}},
                        "paginate": "link",
                        "page_size": 200,
                        "view": ["id"],
                        "data_classes": ["pii"],
                    }
                },
            }
        },
        spec,
    )
    return registry.domains["users"].commands["get-groups"]


def resolver(spec: SpecIndex, okta: Okta) -> UserResolver:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=4,
        rate_limit_max_wait=1,
    )
    return UserResolver(client, ORG, spec.operations["getUser"])


@pytest.mark.anyio
async def test_user_id_is_used_as_is(spec: SpecIndex) -> None:
    okta = Okta()
    assert await resolver(spec, okta).user_id("user", ALICE, {}) == ALICE
    assert okta.paths == []


@pytest.mark.anyio
@pytest.mark.parametrize("login", [LOGIN, LOGIN.lower(), LOGIN.upper()])
async def test_exact_login_ignoring_case(spec: SpecIndex, login: str) -> None:
    okta = Okta()
    assert await resolver(spec, okta).user_id("user", login, {}) == ALICE
    assert okta.paths == ["/api/v1/users/" + login.replace("@", "%40")]


@pytest.mark.anyio
async def test_lookup_value_is_encoded_with_no_safe_characters(spec: SpecIndex) -> None:
    okta = Okta(httpx2.Response(404))
    with pytest.raises(NotFound):
        await resolver(spec, okta).user_id("user", "a+b:c=e@example.com", {})
    assert okta.paths == ["/api/v1/users/a%2Bb%3Ac%3De%40example.com"]


@pytest.mark.anyio
async def test_shortname_is_not_found(spec: SpecIndex) -> None:
    okta = Okta()
    with pytest.raises(NotFound, match="no user has that ID or exact login"):
        await resolver(spec, okta).user_id("user", "alice", {})
    assert okta.paths == ["/api/v1/users/alice"]


@pytest.mark.anyio
async def test_404_is_not_found_and_hides_the_value(spec: SpecIndex) -> None:
    with pytest.raises(NotFound) as e:
        await resolver(spec, Okta()).user_id("user", "zed@example.com", {})
    assert "zed" not in str(e.value)


@pytest.mark.anyio
@pytest.mark.parametrize("status", [400, 401, 403, 500])
async def test_other_errors_pass_through(spec: SpecIndex, status: int) -> None:
    with pytest.raises(UpstreamError):
        await resolver(spec, Okta(httpx2.Response(status))).user_id("user", "a@example.com", {})


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "x",
        {},
        {"id": ALICE},
        {"id": ALICE, "profile": {"login": "other@example.com"}},
        {"id": ALICE, "profile": {"login": None}},
        {"id": ALICE, "profile": "a@example.com"},
        {"id": "00u1", "profile": {"login": "a@example.com"}},
        {"id": ALICE + "\n", "profile": {"login": "a@example.com"}},
        {"id": "00g1alice00000000000", "profile": {"login": "a@example.com"}},
        {"id": 5, "profile": {"login": "a@example.com"}},
    ],
)
async def test_anything_but_that_user_is_not_found(spec: SpecIndex, body: Any) -> None:
    response = httpx2.Response(200, json=body) if body is not None else httpx2.Response(200)
    with pytest.raises(NotFound):
        await resolver(spec, Okta(response)).user_id("user", "a@example.com", {})


@pytest.mark.anyio
@pytest.mark.parametrize(
    "value",
    ["me", "ME", "mE", "\N{FULLWIDTH LATIN SMALL LETTER M}\N{FULLWIDTH LATIN SMALL LETTER E}"],
)
async def test_me_is_refused_before_any_request(spec: SpecIndex, value: str) -> None:
    okta = Okta()
    with pytest.raises(InvalidArguments, match="'user'"):
        await resolver(spec, okta).user_id("user", value, {})
    assert okta.paths == []


@pytest.mark.anyio
@pytest.mark.parametrize("value", [*PAYLOADS, ALICE + "\n", ALICE + " "])
async def test_path_rule_applies_to_the_lookup(spec: SpecIndex, value: object) -> None:
    okta = Okta()
    with pytest.raises(InvalidArguments, match="'user'"):
        await resolver(spec, okta).user_id("user", value, {})
    assert okta.paths == []


@pytest.mark.anyio
async def test_cached_per_call(spec: SpecIndex) -> None:
    okta = Okta()
    r = resolver(spec, okta)
    cache: dict[str, str] = {}
    assert await r.user_id("a", LOGIN, cache) == await r.user_id("b", LOGIN, cache) == ALICE
    assert len(okta.paths) == 1
    await r.user_id("a", LOGIN, {})  # a new call, a new cache
    assert len(okta.paths) == 2


@pytest.mark.anyio
async def test_resolve_replaces_only_resolved_args(spec: SpecIndex, get_groups: Command) -> None:
    okta = Okta()
    out = await resolver(spec, okta).resolve(get_groups, {"user": LOGIN})
    assert out == {"user": ALICE}
    assert await resolver(spec, okta).resolve(get_groups, {}) == {}


def test_needs_get_user(spec: SpecIndex) -> None:
    client: Any = object()
    with pytest.raises(ValueError, match="getUser"):
        UserResolver(client, ORG, spec.operations["getGroup"])


def test_user_id_pattern() -> None:
    assert USER_ID.fullmatch(ALICE)
    assert not USER_ID.fullmatch(ALICE + "\n")
    assert not USER_ID.fullmatch("00u1alice0000000000")


@pytest.mark.anyio
async def test_me_message_is_the_path_rules(spec: SpecIndex) -> None:
    # C7: one check, one message, from the path rule; the resolver has no second copy.
    with pytest.raises(InvalidArguments) as e:
        await resolver(spec, Okta()).user_id("user", "me", {})
    assert str(e.value) == "arg 'user' is the name of another endpoint, not an ID"
