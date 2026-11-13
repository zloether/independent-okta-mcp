from typing import Any

import httpx2
import pytest
from _samples import SAMPLES

from okta_mcp.exec.params import build_request, build_url, check_args, path_segment
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.registry.loader import Command, build_registry, load_registry
from okta_mcp.registry.schema import InvalidArguments
from okta_mcp.registry.spec import SpecIndex, load_spec

ORG = "https://example.okta.com"
# Design §6.4 payload set, plus a valid ID with a trailing newline (`00g…` matches every
# `{17}` ID pattern's character class, so only the newline is wrong).
PAYLOADS: list[object] = [
    "..",
    ".",
    "../x",
    "a/b",
    "a/../b",
    "a%2F..%2Fb",
    "%2e%2e",
    "a\\..\\b",
    "a?b=c",
    "a#b",
    "a b",
    "a\x00b",
    "A" * 10_000,
    "",
    "a\tb",
    "a\N{LINE SEPARATOR}b",
    "a\N{ZERO WIDTH SPACE}b",
    "00g1emaKYZTWRYYRRTSK\n",
    # Lookalikes whose NFKC form is `..`, `/` or `\`.
    "\N{FULLWIDTH FULL STOP}\N{FULLWIDTH FULL STOP}",
    "\N{ONE DOT LEADER}\N{ONE DOT LEADER}",
    "\N{TWO DOT LEADER}",
    "a\N{FULLWIDTH SOLIDUS}b",
    "a\N{FULLWIDTH REVERSE SOLIDUS}b",
    5,
    None,
    ["a"],
]


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


def _unpatterned(spec: SpecIndex) -> dict[str, Command]:
    """Commands whose path params have no pattern, so only the character rule stands between a
    payload and the URL."""
    registry = build_registry(
        {
            "users.yaml": {
                "domain": "users",
                "description": "Users.",
                "commands": {
                    "get": {
                        "operation": "getUser",
                        "summary": "Get a user",
                        "args": {"user": {"path_param": "id"}},
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
                        "data_classes": ["mfa-state", "pii"],
                    },
                },
            },
            "brands.yaml": {
                "domain": "brands",
                "description": "Brands.",
                "commands": {
                    "get": {
                        "operation": "getBrand",
                        "summary": "Get a brand",
                        "args": {
                            "brand": {"path_param": "brandId"},
                            "expand": {"query": "expand", "allowed_values": ["themes", "domains"]},
                        },
                        "data_classes": ["org-config"],
                    }
                },
            },
            "authorization-servers.yaml": {
                "domain": "authorization-servers",
                "description": "Authorization servers.",
                "commands": {
                    "list-associated": {
                        "operation": "listAssociatedServersByTrustedType",
                        "summary": "Associated servers",
                        "args": {
                            "server": {"path_param": "authServerId"},
                            "trusted": {"query": "trusted"},
                            "q": {"query": "q", "arg_rule": {"forbidden": True}},
                        },
                        "paginate": "link",
                        "page_size": 200,
                        "view": ["id", "name"],
                        "data_classes": ["org-config"],
                    }
                },
            },
        },
        spec,
    )
    return {f"{d.name} {c.name}": c for d in registry.domains.values() for c in d.commands.values()}


def _commands(spec: SpecIndex) -> list[Command]:
    registry = load_registry(spec)
    packaged = [c for d in registry.domains.values() for c in d.commands.values()]
    return packaged + list(_unpatterned(spec).values())


def _path_args(cmd: Command) -> dict[str, Any]:
    """A valid value per path arg: by pattern, or a spec enum's first value."""
    props = cmd.schema["properties"]
    return {
        n: props[n]["enum"][0] if "enum" in props[n] else SAMPLES[a.pattern]
        for n, a in cmd.entry.args.items()
        if a.path_param is not None
    }


def _required_query(cmd: Command) -> dict[str, Any]:
    """A valid value per required query arg (`policies list` `type`): a spec enum's first
    value, else a pattern sample, else a plain word."""
    props = cmd.schema["properties"]
    return {
        n: props[n]["enum"][0] if "enum" in props[n] else SAMPLES.get(a.pattern, "sample")
        for n, a in cmd.entry.args.items()
        if a.query is not None and n in cmd.schema.get("required", ())
    }


def _cases() -> list[tuple[Command, str, object]]:
    spec = load_spec()
    return [
        (cmd, name, payload)
        for cmd in _commands(spec)
        for name in _path_args(cmd)
        for payload in PAYLOADS
    ]


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass


class Okta:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return httpx2.Response(200, json={})


async def _call(okta: Okta, cmd: Command, args: dict[str, Any]) -> None:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(okta)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    url, params = build_request(cmd, args, ORG)
    await client.get(url, params)


def _id(case: tuple[Command, str, object]) -> str:
    cmd, name, payload = case
    return f"{cmd.domain}-{cmd.name}-{name}-{repr(payload)[:20]}"


@pytest.mark.anyio
@pytest.mark.parametrize("case", _cases(), ids=_id)
async def test_path_payload_is_rejected_with_no_request(case: tuple[Command, str, object]) -> None:
    cmd, name, payload = case
    okta = Okta()
    with pytest.raises(InvalidArguments, match=f"arg '{name}'"):
        await _call(okta, cmd, {**_required_query(cmd), **_path_args(cmd), name: payload})
    assert okta.requests == []


@pytest.mark.anyio
async def test_every_command_builds_its_template_path(spec: SpecIndex) -> None:
    for cmd in _commands(spec):
        okta = Okta()
        args = _path_args(cmd)
        await _call(okta, cmd, {**_required_query(cmd), **args})
        expected = cmd.operation.path
        for n, v in args.items():
            expected = expected.replace(
                f"{{{cmd.entry.args[n].param}}}", path_segment(n, v, frozenset())
            )
        (request,) = okta.requests
        url = request.url
        origin = (url.scheme, url.host, url.port, url.userinfo)
        assert origin == ("https", "example.okta.com", None, b"")
        assert url.raw_path.decode().partition("?")[0] == expected, cmd.name


def test_path_values_are_encoded_with_no_safe_characters(spec: SpecIndex) -> None:
    get = _unpatterned(spec)["users get"]
    cases = {
        "alice+test@example.com": "alice%2Btest%40example.com",
        "josé@example.com": "jos%C3%A9%40example.com",
        # Lookalikes whose NFKC form passes are kept as sent.
        "\N{FULLWIDTH LATIN SMALL LETTER A}lice": "%EF%BD%81lice",
        "a:b=d&e,f": "a%3Ab%3Dd%26e%2Cf",
        "..a": "..a",
        "x" * 256: "x" * 256,
    }
    for value, segment in cases.items():
        url, params = build_request(get, {"user": value}, ORG)
        assert url == f"{ORG}/api/v1/users/{segment}"
        assert params == {}


def test_query_args_map_to_spec_names_with_page_size(spec: SpecIndex) -> None:
    assoc = _unpatterned(spec)["authorization-servers list-associated"]
    url, params = build_request(assoc, {"server": "aus1", "trusted": True, "q": "a&b=c"}, ORG)
    assert url == f"{ORG}/api/v1/authorizationServers/aus1/associatedServers"
    assert params == {"trusted": "true", "q": "a&b=c", "limit": "200"}
    _, params = build_request(assoc, {"server": "aus1", "trusted": False}, ORG)
    assert params == {"trusted": "false", "limit": "200"}

    groups = load_registry(spec).domains["groups"].commands["list"]
    _, params = build_request(groups, {"sort_by": "profile.name", "sort_order": "asc"}, ORG)
    assert params == {"sortBy": "profile.name", "sortOrder": "asc", "limit": "200"}


@pytest.mark.anyio
async def test_query_values_are_sent_as_params(spec: SpecIndex) -> None:
    assoc = _unpatterned(spec)["authorization-servers list-associated"]
    okta = Okta()
    await _call(okta, assoc, {"server": "aus1", "q": "a&b=c#d"})
    (request,) = okta.requests
    assert request.url.path == "/api/v1/authorizationServers/aus1/associatedServers"
    assert request.url.params == httpx2.QueryParams({"q": "a&b=c#d", "limit": "200"})


@pytest.mark.anyio
async def test_array_query_values_follow_the_spec_explode(spec: SpecIndex) -> None:
    cmds = _unpatterned(spec)
    # getBrand's `expand` is `explode: false`: one comma-joined value.
    okta = Okta()
    await _call(okta, cmds["brands get"], {"brand": "bnd1", "expand": ["themes", "domains"]})
    assert okta.requests[0].url.raw_path == b"/api/v1/brands/bnd1?expand=themes%2Cdomains"
    # discloseIdentifiers takes the OpenAPI default: one key per item.
    okta = Okta()
    args = {"user": "00u1", "disclose_identifiers": ["phone", "phone"]}
    await _call(okta, cmds["users get-enrollments"], args)
    query = okta.requests[0].url.params
    assert query.get_list("discloseIdentifiers") == ["phone", "phone"]


def test_schema_and_path_problems_are_reported_together(spec: SpecIndex) -> None:
    get = _unpatterned(spec)["users get"]
    with pytest.raises(InvalidArguments) as e:
        build_request(get, {"user": "a/b", "nope": 1}, ORG)
    # The unknown-arg message keeps its own `; valid: …` part next to it.
    assert str(e.value) == (
        "arg 'user' can't contain / \\ % ? #, a semicolon, whitespace or control characters; "
        "unknown arg 'nope'; valid: user"
    )
    # A non-string path value is one problem, not two.
    with pytest.raises(InvalidArguments) as e:
        build_request(get, {"user": 5}, ORG)
    assert str(e.value) == "arg 'user' must be a string"


def test_every_path_problem_is_reported_without_values(spec: SpecIndex) -> None:
    get_role = load_registry(spec).domains["groups"].commands["get-role"]
    with pytest.raises(InvalidArguments) as e:
        build_request(get_role, {"group": "secret/1", "role": "secret?2"}, ORG)
    assert "'group'" in str(e.value) and "'role'" in str(e.value)
    assert "secret" not in str(e.value)


def test_path_segment_rejects_independently_of_pattern() -> None:
    for payload in PAYLOADS:
        with pytest.raises(InvalidArguments, match="arg 'user'"):
            path_segment("user", payload, frozenset())
    assert path_segment("user", "00u1abcDEFghiJKLm0h7", frozenset()) == "00u1abcDEFghiJKLm0h7"


def _reserved_cases() -> list[tuple[str, str, str]]:
    return [
        (op.operation_id, param, literal)
        for op in load_spec().operations.values()
        for param, literals in op.reserved.items()
        for literal in sorted(literals)
    ]


@pytest.mark.parametrize("case", _reserved_cases(), ids="-".join)
def test_sibling_endpoint_names_are_rejected_for_every_spec_path_param(
    case: tuple[str, str, str], spec: SpecIndex
) -> None:
    op_id, param, literal = case
    reserved = spec.operations[op_id].reserved[param]
    for value in (literal, literal.upper(), literal.title()):
        with pytest.raises(InvalidArguments, match=f"arg '{param}' is the name of another"):
            path_segment(param, value, reserved)


@pytest.mark.anyio
async def test_path_value_naming_another_endpoint_sends_no_request(spec: SpecIndex) -> None:
    # No `pattern`, so only the reserved-literal rule keeps `export` from reaching
    # `/api/v1/apps/export` (getApplicationsCsvExport) as an app "ID".
    registry = build_registry(
        {
            "apps.yaml": {
                "domain": "apps",
                "description": "Apps.",
                "commands": {
                    "get": {
                        "operation": "getApplication",
                        "summary": "Get an app",
                        "args": {"app": {"path_param": "appId"}},
                        "data_classes": ["org-config"],
                    }
                },
            }
        },
        spec,
    )
    get = registry.domains["apps"].commands["get"]
    okta = Okta()
    for value in ("export", "Export", "search", "types", "\N{FULLWIDTH LATIN SMALL LETTER E}xport"):
        with pytest.raises(InvalidArguments, match="arg 'app'"):
            await _call(okta, get, {"app": value})
    assert okta.requests == []
    await _call(okta, get, {"app": "0oa1emaKYZTWRYYRRTSK"})
    assert [r.url.path for r in okta.requests] == ["/api/v1/apps/0oa1emaKYZTWRYYRRTSK"]


def test_build_url_checks_template_and_origin() -> None:
    template = "/api/v1/groups/{groupId}/roles/{roleAssignmentId}"
    with pytest.raises(RuntimeError):
        build_url(ORG, template, {"groupId": "00g1"})
    with pytest.raises(RuntimeError):
        build_url(ORG, template, {"groupId": "00g1", "roleAssignmentId": "r", "x": "y"})
    # Raw segments that skipped `path_segment` change the parsed path or origin.
    with pytest.raises(RuntimeError):
        build_url(ORG, "/api/v1/groups/{groupId}", {"groupId": "a/../../apps"})
    with pytest.raises(RuntimeError):
        build_url(ORG, "{groupId}", {"groupId": "@evil.example.com/x"})
    assert build_url(ORG, template, {"groupId": "00g1", "roleAssignmentId": "r1"}) == (
        f"{ORG}/api/v1/groups/00g1/roles/r1"
    )


def _user_params() -> list[tuple[str, str]]:
    """Every (operation, path param) of the pinned spec whose param follows a `users` segment."""
    return [
        (op.operation_id, param)
        for op in load_spec().operations.values()
        for param in op.params
        if f"/users/{{{param}}}" in op.path
    ]


@pytest.mark.parametrize("case", _user_params(), ids="-".join)
def test_me_is_refused_after_users_for_every_spec_path_param(
    case: tuple[str, str], spec: SpecIndex
) -> None:
    # `/api/v1/users/me` is the token's own user and no spec path lists it (2026-11-10 review).
    op_id, param = case
    reserved = spec.operations[op_id].reserved.get(param, frozenset())
    assert "me" in reserved
    for value in ("me", "ME", "Me", "\N{FULLWIDTH LATIN SMALL LETTER M}e"):
        with pytest.raises(InvalidArguments, match=f"arg '{param}' is the name of another"):
            path_segment(param, value, reserved)


def test_user_params_are_found(spec: SpecIndex) -> None:
    cases = _user_params()
    assert ("getUser", "id") in cases and ("listFactors", "userId") in cases
    assert len(cases) > 20


def test_me_is_not_reserved_elsewhere(spec: SpecIndex) -> None:
    assert "me" not in spec.operations["getGroup"].reserved.get("groupId", frozenset())
    assert "me" not in spec.operations["getNetworkZone"].reserved.get("zoneId", frozenset())
    # Second param of a users path: not right after `users`.
    assert "me" not in spec.operations["getFactor"].reserved.get("factorId", frozenset())


def test_build_request_refuses_me_on_an_unpatterned_user_path(spec: SpecIndex) -> None:
    get = _unpatterned(spec)["users get"]
    with pytest.raises(InvalidArguments, match="arg 'user' is the name of another endpoint"):
        build_request(get, {"user": "me"}, ORG)
    url, _ = build_request(get, {"user": "mel@example.com"}, ORG)
    assert url == f"{ORG}/api/v1/users/mel%40example.com"


@pytest.mark.parametrize("args", [None, "x", ["group"], 5])
def test_check_args_refuses_non_objects(spec: SpecIndex, args: object) -> None:
    get = load_registry(spec).domains["groups"].commands["get"]
    with pytest.raises(InvalidArguments):
        check_args(get, args)


def test_check_args_reports_schema_and_path_problems(spec: SpecIndex) -> None:
    get = load_registry(spec).domains["groups"].commands["get"]
    with pytest.raises(InvalidArguments) as e:
        check_args(get, {"group": "a/b", "x": 1})
    assert "'group'" in str(e.value) and "'x'" in str(e.value)
    check_args(get, {"group": "00g1emaKYZTWRYYRRTSK"})


def test_me_is_in_the_spec_index_reserved_set(spec: SpecIndex) -> None:
    # C2: `Operation.reserved` is the one source; nothing adds to it later.
    assert "me" in spec.operations["getUser"].reserved["id"]
    assert "me" in spec.operations["listFactors"].reserved["userId"]
    assert "me" not in spec.operations["getFactor"].reserved.get("factorId", frozenset())


def test_path_segment_needs_the_reserved_set() -> None:
    with pytest.raises(TypeError):
        path_segment("user", "me")  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize(
    ("value", "reserved"),
    [
        ("me.json", {"me"}),
        ("ME.", {"me"}),
        ("me.smith@example.com", {"me"}),  # refused too: fail closed, give the ID
        ("rules.json", {"rules"}),
        ("Rules.x.y", {"rules"}),
        ("a;b", set()),
        ("me;x", {"me"}),
        ("\N{FULLWIDTH LATIN SMALL LETTER M}e.json", {"me"}),
    ],
)
def test_reserved_name_with_a_suffix_or_semicolon_is_refused(
    value: str, reserved: set[str]
) -> None:
    with pytest.raises(InvalidArguments, match="arg 'x'"):
        path_segment("x", value, frozenset(reserved))


@pytest.mark.parametrize("value", ["alice.me@example.com", "meg.ryan@example.com", "rulesx.y"])
def test_dotted_values_not_starting_with_a_reserved_name_pass(value: str) -> None:
    path_segment("x", value, frozenset({"me", "rules"}))


def _search_apps(spec: SpecIndex) -> Command:
    registry = build_registry(
        {
            "apps.yaml": {
                "domain": "apps",
                "description": "Apps.",
                "commands": {
                    "search": {
                        "operation": "listApplicationsBySearch",
                        "summary": "Search apps",
                        "args": {
                            "q": {"query": "q", "arg_rule": {"reviewed": "app name"}},
                            "labels": {"query": "labels"},
                        },
                        "paginate": "link",
                        "page_size": 100,
                        "view": ["id", "label"],
                        "data_classes": ["org-config"],
                    }
                },
            }
        },
        spec,
    )
    return registry.domains["apps"].commands["search"]


@pytest.mark.parametrize(
    "args",
    [
        {"q": "\ud800"},
        {"q": "a\udfffb"},
        {"labels": ["\ud800" * 20]},
        {"labels": ["lbco3v6xlwdtEX2il1d6", "lbco3v6xlwdtEX2il1d\udc00"]},
    ],
)
def test_query_values_that_are_not_utf8_are_refused(spec: SpecIndex, args: dict[str, Any]) -> None:
    # A lone surrogate can't be encoded for the URL; refused in validation, naming the arg.
    with pytest.raises(InvalidArguments, match=f"arg '{next(iter(args))}'") as e:
        check_args(_search_apps(spec), args)
    assert "\ud800" not in str(e.value)


@pytest.mark.parametrize("q", ["\x00", "é", "\N{GRINNING FACE}", "a b"])
def test_other_query_strings_are_accepted_as_before(spec: SpecIndex, q: str) -> None:
    check_args(_search_apps(spec), {"q": q})
