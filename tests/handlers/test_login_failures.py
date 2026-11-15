"""`diagnostics login-failures` end to end through the executor against a mocked org (plan 9.1):
policy and scope gates, argument checks, the log query, cause triage, follow-ups only when a
cause calls for them, optional scopes skipped, and no raw event in the result."""

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx2
import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.cursor import Cursors
from okta_mcp.exec.executor import ARGS_ONLY, FORBIDDEN, Call, Code, Executor, Failure, Success
from okta_mcp.exec.resolve import NOT_FOUND, UserResolver
from okta_mcp.handlers import login_failures as lf
from okta_mcp.okta.client import OktaClient, new_http_client
from okta_mcp.okta.token import ServiceToken
from okta_mcp.policy.engine import Engine
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec

ORG = "https://example.okta.com"
UID = "00u1alice00000000000"
OTHER = "00u1admin00000000000"
APP = "0oa1emaKYZTWRYYRRTSK"
HELPDESK = "00g1helpdsk000000000"
WILDCARD_ONLY = "00g1wildcard00000000"
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
ALL_SCOPES = frozenset({"okta.users.read", "okta.logs.read", "okta.apps.read"})
ROLES: dict[str, Any] = {
    "helpdesk": {"groups": [HELPDESK], "allow": {"diagnostics": ["login-failures"]}},
    # A wildcard reaches normal commands only; this one is sensitive.
    "wildcard": {"groups": [WILDCARD_ONLY], "allow": {"diagnostics": ["*"], "groups": ["*"]}},
}


class Tokens:
    async def token(self) -> ServiceToken:
        return ServiceToken("fake-token", "Bearer")

    def invalidate(self, token: ServiceToken) -> None:
        pass

    def ready(self) -> bool:
        return True


def event(
    event_type: str,
    result: str = "FAILURE",
    reason: str = "",
    *,
    at: str = "2026-11-14T10:00:00.000Z",
    actor: str = UID,
    targets: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    e: dict[str, Any] = {
        "uuid": "e-" + at,
        "published": at,
        "eventType": event_type,
        "displayMessage": "raw message",
        "actor": {"id": actor, "type": "User", "alternateId": "alice@example.com"},
        "outcome": {"result": result, "reason": reason},
        "client": {
            "ipAddress": "203.0.113.7",
            "zone": "null",
            "userAgent": {"os": "Mac OS X", "browser": "CHROME"},
            "geographicalContext": {"city": "Springfield", "state": "Oregon", "country": "US"},
        },
        "securityContext": {"isProxy": False, "asNumber": 64500, "asOrg": "example isp"},
        "authenticationContext": {"credentialType": "PASSWORD"},
        "debugContext": {"debugData": {"requestUri": "/idp/idx/identify", "secret": "s3cr3t"}},
        "target": targets or [],
    }
    e.update(extra)
    return e


class Org:
    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []
        self.user: dict[str, Any] = {
            "id": UID,
            "status": "ACTIVE",
            "lastLogin": "2026-11-13T09:00:00.000Z",
            "passwordChanged": "2026-10-01T00:00:00.000Z",
            "profile": {"login": "alice@example.com", "email": "alice@example.com"},
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        }
        self.events: list[dict[str, Any]] = []
        self.assigned: set[str] = set()
        self.enrollments: list[dict[str, Any]] = [
            {"id": "e1", "key": "okta_verify", "type": "app", "status": "ACTIVE", "name": "OV"}
        ]
        self.blocks: list[dict[str, Any]] = []
        # Slice 2: what the policy evaluation reads.
        self.verify_events: list[dict[str, Any]] = []
        self.membership_events: list[dict[str, Any]] = []
        self.policies: dict[str, dict[str, Any]] = {}
        self.rules: dict[str, list[dict[str, Any]]] = {}
        self.zones: list[dict[str, Any]] = []
        self.groups: list[str] = []
        self.authenticators: list[dict[str, Any]] = []
        self.methods: dict[str, list[dict[str, Any]]] = {}
        # Slice 3.
        self.assurance: dict[str, dict[str, Any]] = {}
        self.posture_checks: list[dict[str, Any]] = []
        self.default_posture_checks: list[dict[str, Any]] = []
        self.override: Callable[[httpx2.Request], httpx2.Response | None] | None = None

    @property
    def paths(self) -> list[str]:
        return [unquote(r.url.path) for r in self.requests]

    def log_query(self) -> dict[str, list[str]]:
        (request,) = [r for r in self.requests if r.url.path == "/api/v1/logs"][:1]
        return parse_qs(request.url.query.decode())

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        assert request.method == "GET"
        assert request.url.host == "example.okta.com"
        if self.override is not None and (response := self.override(request)) is not None:
            return response
        parts = [unquote(p) for p in request.url.raw_path.decode().partition("?")[0].split("/")]
        match parts[3:]:
            case ["users", key]:
                if key in (UID, "alice@example.com", "alice"):
                    return httpx2.Response(200, json=self.user)
                return _missing()
            case ["logs"]:
                query = parse_qs(request.url.query.decode())
                filt = query["filter"][0]
                events = (
                    self.verify_events
                    if "user.authentication.verify" in filt
                    else self.membership_events
                    if "group.user_membership" in filt
                    else self.events
                )
                size = int(query["limit"][0])
                start = int(query.get("after", ["0"])[0])
                headers = {}
                if start + size < len(events):
                    nxt = request.url.copy_merge_params({"after": str(start + size)})
                    headers["Link"] = f'<{nxt}>; rel="next"'
                return httpx2.Response(200, json=events[start : start + size], headers=headers)
            case ["policies"]:
                kind = parse_qs(request.url.query.decode())["type"][0]
                return httpx2.Response(
                    200, json=[p for p in self.policies.values() if p.get("type") == kind]
                )
            case ["policies", pid]:
                found = self.policies.get(pid)
                return httpx2.Response(200, json=found) if found else _missing()
            case ["policies", pid, "rules"]:
                return httpx2.Response(200, json=self.rules.get(pid, []))
            case ["zones"]:
                return httpx2.Response(200, json=self.zones)
            case ["users", uid, "groups"]:
                assert uid == UID
                return httpx2.Response(200, json=[{"id": g} for g in self.groups])
            case ["device-assurances", aid]:
                found = self.assurance.get(aid)
                return httpx2.Response(200, json=found) if found else _missing()
            case ["device-posture-checks"]:
                return httpx2.Response(200, json=self.posture_checks)
            case ["device-posture-checks", "default"]:
                return httpx2.Response(200, json=self.default_posture_checks)
            case ["authenticators"]:
                return httpx2.Response(200, json=self.authenticators)
            case ["authenticators", aid, "methods"]:
                return httpx2.Response(200, json=self.methods.get(aid, []))
            case ["apps", app, "users", uid]:
                assert uid == UID
                return (
                    httpx2.Response(200, json={"id": uid}) if app in self.assigned else _missing()
                )
            case ["users", uid, "authenticator-enrollments"]:
                assert uid == UID
                return httpx2.Response(200, json=self.enrollments)
            case ["users", uid, "blocks"]:
                assert uid == UID
                return httpx2.Response(200, json=self.blocks)
            case _:
                return _missing()


def _missing() -> httpx2.Response:
    return httpx2.Response(404, json={"errorCode": "E0000007", "errorSummary": "Not found"})


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def registry(spec: SpecIndex) -> Registry:
    return load_registry(spec)


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lf, "_now", lambda: NOW)


@pytest.fixture
def org() -> Org:
    return Org()


def make(
    registry: Registry, spec: SpecIndex, org: Org, scopes: frozenset[str] = ALL_SCOPES
) -> Executor:
    client = OktaClient(
        new_http_client(httpx2.MockTransport(org)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    policy = build_policy({"version": 1, "roles": copy.deepcopy(ROLES)}, registry)
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
    )


@pytest.fixture
def ex(registry: Registry, spec: SpecIndex, org: Org) -> Executor:
    return make(registry, spec, org)


def helpdesk() -> Principal:
    return Principal(uid="00u1caller0000000000", sub="hd@example.com", groups=frozenset({HELPDESK}))


async def diagnose(ex: Executor, principal: Principal | None = None, **kw: Any) -> Any:
    args = kw.pop("args", {"user": UID})
    out = await ex.execute(
        Call(principal or helpdesk(), "diagnostics", "login-failures", args=args, **kw)
    )
    if isinstance(out, Failure):
        return out
    assert isinstance(out, Success)
    envelope = json.loads(out.text)
    assert envelope["untrusted"] is True
    return envelope["item"]


def failed(out: Any, code: Code) -> Failure:
    assert isinstance(out, Failure), out
    assert out.code is code, out
    return out


def cause(result: dict[str, Any], name: str) -> dict[str, Any]:
    (found,) = [c for c in result["causes"] if c["cause"] == name]
    return found


# --- gates and arguments ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_wildcard_does_not_reach_it(ex: Executor, org: Org) -> None:
    who = Principal(uid="00u1x000000000000000", sub="x", groups=frozenset({WILDCARD_ONLY}))
    assert failed(await diagnose(ex, who), Code.FORBIDDEN_BY_POLICY).message == FORBIDDEN
    assert org.requests == []


@pytest.mark.anyio
async def test_unavailable_without_a_required_scope(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=frozenset({"okta.users.read"}))
    failed(await diagnose(ex), Code.UNAVAILABLE)
    assert org.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kw", [{"select": "id"}, {"limit": 5}, {"links": True}], ids=["select", "limit", "links"]
)
async def test_list_options_are_refused(ex: Executor, org: Org, kw: dict[str, Any]) -> None:
    assert failed(await diagnose(ex, **kw), Code.INVALID_ARGUMENTS).message == ARGS_ONLY
    assert org.requests == []


@pytest.mark.anyio
async def test_a_cursor_is_refused(ex: Executor, org: Org) -> None:
    failed(await diagnose(ex, cursor="abc"), Code.INVALID_ARGUMENTS)
    assert org.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("args", "text"),
    [
        ({}, "missing required arg 'user'"),
        ({"user": UID, "since": "yesterday"}, "must match"),
        ({"user": UID, "since": "2026-13-40T00:00:00Z"}, "not a valid UTC timestamp"),
        ({"user": UID, "since": "2026-01-01T00:00:00Z"}, "more than 90 days"),
        ({"user": UID, "until": "2026-11-15T00:00:00Z"}, "in the future"),
        (
            {"user": UID, "since": "2026-11-14T10:00:00Z", "until": "2026-11-14T09:00:00Z"},
            "must be before",
        ),
        ({"user": UID, "app": APP}, "unknown arg"),
        ({"user": "x" * 300}, "arg 'user' is longer than 256 characters"),
    ],
)
async def test_invalid_arguments(ex: Executor, org: Org, args: dict[str, Any], text: str) -> None:
    assert text in failed(await diagnose(ex, args=args), Code.INVALID_ARGUMENTS).message
    assert not any(p == "/api/v1/logs" for p in org.paths)


@pytest.mark.anyio
async def test_unknown_user(ex: Executor, org: Org) -> None:
    out = failed(await diagnose(ex, args={"user": "bob@example.com"}), Code.NOT_FOUND)
    assert out.message == NOT_FOUND
    assert org.paths == ["/api/v1/users/bob@example.com"]


@pytest.mark.anyio
async def test_a_login_shortname_is_not_the_user(ex: Executor, org: Org) -> None:
    # Okta answers `alice` with the user; the resolver's exact-login rule refuses it.
    failed(await diagnose(ex, args={"user": "alice"}), Code.NOT_FOUND)


@pytest.mark.anyio
async def test_me_is_refused_before_any_request(ex: Executor, org: Org) -> None:
    failed(await diagnose(ex, args={"user": "me"}), Code.INVALID_ARGUMENTS)
    assert org.requests == []


# --- the log query ---------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_log_query(ex: Executor, org: Org) -> None:
    out = await diagnose(ex, args={"user": "alice@example.com"})
    query = org.log_query()
    assert query["filter"] == [
        f'(actor.id eq "{UID}" or target.id eq "{UID}") and (outcome.result eq "FAILURE" '
        'or outcome.result eq "DENY" or eventType sw "user.account.lock" '
        'or eventType sw "user.account.unlock")'
    ]
    assert query["since"] == ["2026-11-13T12:00:00.000Z"]
    assert "until" not in query
    # One more than is read, so a cut shows without a second page.
    assert query["sortOrder"] == ["DESCENDING"] and query["limit"] == ["501"]
    # Nulls and empty lists are pruned from every result (`output.render`).
    assert out["window"] == {
        "since": "2026-11-13T12:00:00.000Z",
        "events_read": 0,
        "events_about_user": 0,
        "truncated": False,
    }
    assert "causes" not in out
    assert out["headline"] == "No failed sign-ins for this user in the window."
    # Nothing failed, so no follow-up: the user and the log only.
    assert org.paths == ["/api/v1/users/alice@example.com", "/api/v1/logs"]


@pytest.mark.anyio
async def test_since_and_until_are_sent(ex: Executor, org: Org) -> None:
    args = {"user": UID, "since": "2026-11-01T00:00:00Z", "until": "2026-11-02T00:00:00.5Z"}
    out = await diagnose(ex, args=args)
    query = org.log_query()
    assert query["since"] == ["2026-11-01T00:00:00.000Z"]
    assert query["until"] == ["2026-11-02T00:00:00.500Z"]
    assert out["window"]["until"] == "2026-11-02T00:00:00.500Z"


@pytest.mark.anyio
async def test_at_most_max_events_are_read(ex: Executor, org: Org) -> None:
    org.events = [
        event("user.session.start", reason="INVALID_CREDENTIALS") for _ in range(lf.MAX_EVENTS + 3)
    ]
    out = await diagnose(ex)
    assert out["window"]["events_read"] == lf.MAX_EVENTS
    assert out["window"]["truncated"] is True
    # The cut is seen on the first page: no second log request (code review, 9.1).
    assert org.paths.count("/api/v1/logs") == 1
    assert cause(out, "invalid_credentials")["count"] == lf.MAX_EVENTS


# --- triage ----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_locked_account(ex: Executor, org: Org) -> None:
    org.user["status"] = "LOCKED_OUT"
    org.blocks = [{"type": "DEVICE_BASED", "appliesTo": "UNKNOWN_DEVICES"}]
    org.events = [
        event(
            "user.account.lock",
            "SUCCESS",
            at="2026-11-14T10:05:00.000Z",
            actor="system",
            targets=[{"id": UID, "type": "User"}],
        ),
        event("user.session.start", reason="INVALID_CREDENTIALS", at="2026-11-14T10:01:00.000Z"),
        event("user.session.start", reason="INVALID_CREDENTIALS", at="2026-11-14T09:00:00.000Z"),
    ]
    out = await diagnose(ex)
    assert out["headline"].startswith("Account is LOCKED_OUT")
    assert [c["cause"] for c in out["causes"]] == ["locked_out", "invalid_credentials"]
    creds = cause(out, "invalid_credentials")
    assert creds["count"] == 2 and creds["followed_by_lock"] == 1
    assert creds["credential_types"] == {"PASSWORD": 2}
    assert creds["ips"] == [
        {
            "ip": "203.0.113.7",
            "count": 2,
            "city": "Springfield",
            "state": "Oregon",
            "country": "US",
            "proxy": False,
            "asn": 64500,
            "as_org": "example isp",
        }
    ]
    # Only what the cause needs: no policy or device fields on a wrong password.
    assert not creds.keys() & {"policies", "devices", "apps", "risk"}
    checks = {c["check"]: c for c in out["checks"]}
    assert checks["user_status"]["pass"] is False
    assert checks["sign_in_blocks"]["pass"] is False
    assert "unknown devices" in checks["sign_in_blocks"]["note"]
    assert "authenticator_enrollment" not in checks  # no MFA cause: not fetched
    assert "/api/v1/users/00u1alice00000000000/authenticator-enrollments" not in org.paths
    # Password causes: the password policy is read; without okta.policies.read it is skipped.
    assert out["password_policy"]["evaluated"] is False
    assert {
        "check": "policy evaluation: PASSWORD policies",
        "reason": "the service app needs okta.policies.read",
    } in out["skipped"]


@pytest.mark.anyio
async def test_unlocked_after_the_last_lock(ex: Executor, org: Org) -> None:
    target = [{"id": UID, "type": "User"}]
    org.events = [
        event(
            "user.account.unlock",
            "SUCCESS",
            at="2026-11-14T11:00:00.000Z",
            actor=OTHER,
            targets=target,
        ),
        event(
            "user.account.lock",
            "SUCCESS",
            at="2026-11-14T10:00:00.000Z",
            actor="system",
            targets=target,
        ),
    ]
    out = await diagnose(ex)
    locked = cause(out, "locked_out")
    assert locked["count"] == 1 and locked["unlocked_after_last_lock"] is True


@pytest.mark.anyio
async def test_a_sign_on_policy_deny(ex: Executor, org: Org) -> None:
    targets = [
        {
            "id": "rul1emaKYZTWRYYRRTSK",
            "type": "Rule",
            "displayName": "Managed devices only",
            "detailEntry": {"policyId": "rst1emaKYZTWRYYRRTSK", "policyName": "Salesforce"},
        },
        {
            "id": "0pr1emaKYZTWRYYRRTSK",
            "type": "Rule",
            "displayName": "Default Rule",
            "detailEntry": {"policyName": "Default Policy"},
        },
        {
            "id": APP,
            "type": "AppInstance",
            "displayName": "Salesforce",
            "detailEntry": {"signOnModeEvaluationResult": "FAILURE"},
        },
        {"id": "guo1emaKYZTWRYYRRTSK", "type": "UDDevice", "displayName": "alice-mbp"},
    ]
    deny = event(
        "policy.evaluate_sign_on",
        "DENY",
        "Sign-on policy evaluation resulted in DENY",
        targets=targets,
        device={
            "os_platform": "MACOS",
            "os_version": "15.1",
            "managed": False,
            "registered": True,
            "device_integrator": '{"OSQUERY":{"genericError(timeout)":1}}',
        },
    )
    deny["securityContext"]["risk"] = {"level": "HIGH", "reasons": "Anomalous Location"}
    deny["debugContext"]["debugData"]["behaviors"] = (
        "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=POSITIVE}"
    )
    org.events = [deny, copy.deepcopy(deny)]
    out = await diagnose(ex)
    denied = cause(out, "sign_on_policy_deny")
    assert denied["count"] == 2
    assert denied["policies"] == [
        {
            "rule_id": "rul1emaKYZTWRYYRRTSK",
            "rule_name": "Managed devices only",
            "policy_id": "rst1emaKYZTWRYYRRTSK",
            "policy_name": "Salesforce",
            "policy_kind": "authentication policy (ACCESS_POLICY)",
            "count": 2,
        },
        {
            "rule_id": "0pr1emaKYZTWRYYRRTSK",
            "rule_name": "Default Rule",
            "policy_name": "Default Policy",
            "policy_kind": "global session or authenticator enrollment policy "
            "(OKTA_SIGN_ON or MFA_ENROLL)",
            "count": 2,
        },
    ]
    assert denied["apps"] == [
        {"id": APP, "name": "Salesforce", "signOnModeEvaluationResult": "FAILURE", "count": 2}
    ]
    assert denied["devices"] == [
        {
            "id": "guo1emaKYZTWRYYRRTSK",
            "name": "alice-mbp",
            "os_platform": "MACOS",
            "os_version": "15.1",
            "managed": False,
            "registered": True,
            "integrator_error": True,
            "count": 2,
        }
    ]
    assert denied["risk"] == {"HIGH": 2}
    assert denied["behaviors"] == {"New Geo-Location": 2, "New IP": 2}
    assert denied["user_agents"] == [{"os": "Mac OS X", "browser": "CHROME", "count": 2}]
    assert "pending" not in out  # slice 2 evaluates the rules (see the policy tests)
    # A policy cause calls for the enrollments (what the rule's authenticators could be).
    checks = {c["check"]: c for c in out["checks"]}
    assert checks["authenticator_enrollment"]["enrolled"] == [
        {"key": "okta_verify", "type": "app", "name": "OV", "status": "ACTIVE"}
    ]
    assert out["headline"].startswith("Most likely: a sign-on or authentication policy denied")


@pytest.mark.anyio
async def test_not_assigned_checks_the_assignment_now(ex: Executor, org: Org) -> None:
    app = {"id": APP, "type": "AppInstance", "displayName": "Salesforce"}
    junk = {"id": "../users", "type": "AppInstance", "displayName": "Bad"}
    org.events = [
        event(
            "app.generic.unauth_app_access_attempt",
            reason="User is not assigned to this app",
            targets=[app, junk],
        ),
    ]
    out = await diagnose(ex)
    checks = [c for c in out["checks"] if c["check"] == "app_assignment"]
    assert checks == [
        {
            "check": "app_assignment",
            "app_id": APP,
            "app_name": "Salesforce",
            "pass": False,
            "actual": "not assigned now, or the app no longer exists",
        }
    ]
    # An app ID that isn't one never reaches a path.
    assert [p for p in org.paths if p.startswith("/api/v1/apps")] == [
        f"/api/v1/apps/{APP}/users/{UID}"
    ]
    org.assigned.add(APP)
    out = await diagnose(ex)
    (check,) = [c for c in out["checks"] if c["check"] == "app_assignment"]
    assert check["pass"] is True


@pytest.mark.anyio
async def test_an_optional_scope_missing_skips_only_that_check(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=frozenset({"okta.users.read", "okta.logs.read"}))
    org.events = [
        event(
            "app.generic.unauth_app_access_attempt",
            reason="not assigned",
            targets=[{"id": APP, "type": "AppInstance"}],
        ),
    ]
    out = await diagnose(ex)
    assert out["skipped"] == [
        {"check": "app_assignment", "reason": "the service app needs okta.apps.read"}
    ]
    assert cause(out, "not_assigned")["apps"] == [{"id": APP, "count": 1}]
    assert not any(p.startswith("/api/v1/apps") for p in org.paths)


@pytest.mark.anyio
async def test_a_failing_follow_up_is_skipped_not_fatal(ex: Executor, org: Org) -> None:
    org.events = [
        event(
            "user.authentication.auth_via_mfa",
            reason="INVALID_CREDENTIALS",
            authenticationContext={"credentialType": "OTP"},
        )
    ]
    org.override = lambda r: (
        httpx2.Response(500, json={}) if r.url.path.endswith("/authenticator-enrollments") else None
    )
    out = await diagnose(ex)
    (skip,) = out["skipped"]
    assert skip["check"] == "authenticator_enrollment"
    assert skip["reason"] == "Okta returned HTTP 500"
    assert cause(out, "mfa_failed")["credential_types"] == {"OTP": 1}


@pytest.mark.anyio
async def test_mfa_failure_names_the_failing_authenticator(ex: Executor, org: Org) -> None:
    org.enrollments = [{"key": "phone_number", "type": "phone", "status": "INACTIVE"}]
    org.events = [
        event(
            "user.authentication.auth_via_mfa",
            reason="VERIFICATION_ERROR",
            authenticationContext={"credentialType": "SMS"},
        )
    ]
    out = await diagnose(ex)
    (check,) = [c for c in out["checks"] if c["check"] == "authenticator_enrollment"]
    assert check["pass"] is False
    assert check["failing_credential_types"] == {"SMS": 1}
    assert "enroll" in check["note"]


@pytest.mark.anyio
async def test_an_admin_s_failed_action_on_the_user_is_left_out(ex: Executor, org: Org) -> None:
    org.events = [
        event(
            "user.lifecycle.deactivate",
            reason="INSUFFICIENT_PERMISSIONS",
            actor=OTHER,
            targets=[{"id": UID, "type": "User"}],
        ),
    ]
    out = await diagnose(ex)
    assert out["window"]["events_read"] == 1 and out["window"]["events_about_user"] == 0
    assert "causes" not in out


@pytest.mark.anyio
async def test_token_failures_count_but_the_dpop_handshake_does_not(ex: Executor, org: Org) -> None:
    client = "0oa2emaKYZTWRYYRRTSK"
    user = [{"id": UID, "type": "User"}]
    org.events = [
        event("app.oauth2.token.grant", reason="use_dpop_nonce", actor=client, targets=user),
        event("app.oauth2.token.grant", reason="invalid_grant", actor=client, targets=user),
    ]
    for e in org.events:
        e["actor"]["type"] = "PublicClientApp"
    out = await diagnose(ex)
    tokens = cause(out, "oauth_token_error")
    assert tokens["count"] == 1 and tokens["reasons"] == {"invalid_grant": 1}
    assert tokens["clients"] == [{"client_id": client, "count": 1}]


@pytest.mark.anyio
async def test_no_raw_event_and_nothing_secret_in_the_result(ex: Executor, org: Org) -> None:
    org.events = [
        event("policy.evaluate_sign_on", "DENY", "x", targets=[{"id": "r", "type": "Rule"}]),
        event("user.session.start", reason="INVALID_CREDENTIALS"),
        event("something.else", reason="odd"),
    ]
    text = json.dumps(await diagnose(ex))
    for raw in ("raw message", "debugContext", "requestUri", "s3cr3t", "uuid", "alternateId"):
        assert raw not in text


@pytest.mark.anyio
async def test_federated_user_gets_a_provider_note(ex: Executor, org: Org) -> None:
    org.user["credentials"] = {"provider": {"type": "ACTIVE_DIRECTORY"}}
    out = await diagnose(ex)
    (status,) = [c for c in out["checks"] if c["check"] == "user_status"]
    assert status["pass"] is True and "ACTIVE_DIRECTORY" in status["provider_note"]
    assert out["user"]["credentials_provider"] == "ACTIVE_DIRECTORY"


@pytest.mark.anyio
async def test_follow_ups_run_concurrently(ex: Executor, org: Org) -> None:
    # Policy DENY (enrollments) + not assigned (assignment) + locked (blocks): three at once.
    org.user["status"] = "LOCKED_OUT"
    org.events = [
        event("policy.evaluate_sign_on", "DENY", "x"),
        event(
            "app.generic.unauth_app_access_attempt",
            reason="not assigned",
            targets=[{"id": APP, "type": "AppInstance"}],
        ),
    ]
    import anyio

    started: list[str] = []
    gate = anyio.Event()

    async def slow(request: httpx2.Request) -> httpx2.Response:
        if request.url.path in ("/api/v1/users", f"/api/v1/users/{UID}", "/api/v1/logs"):
            return await Org.__call__(org, request)
        started.append(request.url.path)
        if len(started) == 3:
            gate.set()
        with anyio.fail_after(5):
            await gate.wait()  # each waits for the others: only concurrent calls finish
        return await Org.__call__(org, request)

    client = OktaClient(
        new_http_client(httpx2.MockTransport(slow)),
        org_url=ORG,
        tokens=Tokens(),
        dpop=None,
        max_inflight=10,
        rate_limit_max_wait=10,
    )
    ex._client = client  # pyright: ignore[reportPrivateUsage]
    out = await diagnose(ex)
    # The three follow-ups ran at once (the gate opened); the policy lookups come after.
    assert len(started) >= 3
    assert {c["check"] for c in out["checks"]} == {
        "user_status",
        "app_assignment",
        "authenticator_enrollment",
        "sign_in_blocks",
    }


# --- classification --------------------------------------------------------------------


def _e(event_type: str, result: str = "FAILURE", reason: str = "", cred: str = "") -> Any:
    raw = {
        "eventType": event_type,
        "outcome": {"result": result, "reason": reason},
        "authenticationContext": {"credentialType": cred},
    }
    return lf._event(raw)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (
            ("user.session.start", "FAILURE", "INVALID_CREDENTIALS", "PASSWORD"),
            "invalid_credentials",
        ),
        (("user.session.start", "FAILURE", "LOCKED_OUT"), "locked_out"),
        (("user.account.lock", "SUCCESS"), "locked_out"),
        (("user.account.unlock", "SUCCESS"), None),
        (("user.session.start", "FAILURE", "PASSWORD_EXPIRED"), "password_expired"),
        (
            ("policy.evaluate_sign_on", "DENY", "Sign-on policy evaluation resulted in DENY"),
            "sign_on_policy_deny",
        ),
        (("policy.auth_reevaluate.fail", "DENY"), "other_policy_deny"),
        (("user.session.start", "DENY", "Request blocked by network zone"), "ip_or_threat_block"),
        (("user.authentication.auth_via_IDP", "FAILURE"), "idp_failure"),
        (
            ("user.authentication.auth_via_mfa", "FAILURE", "VERIFICATION_ERROR", "OTP"),
            "mfa_failed",
        ),
        (("user.authentication.verify", "FAILURE", "INVALID_CREDENTIALS", "OTP"), "mfa_failed"),
        (
            ("user.authentication.verify", "FAILURE", "INVALID_CREDENTIALS", "PASSWORD"),
            "invalid_credentials",
        ),
        (
            ("user.authentication.verify", "FAILURE", "Authenticator method abandoned"),
            "mfa_abandoned",
        ),
        (("app.oauth2.as.token.grant", "FAILURE", "invalid_refresh_token"), "oauth_token_error"),
        (("app.oauth2.token.grant", "FAILURE", "use_dpop_nonce"), None),
        (("system.something", "FAILURE", "odd"), "other"),
    ],
)
def test_cause(args: tuple[str, ...], expected: str | None) -> None:
    assert lf._cause(_e(*args)) == expected  # pyright: ignore[reportPrivateUsage]


def test_every_cause_has_attributes_and_a_rank() -> None:
    assert lf.CAUSES.keys() == lf._ATTRS.keys()  # pyright: ignore[reportPrivateUsage]
    assert len({rank for rank, _ in lf.CAUSES.values()}) == len(lf.CAUSES)


def test_the_registry_pattern_is_the_handler_s(registry: Registry) -> None:
    command = registry.domains["diagnostics"].commands["login-failures"]
    for arg in ("since", "until"):
        assert command.entry.args[arg].pattern == lf.TIMESTAMP


def test_a_helpdesk_principal_sees_only_the_diagnosis(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    from okta_mcp.resources import Resources
    from okta_mcp.tools import Tools

    ex = make(registry, spec, org)
    engine = ex._engine  # pyright: ignore[reportPrivateUsage]
    resources = Resources(registry, engine)
    tools = Tools(
        registry=registry, engine=engine, executor=ex, max_items=1000, guides=resources.guides
    )
    listed = {t.name: t for t in tools.list_tools(helpdesk())}
    assert set(listed) == {"okta_diagnostics", "okta_help", "okta_status"}
    description = listed["okta_diagnostics"].description or ""
    assert "login-failures <user> [options]" in description
    assert "okta://guide/diagnostics" in description


@pytest.mark.anyio
async def test_until_alone_clamps_the_default_since(ex: Executor, org: Org) -> None:
    # 24 h before `until` would be past retention; the default stops at 90 days.
    await diagnose(ex, args={"user": UID, "until": "2026-08-16T13:00:00Z"})
    assert org.log_query()["since"] == ["2026-08-16T12:00:00.000Z"]
    out = await diagnose(ex, args={"user": UID, "until": "2026-08-01T00:00:00Z"})
    assert "arg 'until' is more than 90 days" in failed(out, Code.INVALID_ARGUMENTS).message


@pytest.mark.anyio
async def test_the_user_s_own_failed_admin_actions_are_left_out(ex: Executor, org: Org) -> None:
    org.events = [
        event("group.user_membership.add", reason="INSUFFICIENT_PERMISSIONS"),
        event("user.session.start", reason="INVALID_CREDENTIALS"),
    ]
    out = await diagnose(ex)
    assert out["window"]["events_about_user"] == 1
    assert [c["cause"] for c in out["causes"]] == ["invalid_credentials"]


@pytest.mark.anyio
async def test_a_bug_in_one_check_costs_only_that_check(
    ex: Executor, org: Org, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(ctx: Any, uid: str) -> Any:
        async def job() -> dict[str, Any]:
            raise KeyError("boom")

        return job

    monkeypatch.setattr(lf, "_blocks", broken)
    org.user["status"] = "LOCKED_OUT"
    org.events = [event("policy.evaluate_sign_on", "DENY", "x")]
    out = await diagnose(ex)
    follow_ups = [x for x in out["skipped"] if not x["check"].startswith("policy evaluation")]
    assert follow_ups == [{"check": "sign_in_blocks", "reason": lf.INTERNAL}]
    assert [c["check"] for c in out["checks"]] == ["user_status", "authenticator_enrollment"]


@pytest.mark.anyio
async def test_checks_come_in_job_order_whatever_finishes_first(ex: Executor, org: Org) -> None:
    import anyio

    org.user["status"] = "LOCKED_OUT"
    org.events = [
        event("policy.evaluate_sign_on", "DENY", "x"),
        event(
            "app.generic.unauth_app_access_attempt",
            reason="not assigned",
            targets=[{"id": APP, "type": "AppInstance"}],
        ),
    ]
    first = Org.__call__

    async def slow_assignment(self: Org, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/api/v1/apps"):
            await anyio.sleep(0.05)  # finishes last
        return await first(self, request)

    Org.__call__ = slow_assignment  # pyright: ignore[reportAttributeAccessIssue]
    try:
        out = await diagnose(ex)
    finally:
        Org.__call__ = first  # pyright: ignore[reportAttributeAccessIssue]
    assert [c["check"] for c in out["checks"]] == [
        "user_status",
        "app_assignment",
        "authenticator_enrollment",
        "sign_in_blocks",
    ]


@pytest.mark.anyio
async def test_many_distinct_rules_are_capped(ex: Executor, org: Org) -> None:
    org.events = [
        event(
            "policy.evaluate_sign_on",
            "DENY",
            "x",
            targets=[{"id": f"rul{i:017d}", "type": "Rule", "displayName": "r" * 300}],
        )
        for i in range(50)
    ]
    out = await diagnose(ex)
    policies = cause(out, "sign_on_policy_deny")["policies"]
    assert len(policies) == 10
    assert all(len(p["rule_name"]) == 200 for p in policies)


@pytest.mark.anyio
async def test_a_token_event_never_shows_the_requester_s_ip(ex: Executor, org: Org) -> None:
    user = [{"id": UID, "type": "User"}]
    org.events = [
        event(
            "app.oauth2.token.grant", reason="request blocked by threat", actor=OTHER, targets=user
        ),
    ]
    out = await diagnose(ex)
    tokens = cause(out, "oauth_token_error")
    assert "ips" not in tokens and "clients" not in tokens  # a User actor isn't a client


# --- slice 2: policy evaluation --------------------------------------------------------

POLICY_SCOPES = ALL_SCOPES | {
    "okta.policies.read",
    "okta.networkZones.read",
    "okta.authenticators.read",
}
OFFICE = "nzo1emaKYZTWRYYRRTSK"
VPN = "00g1vpn0000000000000"
STAFF = "00g1staff00000000000"


def access_policy(org: Org) -> None:
    """An app policy: ALLOW from the office for the VPN group with Okta Verify, else DENY."""
    org.policies["rst1emaKYZTWRYYRRTSK"] = {
        "id": "rst1emaKYZTWRYYRRTSK",
        "name": "Salesforce",
        "type": "ACCESS_POLICY",
        "lastUpdated": "2026-11-01T00:00:00.000Z",
    }
    org.rules["rst1emaKYZTWRYYRRTSK"] = [
        {
            "id": "rul1emaKYZTWRYYRRTSK",
            "name": "Office + VPN group",
            "priority": 0,
            "status": "ACTIVE",
            "lastUpdated": "2026-11-14T11:00:00.000Z",  # edited after the denial
            "conditions": {
                "network": {"connection": "ZONE", "include": [OFFICE]},
                "people": {"groups": {"include": [VPN]}},
            },
            "actions": {
                "appSignOn": {
                    "access": "ALLOW",
                    "verificationMethod": {
                        "type": "ASSURANCE",
                        "constraints": [{"possession": {"types": ["app"]}}],
                    },
                }
            },
        },
        {
            "id": "rul9emaKYZTWRYYRRTSK",
            "name": "Catch-all Rule",
            "priority": 1,
            "status": "ACTIVE",
            "system": True,
            "actions": {"appSignOn": {"access": "DENY"}},
        },
    ]
    org.zones = [
        {
            "id": OFFICE,
            "name": "Office",
            "type": "IP",
            "status": "ACTIVE",
            "gateways": [{"type": "CIDR", "value": "10.0.0.0/8"}],
        }
    ]
    org.groups = [STAFF]
    org.authenticators = [{"id": "aut1emaKYZTWRYYRRTSK", "key": "okta_verify", "status": "ACTIVE"}]
    org.methods = {"aut1emaKYZTWRYYRRTSK": [{"type": "push", "status": "ACTIVE"}]}


def catch_all_deny(**extra: Any) -> dict[str, Any]:
    targets = [
        {
            "id": "rul9emaKYZTWRYYRRTSK",
            "type": "Rule",
            "displayName": "Catch-all Rule",
            "detailEntry": {"policyId": "rst1emaKYZTWRYYRRTSK", "policyName": "Salesforce"},
        },
        {"id": APP, "type": "AppInstance", "displayName": "Salesforce"},
    ]
    return event(
        "policy.evaluate_sign_on",
        "DENY",
        "Sign-on policy evaluation resulted in DENY",
        targets=targets,
        **extra,
    )


@pytest.mark.anyio
async def test_a_catch_all_deny_names_what_the_allow_rule_lacked(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    org.enrollments = [{"id": "e1", "key": "okta_email", "type": "email", "status": "ACTIVE"}]
    org.events = [catch_all_deny()]
    out = await diagnose(ex)
    (evaluation,) = out["policy_evaluation"]
    assert evaluation["rule_ids"] == ["rul9emaKYZTWRYYRRTSK"]
    assert evaluation["app"] == {"id": APP, "displayName": "Salesforce"}
    (rule,) = evaluation["rules"]
    assert rule["kind"] == "no_allow_rule_matched"
    assert rule["policy"] == {
        "id": "rst1emaKYZTWRYYRRTSK",
        "name": "Salesforce",
        "type": "ACCESS_POLICY",
    }
    (candidate,) = rule["candidates"]
    assert candidate["rule"]["id"] == "rul1emaKYZTWRYYRRTSK"
    failing = {r["check"]: r for r in candidate["failing"]}
    # Outside the office, not in the VPN group, and no Okta Verify enrolled: all three.
    assert set(failing) == {"network.include", "people.include", "enrolled authenticator"}
    assert failing["network.include"]["required"]["zones"] == ["Office"]
    assert failing["people.include"]["required"]["groups"] == [VPN]
    assert "network.include" in rule["reason"]
    assert out["headline"].endswith(f"Newest denial: {rule['reason']}.")
    assert evaluation["changed_after_event"] == [
        {"type": "rule", "id": "rul1emaKYZTWRYYRRTSK", "last_updated": "2026-11-14T11:00:00.000Z"}
    ]
    assert "skipped" not in out


@pytest.mark.anyio
async def test_groups_are_rewound_to_the_time_of_the_denial(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    org.groups = [STAFF, VPN]  # in the VPN group now ...
    org.membership_events = [
        {
            "published": "2026-11-14T11:00:00.000Z",
            "eventType": "group.user_membership.add",
            "target": [{"type": "UserGroup", "id": VPN}],
        },  # ... but only since after the denial
    ]
    org.events = [catch_all_deny()]
    out = await diagnose(ex)
    (candidate,) = out["policy_evaluation"][0]["rules"][0]["candidates"]
    assert "people.include" in {r["check"] for r in candidate["failing"]}


@pytest.mark.anyio
async def test_without_policy_scopes_the_evaluation_is_skipped_not_fatal(
    ex: Executor, org: Org
) -> None:
    access_policy(org)
    org.events = [catch_all_deny()]
    out = await diagnose(ex)
    (evaluation,) = out["policy_evaluation"]
    assert evaluation["unresolved"][0]["reason"] == "the service app needs okta.policies.read"
    reasons = {s["check"]: s["reason"] for s in out["skipped"]}
    assert reasons["policy evaluation: policy"] == "the service app needs okta.policies.read"
    assert reasons["policy evaluation: network zones"] == (
        "the service app needs okta.networkZones.read"
    )
    assert cause(out, "sign_on_policy_deny")["count"] == 1
    assert not any(p.startswith(("/api/v1/policies", "/api/v1/zones")) for p in org.paths)


@pytest.mark.anyio
async def test_a_rule_without_its_policy_is_found_by_scanning(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    org.policies["00p1emaKYZTWRYYRRTSK"] = {
        "id": "00p1emaKYZTWRYYRRTSK",
        "name": "Default Policy",
        "type": "OKTA_SIGN_ON",
    }
    org.rules["00p1emaKYZTWRYYRRTSK"] = [
        {
            "id": "0pr1emaKYZTWRYYRRTSK",
            "name": "Block abroad",
            "priority": 1,
            "status": "ACTIVE",
            "actions": {"signon": {"access": "DENY"}},
            "conditions": {"network": {"connection": "ZONE", "include": [OFFICE]}},
        },
    ]
    org.zones = [
        {
            "id": OFFICE,
            "name": "Abroad",
            "type": "IP",
            "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}],
        }
    ]
    org.events = [
        event(
            "policy.evaluate_sign_on",
            "DENY",
            "x",
            targets=[
                {
                    "id": "0pr1emaKYZTWRYYRRTSK",
                    "type": "Rule",
                    "displayName": "Block abroad",
                    "detailEntry": {"policyName": "Default Policy"},
                },
            ],
        )
    ]
    out = await diagnose(ex)
    (rule,) = out["policy_evaluation"][0]["rules"]
    assert rule["kind"] == "explicit_deny_rule"
    assert rule["policy"]["type"] == "OKTA_SIGN_ON"
    assert rule["passed"] == 1  # the IP is in the rule's zone: the DENY rule matched


@pytest.mark.anyio
async def test_an_id_from_the_event_that_isn_t_one_never_reaches_a_path(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    org.events = [
        event(
            "policy.evaluate_sign_on",
            "DENY",
            "x",
            targets=[
                {"id": "rul1", "type": "Rule", "detailEntry": {"policyId": "../../users/me"}},
                {"id": "rul2", "type": "Rule", "detailEntry": {"policyId": "simulate"}},
            ],
        )
    ]
    out = await diagnose(ex)
    unresolved = out["policy_evaluation"][0]["unresolved"]
    assert len(unresolved) == 2
    assert not any("users/me" in p or p.endswith("/simulate") for p in org.paths)


@pytest.mark.anyio
async def test_verify_events_match_only_the_same_sign_in(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    org.events = [catch_all_deny(transaction={"id": "tx1"})]
    org.verify_events = [
        event("user.authentication.verify", "SUCCESS", transaction={"id": "tx-other"}),
        event("user.authentication.verify", "SUCCESS", transaction={"id": "tx1"}),
    ]
    out = await diagnose(ex)
    assert out["policy_evaluation"][0]["verify_events_matched_by"] == "transaction.id"
    query = parse_qs(
        next(r for r in org.requests if "verify" in r.url.query.decode()).url.query.decode()
    )
    assert query["since"] == ["2026-11-14T09:30:00.000Z"]
    assert query["until"] == ["2026-11-14T10:00:01.000Z"]


@pytest.mark.anyio
async def test_the_password_policy_for_a_lockout(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    org.user["status"] = "LOCKED_OUT"
    org.groups = [STAFF]
    org.policies["00p2emaKYZTWRYYRRTSK"] = {
        "id": "00p2emaKYZTWRYYRRTSK",
        "name": "Staff passwords",
        "type": "PASSWORD",
        "status": "ACTIVE",
        "priority": 1,
        "conditions": {
            "people": {"groups": {"include": [STAFF]}},
            "authProvider": {"provider": "OKTA"},
        },
        "settings": {"password": {"lockout": {"maxAttempts": 3, "autoUnlockMinutes": 30}}},
    }
    target = [{"id": UID, "type": "User"}]
    org.events = [
        event("user.account.lock", "SUCCESS", actor="system", targets=target),
        *[event("user.session.start", reason="INVALID_CREDENTIALS") for _ in range(3)],
    ]
    out = await diagnose(ex)
    password = out["password_policy"]
    assert password["policy"]["name"] == "Staff passwords"
    assert [r["check"] for r in password["failing"]] == ["password.lockout.maxAttempts"]
    assert "30 minutes" in password["undecided"][0]["note"]
    assert "policy_evaluation" not in out  # no DENY, so no rules to evaluate


@pytest.mark.anyio
async def test_a_small_budget_trims_detail_instead_of_failing(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    access_policy(org)
    org.rules["rst1emaKYZTWRYYRRTSK"] = [
        {
            **org.rules["rst1emaKYZTWRYYRRTSK"][0],
            "id": f"rul{i}emaKYZTWRYYRRTSK",
            "priority": i,
            "name": "r" * 150,
        }
        for i in range(5)
    ] + [{**org.rules["rst1emaKYZTWRYYRRTSK"][1], "priority": 9}]
    org.events = [catch_all_deny()]
    small = make(registry, spec, org, scopes=POLICY_SCOPES)
    small._max_bytes = 6000  # pyright: ignore[reportPrivateUsage]
    out = await diagnose(small)
    assert out["trimmed"] is True
    (rule,) = out["policy_evaluation"][0]["rules"]
    assert len(rule["candidates"]) == 1 and rule["candidates_total"] == 5


# --- slice 2 code review regressions --------------------------------------------------


@pytest.mark.anyio
async def test_a_failed_policy_read_with_a_scanned_rule_does_not_crash(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    pid = "00p1emaKYZTWRYYRRTSK"
    org.policies[pid] = {"id": pid, "name": "Default Policy", "type": "OKTA_SIGN_ON"}
    org.rules[pid] = [
        {
            "id": "0pr1emaKYZTWRYYRRTSK",
            "priority": 1,
            "status": "ACTIVE",
            "actions": {"signon": {"access": "DENY"}},
        }
    ]
    org.override = lambda r: (
        httpx2.Response(500, json={}) if r.url.path == f"/api/v1/policies/{pid}" else None
    )
    org.events = [
        event(
            "policy.evaluate_sign_on",
            "DENY",
            "x",
            targets=[
                {"id": "rul1", "type": "Rule", "detailEntry": {"policyId": pid}},
                {
                    "id": "0pr1emaKYZTWRYYRRTSK",
                    "type": "Rule",
                    "detailEntry": {"policyName": "Default Policy"},
                },
            ],
        )
    ]
    out = await diagnose(ex)
    (evaluation,) = out["policy_evaluation"]
    # The listed policy stands in for the failed read: the scanned rule is diagnosed.
    assert [r["rule"]["id"] for r in evaluation["rules"]] == ["0pr1emaKYZTWRYYRRTSK"]


@pytest.mark.anyio
async def test_cut_membership_changes_make_a_group_miss_undecided(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    org.membership_events = [
        {
            "published": "2026-11-14T11:00:00.000Z",
            "eventType": "group.user_membership.add",
            "target": [{"type": "UserGroup", "id": f"00g{i:017d}"}],
        }
        for i in range(250)
    ]
    org.events = [catch_all_deny()]
    out = await diagnose(ex)
    evaluation = out["policy_evaluation"][0]
    assert "more group membership changes" in evaluation["groups_note"]
    (candidate,) = evaluation["rules"][0]["candidates"]
    assert "people.include" in {r["check"] for r in candidate.get("undecided", [])}


@pytest.mark.anyio
async def test_one_verify_query_serves_every_denial(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    other = catch_all_deny(at="2026-11-14T08:00:00.000Z")
    other["target"][1]["id"] = "0oa2emaKYZTWRYYRRTSK"  # another app: another denial group
    org.events = [catch_all_deny(), other]
    out = await diagnose(ex)
    assert len(out["policy_evaluation"]) == 2
    verify = [r for r in org.requests if "user.authentication.verify" in r.url.query.decode()]
    assert len(verify) == 1
    query = parse_qs(verify[0].url.query.decode())
    assert query["since"] == ["2026-11-14T07:30:00.000Z"]


@pytest.mark.anyio
async def test_the_headline_never_borrows_an_older_denial_s_reason(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    access_policy(org)
    older = catch_all_deny(at="2026-11-14T08:00:00.000Z")
    newest = event(
        "policy.evaluate_sign_on",
        "DENY",
        "x",
        targets=[
            {
                "id": "rulXemaKYZTWRYYRRTSK",
                "type": "Rule",
                "detailEntry": {"policyId": "rst1emaKYZTWRYYRRTSK"},
            },  # not in the policy now
        ],
    )
    org.events = [newest, older]
    out = await diagnose(ex)
    assert out["policy_evaluation"][1]["rules"][0].get("reason")
    assert "Newest denial" not in out["headline"]


@pytest.mark.anyio
async def test_wave_one_runs_alongside_the_follow_ups(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    import anyio

    access_policy(org)
    org.events = [catch_all_deny()]
    seen_policy = anyio.Event()
    first = Org.__call__

    async def gated(self: Org, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/api/v1/policies"):
            seen_policy.set()
        if request.url.path.endswith("/authenticator-enrollments"):
            with anyio.fail_after(5):
                await seen_policy.wait()  # sequential waves would never get here in time
        return await first(self, request)

    Org.__call__ = gated  # pyright: ignore[reportAttributeAccessIssue]
    try:
        out = await diagnose(make(registry, spec, org, scopes=POLICY_SCOPES))
    finally:
        Org.__call__ = first  # pyright: ignore[reportAttributeAccessIssue]
    assert out["policy_evaluation"][0]["rules"][0]["kind"] == "no_allow_rule_matched"


@pytest.mark.anyio
@pytest.mark.parametrize("max_bytes", [1500, 3000, 6000])
async def test_any_budget_gets_an_answer(
    registry: Registry, spec: SpecIndex, org: Org, max_bytes: int
) -> None:
    access_policy(org)
    org.user["status"] = "LOCKED_OUT"
    org.rules["rst1emaKYZTWRYYRRTSK"] = [
        {
            **org.rules["rst1emaKYZTWRYYRRTSK"][0],
            "id": f"rul{i}emaKYZTWRYYRRTSK",
            "priority": i,
            "name": "r" * 150,
        }
        for i in range(5)
    ] + [{**org.rules["rst1emaKYZTWRYYRRTSK"][1], "priority": 9}]
    org.events = [
        catch_all_deny(),
        *[
            event(
                "user.session.start",
                reason="INVALID_CREDENTIALS",
                at=f"2026-11-14T09:{i:02d}:00.000Z",
            )
            for i in range(20)
        ],
    ]
    small = make(registry, spec, org, scopes=POLICY_SCOPES)
    small._max_bytes = max_bytes  # pyright: ignore[reportPrivateUsage]
    out = await small.execute(Call(helpdesk(), "diagnostics", "login-failures", args={"user": UID}))
    assert isinstance(out, Success), out
    assert json.loads(out.text)["item"]["headline"]


# --- slice 3: device assurance and advanced posture checks ----------------------------

DEVICE_SCOPES = POLICY_SCOPES | {"okta.deviceAssurance.read", "okta.devicePostureChecks.read"}
ASSURANCE = "dae1emaKYZTWRYYRRTSK"


def device_policy(org: Org, *, posture: bool) -> None:
    """The app policy's ALLOW rule needs a compliant Mac, with a firewall posture check."""
    access_policy(org)
    allow = org.rules["rst1emaKYZTWRYYRRTSK"][0]
    allow["conditions"] = {"device": {"registered": True, "assurance": {"include": [ASSURANCE]}}}
    allow["actions"]["appSignOn"].pop("verificationMethod")
    org.assurance[ASSURANCE] = {
        "id": ASSURANCE,
        "name": "Mac baseline",
        "platform": "MACOS",
        "osVersion": {"minimum": "15.0"},
        **(
            {"devicePostureChecks": {"include": [{"variableName": "macOSFirewall", "value": "1"}]}}
            if posture
            else {}
        ),
    }
    org.posture_checks = [
        {
            "id": "dch1emaKYZTWRYYRRTSK",
            "variableName": "macOSFirewall",
            "name": "Firewall on",
            "type": "CUSTOM",
            "query": "SELECT 1;",
            "remediationSettings": {"message": {"customText": "Turn on the firewall"}},
        }
    ]


def mac_deny() -> dict[str, Any]:
    return catch_all_deny(
        device={
            "os_platform": "OSX",
            "os_version": "14.6",
            "registered": True,
            "managed": True,
            "macOSFirewall": "0",
        }
    )


@pytest.mark.anyio
async def test_a_device_failing_assurance_and_a_posture_check(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=DEVICE_SCOPES)
    device_policy(org, posture=True)
    org.events = [mac_deny()]
    out = await diagnose(ex)
    (candidate,) = out["policy_evaluation"][0]["rules"][0]["candidates"]
    failing = {r["check"]: r for r in candidate["failing"]}
    assert set(failing) == {
        "assurance 'Mac baseline': osVersion.minimum",
        "assurance 'Mac baseline': posture check macOSFirewall",
    }
    posture = failing["assurance 'Mac baseline': posture check macOSFirewall"]
    assert posture["required"]["remediation"] == "Turn on the firewall"
    assert posture["actual"] == "0"
    assert candidate["passed"] == 1  # device.registered
    assert org.paths.count(f"/api/v1/device-assurances/{ASSURANCE}") == 1
    assert "/api/v1/device-posture-checks" in org.paths
    assert "skipped" not in out


@pytest.mark.anyio
async def test_no_posture_checks_in_use_means_no_posture_calls_or_scope(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    # The org doesn't use advanced posture checks, and the service app lacks their scope.
    scopes = POLICY_SCOPES | {"okta.deviceAssurance.read"}
    ex = make(registry, spec, org, scopes=scopes)
    device_policy(org, posture=False)
    org.events = [mac_deny()]
    out = await diagnose(ex)
    assert not any(p.startswith("/api/v1/device-posture-checks") for p in org.paths)
    assert "skipped" not in out
    (candidate,) = out["policy_evaluation"][0]["rules"][0]["candidates"]
    assert [r["check"] for r in candidate["failing"]] == [
        "assurance 'Mac baseline': osVersion.minimum"
    ]


@pytest.mark.anyio
async def test_posture_checks_without_their_scope_still_evaluate(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES | {"okta.deviceAssurance.read"})
    device_policy(org, posture=True)
    org.events = [mac_deny()]
    out = await diagnose(ex)
    assert {
        "check": "policy evaluation: device posture checks",
        "reason": "the service app needs okta.devicePostureChecks.read",
    } in out["skipped"]
    (candidate,) = out["policy_evaluation"][0]["rules"][0]["candidates"]
    posture = next(r for r in candidate["failing"] if "posture check" in r["check"])
    assert posture["actual"] == "0" and "remediation" not in posture["required"]


@pytest.mark.anyio
async def test_without_the_assurance_scope_the_assurance_check_is_undecided(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=POLICY_SCOPES)
    device_policy(org, posture=True)
    org.events = [mac_deny()]
    out = await diagnose(ex)
    (candidate,) = out["policy_evaluation"][0]["rules"][0]["candidates"]
    assert candidate["status"] == "undetermined"
    assert candidate["undecided"][0]["note"] == "the service app needs okta.deviceAssurance.read"
    assert not any(p.startswith("/api/v1/device") for p in org.paths)


@pytest.mark.anyio
async def test_an_assurance_id_that_isn_t_one_is_never_sent(
    registry: Registry, spec: SpecIndex, org: Org
) -> None:
    ex = make(registry, spec, org, scopes=DEVICE_SCOPES)
    device_policy(org, posture=False)
    allow = org.rules["rst1emaKYZTWRYYRRTSK"][0]
    allow["conditions"]["device"]["assurance"]["include"] = ["../users/me"]
    org.events = [mac_deny()]
    await diagnose(ex)
    assert not any(p.startswith("/api/v1/device-assurances") for p in org.paths)
