"""The logs, sessions and security registries (plan step 5.3)."""

from typing import Any

import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.executor import searchable
from okta_mcp.exec.output import load_scrub
from okta_mcp.exec.params import build_request
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.expression import scrubbed
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry
from okta_mcp.registry.schema import InvalidArguments, validate_args

ORG = "https://example.okta.com"
SESSION = "102GALFKlYFRGq_1TuolTsMjQ"
G1 = "00g1secanalyst000000"


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.operation.operation_id for n, c in registry.domains[domain].commands.items()}


def test_commands(registry: Registry) -> None:
    assert _commands(registry, "logs") == {"list": "listLogEvents"}
    assert _commands(registry, "sessions") == {"get": "getSession"}
    assert _commands(registry, "security") == {
        "get-threat-insight-config": "getCurrentConfiguration",
        "get-bot-protection-config": "getBotProtectionConfiguration",
        "list-event-providers": "listSecurityEventsProviderInstances",
        "get-event-provider": "getSecurityEventsProviderInstance",
    }


def test_ssf_streams_are_not_served(registry: Registry) -> None:
    # Excluded in the catalogue: Okta shows a client only the streams it created.
    ops = {c.operation.operation_id for d in registry.domains.values() for c in d.commands.values()}
    assert not ops & {"getSsfStreams", "getSsfStreamStatus"}


def test_classes(registry: Registry) -> None:
    logs = registry.domains["logs"].commands["list"]
    assert logs.entry.data_classes == ("audit-log", "pii", "risk")
    assert logs.sensitivity == "sensitive"
    session = registry.domains["sessions"].commands["get"]
    assert session.entry.data_classes == ("session", "pii")
    assert session.sensitivity == "sensitive"
    for cmd in registry.domains["security"].commands.values():
        assert cmd.entry.data_classes == ("org-config",), cmd.name
        assert cmd.sensitivity == "normal"


def test_scope_sets(registry: Registry) -> None:
    def scopes(domain: str, command: str) -> tuple[frozenset[str], ...]:
        return registry.domains[domain].commands[command].scope_sets

    assert scopes("logs", "list") == (frozenset({"okta.logs.read"}),)
    assert scopes("sessions", "get") == (frozenset({"okta.sessions.read"}),)
    assert scopes("security", "get-threat-insight-config") == (
        frozenset({"okta.threatInsights.read"}),
    )
    assert scopes("security", "get-bot-protection-config") == (
        frozenset({"okta.botProtection.read"}),
    )
    for name in ("list-event-providers", "get-event-provider"):
        assert scopes("security", name) == (frozenset({"okta.securityEventsProviders.read"}),)


def test_logs_list_args(registry: Registry) -> None:
    cmd = registry.domains["logs"].commands["list"]
    assert set(cmd.entry.args) == {"since", "until", "filter", "sort_order"}
    # Keyword search can match fields results redact; `after` is the paging token.
    exposed = {a.param for a in cmd.entry.args.values()}
    assert {"q", "after", "limit"} <= set(cmd.operation.params)
    assert not exposed & {"q", "after", "limit"}
    rule = cmd.entry.args["filter"].arg_rule
    assert rule is not None and rule.attribute_expression
    validate_args(cmd, {})
    validate_args(
        cmd,
        {
            "since": "2026-11-01T00:00:00.000Z",
            "until": "2026-11-02T00:00:00.000Z",
            "filter": 'eventType eq "user.session.start"',
            "sort_order": "DESCENDING",
        },
    )
    for bad in ({"sort_order": "desc"}, {"q": "alice"}, {"after": "x"}, {"limit": 5}):
        with pytest.raises(InvalidArguments):
            validate_args(cmd, bad)


def test_logs_list_request(registry: Registry) -> None:
    cmd = registry.domains["logs"].commands["list"]
    assert cmd.entry.paginate == "link"
    url, params = build_request(
        cmd, {"filter": 'outcome.result eq "FAILURE"', "sort_order": "ASCENDING"}, ORG
    )
    assert url == f"{ORG}/api/v1/logs"
    assert params == {
        "filter": 'outcome.result eq "FAILURE"',
        "sortOrder": "ASCENDING",
        "limit": "100",
    }


def _engine(registry: Registry, role: dict[str, Any]) -> Engine:
    policy = build_policy({"version": 1, "roles": {"analyst": {"groups": [G1], **role}}}, registry)
    scopes = frozenset(
        s
        for d in registry.domains.values()
        for c in d.commands.values()
        for ss in c.scope_sets
        for s in ss
    )
    return Engine(policy, registry, scopes)


WHO = Principal(uid="00u1example000000000", sub="user@example.com", groups=frozenset({G1}))


def test_logs_filter_is_checked_against_search_attributes(registry: Registry) -> None:
    e = _engine(
        registry,
        {
            "allow": {"logs": ["list"]},
            "search_attributes": ["eventType", "outcome.result", "actor.alternateId"],
        },
    )
    ok = 'eventType eq "user.session.start" and outcome.result eq "FAILURE"'
    assert e.check(WHO, "logs", "list", {"filter": ok}) is Verdict.ALLOWED
    assert e.check(WHO, "logs", "list", {}) is Verdict.ALLOWED
    for other in ('target.id eq "00u1"', 'eventType eq "x" or client.ipAddress sw "10."'):
        assert e.check(WHO, "logs", "list", {"filter": other}) is Verdict.FORBIDDEN
    assert e.check(WHO, "logs", "list", {"filter": "eventType eq 'x'"}) is Verdict.INVALID


def test_logs_filter_without_search_attributes_is_refused(registry: Registry) -> None:
    e = _engine(registry, {"allow": {"logs": ["*"]}, "include_sensitive": ["logs"]})
    assert e.check(WHO, "logs", "list", {"since": "2026-11-01T00:00:00Z"}) is Verdict.ALLOWED
    f = 'eventType eq "user.session.start"'
    assert e.check(WHO, "logs", "list", {"filter": f}) is Verdict.FORBIDDEN


def test_logs_filter_never_names_a_redacted_attribute(registry: Registry) -> None:
    # Okta hashes `clientSecret` in debugData, and scrub.yaml redacts it; `*` doesn't lift that.
    e = _engine(registry, {"allow": {"logs": ["list"]}, "search_attributes": ["*"]})
    assert e.check(WHO, "logs", "list", {"filter": 'eventType eq "x"'}) is Verdict.ALLOWED
    for attr in (
        "debugContext.debugData.clientSecret",
        "target.changeDetails.to.channel.config.headers.value",
        "debugContext.debugData.token",
    ):
        verdict = e.check(WHO, "logs", "list", {"filter": f'{attr} sw "a"'})
        assert verdict is Verdict.FORBIDDEN, attr


def test_logs_filter_is_closed_to_plain_fields_whatever_the_role(registry: Registry) -> None:
    # Naming a free-form object could match a redacted key inside it, which the redaction test
    # (names only) can't see; `*` doesn't open them.
    e = _engine(registry, {"allow": {"logs": ["list"]}, "search_attributes": ["*"]})
    for attr in (
        "debugContext.debugData",
        "debugContext",
        "debugContext.debugData.url",
        "debugContext.debugData.requestUri",
        "target.changeDetails.to",
        "target.changeDetails",
        "target",
        "actor.detailEntry",
        "transaction.detail",
        "securityContext.risk",
        "client",
    ):
        verdict = e.check(WHO, "logs", "list", {"filter": f'{attr} co "a"'})
        assert verdict is Verdict.FORBIDDEN, attr
    both = 'eventType eq "x" and debugContext.debugData co "a"'
    assert e.check(WHO, "logs", "list", {"filter": both}) is Verdict.FORBIDDEN
    # A role's own list is held to the closed set as well.
    listed = _engine(
        registry,
        {"allow": {"logs": ["list"]}, "search_attributes": ["eventType", "debugContext.debugData"]},
    )
    assert listed.check(WHO, "logs", "list", {"filter": 'eventType eq "x"'}) is Verdict.ALLOWED
    f = 'debugContext.debugData co "a"'
    assert listed.check(WHO, "logs", "list", {"filter": f}) is Verdict.FORBIDDEN


def test_logs_closed_set_is_plain_and_unredacted(registry: Registry) -> None:
    rule = registry.domains["logs"].commands["list"].entry.args["filter"].arg_rule
    assert rule is not None and rule.attributes is not None
    free_form = ("debugContext", "changeDetails", "detailEntry", "transaction.detail")
    for attr in rule.attributes:
        assert not any(part in attr for part in free_form), attr
        assert not scrubbed(attr, load_scrub()), attr


def test_logs_help_lists_the_closed_set(registry: Registry) -> None:
    cmd = registry.domains["logs"].commands["list"]
    wildcard = _engine(registry, {"allow": {"logs": ["list"]}, "search_attributes": ["*"]})
    line = searchable(wildcard, WHO, cmd)
    assert line.startswith("expressions may name only: ") and "eventType" in line
    assert "debugData" not in line and "(+19)" in line  # 39 attributes, 20 shown
    narrow = _engine(
        registry,
        {"allow": {"logs": ["list"]}, "search_attributes": ["eventType", "debugContext.debugData"]},
    )
    assert searchable(narrow, WHO, cmd) == "expressions may name only: eventType"
    outside = _engine(
        registry, {"allow": {"logs": ["list"]}, "search_attributes": ["debugContext.debugData"]}
    )
    assert searchable(outside, WHO, cmd) == "your roles allow no filter on this command"


def test_sensitive_commands_need_naming_or_include_sensitive(registry: Registry) -> None:
    wildcard = _engine(registry, {"allow": {"logs": ["*"], "sessions": ["*"], "security": ["*"]}})
    assert wildcard.check(WHO, "logs", "list", {}) is Verdict.FORBIDDEN
    assert wildcard.check(WHO, "sessions", "get", {"session": SESSION}) is Verdict.FORBIDDEN
    assert wildcard.check(WHO, "security", "get-threat-insight-config", {}) is Verdict.ALLOWED
    named = _engine(registry, {"allow": {"logs": ["list"], "sessions": ["get"]}})
    assert named.check(WHO, "logs", "list", {}) is Verdict.ALLOWED
    assert named.check(WHO, "sessions", "get", {"session": SESSION}) is Verdict.ALLOWED


def test_session_id_shape(registry: Registry) -> None:
    cmd = registry.domains["sessions"].commands["get"]
    validate_args(cmd, {"session": SESSION})
    validate_args(cmd, {"session": "l7FbDVqS8zHSy65uJD85"})  # the spec's example, 20 characters
    # `me` is Okta's alias for the caller's own session; too short to pass.
    for bad in ("me", "ME", "l7FbDVqS8zHSy65uJD8", "a/b" * 10, f"{SESSION}\n", "..", f"{SESSION}."):
        with pytest.raises(InvalidArguments, match="arg 'session'"):
            validate_args(cmd, {"session": bad})
    url, _ = build_request(cmd, {"session": SESSION}, ORG)
    assert url == f"{ORG}/api/v1/sessions/{SESSION}"


def test_event_provider_id_shape(registry: Registry) -> None:
    cmd = registry.domains["security"].commands["get-event-provider"]
    validate_args(cmd, {"provider": "sse1qg25RpusjUP6m0g5"})
    for bad in ("", "a/b", "..", "sse1 qg", "sse1qg25RpusjUP6m0g5\n"):
        with pytest.raises(InvalidArguments, match="arg 'provider'"):
            validate_args(cmd, {"provider": bad})
