"""The pure policy evaluator of `diagnostics login-failures` (plan 9.1 slice 2): zones, each
condition, the verification gate, rule diagnosis, group state as of the event, password policy."""

from datetime import UTC, datetime
from typing import Any

import pytest

from okta_mcp.handlers import policy_eval as pe

UID = "00u1alice00000000000"
T = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def ev(**extra: Any) -> dict[str, Any]:
    e: dict[str, Any] = {
        "published": "2026-11-14T10:00:00.000Z",
        "client": {
            "ipAddress": "203.0.113.7",
            "zone": "null",
            "device": "Computer",
            "userAgent": {"os": "Mac OS X"},
            "geographicalContext": {"country": "United States", "state": "Oregon"},
        },
        "securityContext": {"asNumber": 64500},
        "target": [],
    }
    e.update(extra)
    return e


def facts(**kw: Any) -> pe.Facts:
    base: dict[str, Any] = {
        "user": {"id": UID, "type": {"id": "oty1"}},
        "zones": {},
        "groups_now": frozenset({"00g1staff00000000000"}),
        "groups_complete": True,
        "membership_events": [],
        "authenticators": {},
        "enrollments": [],
    }
    base.update(kw)
    return pe.Facts(**base)


def denial(event: dict[str, Any] | None = None, **kw: Any) -> pe.Denial:
    base: dict[str, Any] = {
        "event": event or ev(),
        "at": T,
        "verify_events": [],
        "verify_by": None,
        "groups_at": frozenset({"00g1staff00000000000"}),
    }
    base.update(kw)
    return pe.Denial(**base)


def only(rows: list[pe.Row]) -> pe.Row:
    (r,) = rows
    return r


# --- zones ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gateway", "hit"),
    [
        ({"type": "CIDR", "value": "203.0.113.0/24"}, True),
        ({"type": "CIDR", "value": "198.51.100.0/24"}, False),
        ({"type": "RANGE", "value": "203.0.113.1-203.0.113.9"}, True),
        ({"type": "RANGE", "value": "203.0.113.8-203.0.113.9"}, False),
        ({"type": "RANGE", "value": "::1-::2"}, False),
        ({"type": "CIDR", "value": "nonsense"}, None),
    ],
)
def test_ip_zones(gateway: dict[str, Any], hit: bool | None) -> None:
    assert pe.zone_hit({"type": "IP", "gateways": [gateway]}, ev()) is hit


def test_an_inactive_zone_never_matches() -> None:
    zone = {
        "type": "IP",
        "status": "INACTIVE",
        "gateways": [{"type": "CIDR", "value": "0.0.0.0/0"}],
    }
    assert pe.zone_hit(zone, ev()) is False


def test_dynamic_v2_include_and_exclude() -> None:
    zone: dict[str, Any] = {
        "type": "DYNAMIC_V2",
        "locations": {"include": [{"country": "US", "region": "US-OR"}], "exclude": []},
        "asns": {"include": [], "exclude": ["64500"]},
    }
    assert pe.zone_hit(zone, ev()) is False  # excluded by ASN
    zone["asns"]["exclude"] = ["1"]
    assert pe.zone_hit(zone, ev()) is True
    zone["locations"]["include"] = [{"country": "US", "region": "US-WA"}]
    assert pe.zone_hit(zone, ev()) is False


def test_an_unknown_country_name_is_undecided_not_a_miss() -> None:
    e = ev()
    e["client"]["geographicalContext"] = {"country": "Atlantis"}
    zone = {"type": "DYNAMIC_V2", "locations": {"include": [{"country": "US"}]}}
    assert pe.zone_hit(zone, e) is None


def test_legacy_dynamic_proxy() -> None:
    e = ev()
    e["securityContext"]["isProxy"] = True
    assert pe.zone_hit({"type": "DYNAMIC", "proxyType": "Any"}, e) is True
    e["securityContext"]["isProxy"] = False
    assert pe.zone_hit({"type": "DYNAMIC", "proxyType": "Any"}, e) is False


def test_the_event_s_zone_name_matches() -> None:
    e = ev()
    e["client"]["zone"] = "Office"
    assert pe.zone_hit({"type": "DYNAMIC", "name": "Office"}, e) is True


# --- conditions ----------------------------------------------------------------------------


def test_network_include_names_the_zone_and_fails() -> None:
    f = facts(
        zones={
            "nzo1": {
                "id": "nzo1",
                "name": "Office",
                "type": "IP",
                "gateways": [{"type": "CIDR", "value": "10.0.0.0/8"}],
            }
        }
    )
    r = only(pe.conditions({"network": {"connection": "ZONE", "include": ["nzo1"]}}, denial(), f))
    assert r["pass"] is False
    assert r["required"]["zones"] == ["Office"] and r["actual"]["ip"] == "203.0.113.7"


def test_network_without_zones_is_undecided_with_the_reason() -> None:
    f = facts(zones=pe.Missing("the service app needs okta.networkZones.read"))
    r = only(pe.conditions({"network": {"connection": "ZONE", "include": ["nzo1"]}}, denial(), f))
    assert r["pass"] is None and "networkZones" in r["note"]


def test_network_exclude() -> None:
    f = facts(
        zones={
            "nzo1": {
                "id": "nzo1",
                "name": "Bad",
                "type": "IP",
                "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}],
            }
        }
    )
    r = only(pe.conditions({"network": {"connection": "ZONE", "exclude": ["nzo1"]}}, denial(), f))
    assert r["pass"] is False


def test_people_uses_groups_as_of_the_event() -> None:
    cond = {"people": {"groups": {"include": ["00g1vpn0000000000000"]}}}
    r = only(pe.conditions(cond, denial(), facts()))
    assert r["pass"] is False and r["required"]["groups"] == ["00g1vpn0000000000000"]
    r = only(pe.conditions(cond, denial(groups_at=frozenset({"00g1vpn0000000000000"})), facts()))
    assert r["pass"] is True


def test_people_with_a_cut_group_list_is_undecided_on_a_miss() -> None:
    cond = {"people": {"groups": {"include": ["00g1vpn0000000000000"]}}}
    assert only(pe.conditions(cond, denial(), facts(groups_complete=False)))["pass"] is None


def test_people_exclude_and_users() -> None:
    cond = {"people": {"users": {"exclude": [UID]}}}
    assert only(pe.conditions(cond, denial(), facts()))["pass"] is False
    cond = {"people": {"users": {"include": [UID]}}}
    assert only(pe.conditions(cond, denial(groups_at=None), facts()))["pass"] is True


def test_user_type() -> None:
    assert (
        only(pe.conditions({"userType": {"include": ["oty2"]}}, denial(), facts()))["pass"] is False
    )
    assert (
        only(pe.conditions({"userType": {"exclude": ["oty2"]}}, denial(), facts()))["pass"] is True
    )


def test_device_without_a_device_object() -> None:
    rows = pe.conditions({"device": {"registered": True, "managed": False}}, denial(), facts())
    assert [r["pass"] for r in rows] == [False, True]


def test_device_assurance_not_read_is_undecided() -> None:
    e = ev(device={"registered": True, "managed": True, "os_platform": "MACOS"})
    cond = {"device": {"registered": True, "assurance": {"include": ["dae1"]}}}
    rows = pe.conditions(cond, denial(e), facts())
    assert rows[0]["pass"] is True
    assert rows[1]["check"] == "assurance dae1" and rows[1]["pass"] is None


def test_platform_from_the_user_agent() -> None:
    cond = {"platform": {"include": [{"type": "MOBILE", "os": {"type": "IOS"}}]}}
    assert only(pe.conditions(cond, denial(), facts()))["pass"] is False
    cond = {"platform": {"include": [{"type": "DESKTOP", "os": {"type": "MACOS"}}]}}
    assert only(pe.conditions(cond, denial(), facts()))["pass"] is True


def test_risk_score() -> None:
    e = ev()
    e["securityContext"]["risk"] = {"level": "HIGH"}
    assert only(pe.conditions({"riskScore": {"level": "LOW"}}, denial(e), facts()))["pass"] is False
    assert only(pe.conditions({"riskScore": {"level": "LOW"}}, denial(), facts()))["pass"] is None


def test_el_names_attributes_never_values() -> None:
    cond = {
        "elCondition": {"condition": 'user.profile.department == "Sales" && user.isMemberOf("x")'}
    }
    r = only(
        pe.conditions(cond, denial(), facts(user={"id": UID, "profile": {"department": "Ops"}}))
    )
    assert r["pass"] is None
    assert r["actual"] == {"user_attributes_named": ["department"]}
    assert "Ops" not in str(r)


def test_app_condition() -> None:
    e = ev(target=[{"type": "AppInstance", "id": "0oa1"}])
    cond = {"app": {"include": [{"id": "0oa2"}]}}
    assert only(pe.conditions(cond, denial(e), facts()))["pass"] is False


def test_an_unknown_condition_is_undecided() -> None:
    r = only(pe.conditions({"userIdentifier": {"patterns": []}}, denial(), facts()))
    assert r["pass"] is None and "isn't evaluated" in r["note"]


# --- verification gate ---------------------------------------------------------------------


def _rule(method: dict[str, Any], **kw: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "rul1",
        "name": "MFA",
        "priority": 1,
        "status": "ACTIVE",
        "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": method}},
    }
    rule.update(kw)
    return rule


def test_assurance_needs_an_enrolled_possession_factor() -> None:
    method = {"type": "ASSURANCE", "constraints": [{"possession": {"types": ["app"]}}]}
    rows = pe.gate(
        _rule(method), denial(), facts(enrollments=[{"type": "email", "status": "ACTIVE"}])
    )
    assert only(rows)["pass"] is False
    enrolled = facts(enrollments=[{"type": "app", "key": "okta_verify", "status": "ACTIVE"}])
    assert only(pe.gate(_rule(method), denial(), enrolled))["pass"] is True


def test_enrolled_only_after_the_event_doesn_t_count() -> None:
    method = {"type": "ASSURANCE", "constraints": [{"possession": {"types": ["app"]}}]}
    late = [{"type": "app", "status": "ACTIVE", "created": "2026-11-14T11:00:00.000Z"}]
    assert only(pe.gate(_rule(method), denial(), facts(enrollments=late)))["pass"] is False


def test_a_listed_method_the_enrollment_policy_forbids() -> None:
    method = {
        "type": "AUTH_METHOD_CHAIN",
        "chains": [{"authenticationMethods": [{"key": "okta_verify", "method": "signed_nonce"}]}],
    }
    mfa = {
        "id": "0pr1",
        "settings": {"authenticators": [{"key": "okta_verify", "enroll": {"self": "NOT_ALLOWED"}}]},
    }
    f = facts(
        authenticators={"okta_verify": {"id": "aut1", "status": "ACTIVE"}},
        methods={"aut1": {"signed_nonce": {"status": "ACTIVE"}}},
        enrollments=[],
    )
    rows = pe.gate(_rule(method), denial(mfa_policy=mfa), f)
    failing = {r["check"] for r in rows if r["pass"] is False}
    assert failing == {
        "okta_verify/signed_nonce: enrollment policy allows it",
        "okta_verify/signed_nonce: user enrolled at the time",
    }


def test_verified_properties_from_the_matched_verify_event() -> None:
    method = {
        "type": "ASSURANCE",
        "constraints": [
            {"possession": {"types": ["security_key"], "phishingResistant": "REQUIRED"}}
        ],
    }
    verify = [
        {
            "target": [
                {
                    "type": "AuthenticatorMethod",
                    "detailEntry": {"methodUsedVerifiedProperties": "[USER_PRESENCE]"},
                }
            ]
        }
    ]
    f = facts(enrollments=[{"type": "security_key", "status": "ACTIVE"}])
    rows = pe.gate(_rule(method), denial(verify_events=verify), f)
    prop = next(r for r in rows if "PHISHING_RESISTANT" in r["check"])
    assert prop["pass"] is False
    rows = pe.gate(_rule(method), denial(verify_events=pe.Missing("verify events weren't read")), f)
    assert next(r for r in rows if "verified" in r["check"])["pass"] is None


def test_any_one_option_suffices() -> None:
    method = {
        "type": "ASSURANCE",
        "constraints": [
            {"possession": {"types": ["security_key"]}},
            {"possession": {"types": ["app"]}},
        ],
    }
    f = facts(enrollments=[{"type": "app", "status": "ACTIVE"}])
    r = only(pe.gate(_rule(method), denial(), f))
    assert r["pass"] is True and r["actual"] == "met by option 2"


# --- rule diagnosis ------------------------------------------------------------------------


def _policy(kind: str = "ACCESS_POLICY") -> dict[str, Any]:
    return {"id": "rst1", "name": "App policy", "type": kind}


def test_catch_all_evaluates_the_allow_rules_above_it() -> None:
    allow = _rule(
        {},
        id="rul1",
        name="Office only",
        priority=1,
        conditions={"network": {"connection": "ZONE", "include": ["nzo1"]}},
    )
    catch = {
        "id": "rul9",
        "name": "Catch-all",
        "priority": 99,
        "system": True,
        "actions": {"appSignOn": {"access": "DENY"}},
    }
    f = facts(
        zones={
            "nzo1": {
                "id": "nzo1",
                "name": "Office",
                "type": "IP",
                "gateways": [{"type": "CIDR", "value": "10.0.0.0/8"}],
            }
        }
    )
    out = pe.diagnose_rule(_policy(), [allow, catch], catch, denial(), f)
    assert out["kind"] == "no_allow_rule_matched"
    assert out["reason"] == "closest ALLOW rule 'Office only' failed: network.include"
    (candidate,) = out["candidates"]
    assert candidate["status"] == "blocked" and "pass" not in candidate["failing"][0]
    assert candidate["passed"] == 0


def test_no_allow_rule_above_the_catch_all() -> None:
    catch = {
        "id": "rul9",
        "priority": 1,
        "system": True,
        "actions": {"appSignOn": {"access": "DENY"}},
    }
    out = pe.diagnose_rule(_policy(), [catch], catch, denial(), facts())
    assert out["kind"] == "no_allow_rule_above_catch_all"


def test_an_explicit_deny_rule_shows_its_conditions() -> None:
    deny = {
        "id": "rul2",
        "priority": 1,
        "system": False,
        "actions": {"appSignOn": {"access": "DENY"}},
        "conditions": {"riskScore": {"level": "ANY"}},
    }
    out = pe.diagnose_rule(_policy(), [deny], deny, denial(), facts())
    assert out["kind"] == "explicit_deny_rule" and out["passed"] == 1


def test_an_allow_rule_whose_gate_failed() -> None:
    method = {"type": "ASSURANCE", "constraints": [{"possession": {"types": ["app"]}}]}
    rule = _rule(method)
    out = pe.diagnose_rule(_policy(), [rule], rule, denial(), facts())
    assert out["kind"] == "allow_rule_gate_failed"


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("MFA_ENROLL", "enrollment_policy_context"),
        ("IDP_DISCOVERY", "rule_context"),
        ("OKTA_SIGN_ON", "allow_rule_matched"),
    ],
)
def test_other_policy_types(kind: str, expected: str) -> None:
    rule = {
        "id": "0pr2",
        "priority": 1,
        "actions": {"signon": {"access": "ALLOW"}},
        "conditions": {"network": {"connection": "ANYWHERE"}},
    }
    assert pe.diagnose_rule(_policy(kind), [rule], rule, denial(), facts())["kind"] == expected


def test_candidates_are_capped() -> None:
    allows = [
        _rule({}, id=f"rul{i}", priority=i, conditions={"riskScore": {"level": "LOW"}})
        for i in range(1, 9)
    ]
    catch = {
        "id": "rul99",
        "priority": 99,
        "system": True,
        "actions": {"appSignOn": {"access": "DENY"}},
    }
    out = pe.diagnose_rule(_policy(), [*allows, catch], catch, denial(), facts())
    assert len(out["candidates"]) == pe.CANDIDATES_SHOWN and out["candidates_total"] == 8


# --- state as of the event -----------------------------------------------------------------


def test_groups_as_of_the_event() -> None:
    changes = [
        {
            "published": "2026-11-14T11:00:00.000Z",
            "eventType": "group.user_membership.add",
            "target": [{"type": "UserGroup", "id": "00g1new0000000000000"}],
        },
        {
            "published": "2026-11-14T10:30:00.000Z",
            "eventType": "group.user_membership.remove",
            "target": [{"type": "UserGroup", "id": "00g1old0000000000000"}],
        },
        {
            "published": "2026-11-14T09:00:00.000Z",
            "eventType": "group.user_membership.add",
            "target": [{"type": "UserGroup", "id": "00g1kept000000000000"}],
        },
    ]
    now = frozenset({"00g1new0000000000000", "00g1kept000000000000"})
    assert pe.groups_at(now, changes, T) == {"00g1old0000000000000", "00g1kept000000000000"}


def test_changed_after_the_event() -> None:
    objects = [
        {"id": "a", "lastUpdated": "2026-11-14T11:00:00.000Z"},
        {"id": "b", "lastUpdated": "2026-11-14T09:00:00.000Z"},
    ]
    assert [c["id"] for c in pe.changed_after(T, objects, "rule")] == ["a"]


# --- password policy -----------------------------------------------------------------------


def _password(**settings: Any) -> dict[str, Any]:
    return {
        "id": "00p1",
        "name": "Default",
        "status": "ACTIVE",
        "priority": 1,
        "conditions": {
            "people": {"groups": {"include": ["00g1staff00000000000"]}},
            "authProvider": {"provider": "OKTA"},
        },
        "settings": {"password": settings},
    }


def test_password_policy_lockout_for_a_locked_account() -> None:
    p = _password(lockout={"maxAttempts": 5, "autoUnlockMinutes": 0})
    out = pe.password_policy(
        [p],
        frozenset({"00g1staff00000000000"}),
        {"id": UID},
        {"locked_out": 1, "invalid_credentials": 6},
        NOW,
    )
    assert out["policy"] == {"id": "00p1", "name": "Default"}
    checks = [r["check"] for r in out["failing"]]
    assert checks == ["password.lockout.maxAttempts"]
    assert "admin" in out["undecided"][0]["note"]


def test_password_policy_expired() -> None:
    p = _password(age={"maxAgeDays": 30})
    user = {"id": UID, "status": "PASSWORD_EXPIRED", "passwordChanged": "2026-09-01T00:00:00.000Z"}
    out = pe.password_policy([p], frozenset({"00g1staff00000000000"}), user, {}, NOW)
    assert out["failing"][0]["check"] == "password.age.maxAgeDays"


def test_password_policy_for_another_provider_doesn_t_apply() -> None:
    user = {"id": UID, "credentials": {"provider": {"type": "ACTIVE_DIRECTORY"}}}
    out = pe.password_policy(
        [_password()], frozenset({"00g1staff00000000000"}), user, {"locked_out": 1}, NOW
    )
    assert out["evaluated"] is False


def test_password_policy_without_groups() -> None:
    out = pe.password_policy([_password()], None, {"id": UID}, {"locked_out": 1}, NOW)
    assert out["evaluated"] is False and "groups" in out["note"]


def test_long_values_are_clipped() -> None:
    r = pe.row("x", "y" * 500, ["z"] * 50, False)
    assert len(r["required"]) == 200 and len(r["actual"]) == 21


# --- slice 2 code review regressions ---------------------------------------------------------


def test_a_device_that_doesn_t_say_is_undecided() -> None:
    e = ev(device={"os_platform": "MACOS"})
    r = only(pe.conditions({"device": {"managed": True}}, denial(e), facts()))
    assert r["pass"] is None


def test_methods_count_only_enrollments_before_the_event() -> None:
    method = {"type": "ASSURANCE", "constraints": [{"possession": {"methods": ["PUSH"]}}]}
    f = facts(
        authenticators={"okta_verify": {"id": "aut1", "status": "ACTIVE"}},
        methods={"aut1": {"push": {"status": "ACTIVE"}}},
        enrollments=[
            {
                "type": "app",
                "key": "okta_verify",
                "status": "ACTIVE",
                "created": "2026-11-14T11:00:00.000Z",
            },
        ],
    )
    assert only(pe.gate(_rule(method), denial(), f))["pass"] is False


def test_password_policy_with_cut_groups_says_so() -> None:
    p = _password(lockout={"maxAttempts": 5})
    out = pe.password_policy(
        [p],
        frozenset({"00g1staff00000000000"}),
        {"id": UID},
        {"locked_out": 1},
        NOW,
        complete=False,
    )
    assert "higher-priority" in out["note"]
    out = pe.password_policy([p], frozenset(), {"id": UID}, {"locked_out": 1}, NOW, complete=False)
    assert out["evaluated"] is False


def test_a_rule_s_user_list_never_names_other_users() -> None:
    other = "00u1other00000000000"
    cond = {"people": {"users": {"include": [other, UID]}, "groups": {"include": []}}}
    r = only(pe.conditions(cond, denial(), facts()))
    assert r["pass"] is True
    assert r["required"] == {"groups": [], "users_listed": 2, "named_user_listed": True}
    assert other not in str(r)
