"""Fetching for the policy evaluation of `diagnostics login-failures` (plan 9.1, slice 2).

Two waves, each of independent requests at once (bounded by the client's in-flight share):

1. the policies and rules the DENY events name by ID, the lists of global session and enrollment
   policies (for rules named without their policy), password policies when a password cause is
   present, network zones, the user's groups, group-membership changes since the oldest denial,
   the org's authenticators, and per denial the user's `user.authentication.verify` events just
   before it;
2. the rules of those listed policies, to find the rules named without a policy, and the
   methods of the authenticators the rules name or the user has enrolled.

Every lookup is optional: a scope the service app lacks, an Okta error or an ID that isn't one
gives `Missing` (its reason in `skipped`), and the checks that needed it are undecided. Only IDs
of the expected shape go into a path.
"""

import logging
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import anyio

from okta_mcp.exec.composite import Context, Unavailable
from okta_mcp.handlers import policy_eval as pe
from okta_mcp.logs import log_internal
from okta_mcp.okta.client import UpstreamError
from okta_mcp.okta.paginate import PaginationError
from okta_mcp.okta.ratelimit import RateLimited
from okta_mcp.registry.schema import InvalidArguments

_log = logging.getLogger(__name__)

MAX_DENIALS = 3
"""Distinct denials (same rules and app) evaluated, newest first."""
_POLICY_ID = re.compile(r"[A-Za-z0-9]{1,64}")
_AUTHENTICATOR_ID = re.compile(r"aut[A-Za-z0-9]{17}")
_POLICIES_PER_TYPE = 50
_RULES_PER_POLICY = 200
_SCANNED_POLICIES = 20
_ZONES = 1000
_GROUPS = 2000
_MEMBERSHIP_EVENTS = 200
_VERIFY_EVENTS = 50
_VERIFY_LOOKBACK = timedelta(minutes=30)
_METHODS = 10
_PASSWORD_CAUSES = frozenset({"invalid_credentials", "locked_out", "password_expired"})


@dataclass(frozen=True)
class RuleRef:
    rule_id: str | None
    policy_id: str | None
    policy_name: str | None


@dataclass
class DenialGroup:
    events: list[Mapping[str, Any]]
    """Newest first; `events[0]` is the one evaluated."""
    rule_ids: tuple[str, ...]
    app: Mapping[str, Any] | None

    @property
    def event(self) -> Mapping[str, Any]:
        return self.events[0]

    def refs(self) -> list[RuleRef]:
        out: list[RuleRef] = []
        for t in pe.targets(self.event):
            kind = t.get("type")
            detail = pe.as_dict(t.get("detailEntry"))
            if kind == "Rule":
                out.append(
                    RuleRef(
                        _s(t.get("id")) or None,
                        _s(detail.get("policyId")) or None,
                        _s(detail.get("policyName")) or None,
                    )
                )
            elif isinstance(kind, str) and "Policy" in kind and _s(t.get("id")):
                out.append(RuleRef(None, _s(t.get("id")), _s(t.get("displayName")) or None))
        return out


def denial_groups(events: Sequence[Mapping[str, Any]]) -> list[DenialGroup]:
    """DENYs grouped by the rules they name and their app, newest group first."""
    groups: dict[tuple[tuple[str, ...], str | None], DenialGroup] = {}
    for e in events:  # newest first
        ts = pe.targets(e)
        rules = tuple(sorted(_s(t.get("id")) for t in ts if t.get("type") == "Rule"))
        app = next((t for t in ts if t.get("type") == "AppInstance"), None)
        key = (rules, _s(app.get("id")) if app else None)
        if key not in groups:
            groups[key] = DenialGroup([], rules, app)
        groups[key].events.append(e)
    return list(groups.values())


@dataclass
class _Store:
    """Results of the waves, and why any lookup is missing."""

    skipped: dict[str, str] = field(default_factory=dict[str, str])

    def missing(self, what: str, reason: str) -> pe.Missing:
        self.skipped.setdefault(what, reason)
        return pe.Missing(reason)


async def _guard(store: _Store, what: str, job: Callable[[], Awaitable[Any]]) -> Any:
    """`job()`, or `Missing` with the reason any lookup failure gives."""
    try:
        return await job()
    except Unavailable as e:
        return store.missing(what, f"the service app needs {e.needs}")
    except (UpstreamError, PaginationError, RateLimited) as e:
        return store.missing(what, str(e))
    except InvalidArguments:
        return store.missing(what, "an ID from the event isn't one this server sends to Okta")
    except Exception as e:
        log_internal(_log, f"diagnostics login-failures {what}", e)
        return store.missing(what, "internal error; the server log has the details")


async def evaluate(
    ctx: Context,
    user: Mapping[str, Any],
    deny_events: Sequence[Mapping[str, Any]],
    causes: Mapping[str, int],
    enrollments: Callable[[], Awaitable[Sequence[Mapping[str, Any]] | pe.Missing]],
    now: datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, str]]:
    """(per-denial evaluations, the password policy section or None, skipped lookups).
    `enrollments` waits for the user's enrollments, which the slice-1 follow-up reads: wave 1
    runs alongside it, and only wave 2 waits."""
    uid = cast(str, user["id"])
    store = _Store()
    groups = denial_groups(deny_events)
    chosen = groups[:MAX_DENIALS]
    refs = [r for g in chosen for r in g.refs()]
    policy_ids = sorted({r.policy_id for r in refs if r.policy_id})
    need_scan = any(r.rule_id and not r.policy_id for r in refs)
    need_password = (
        bool(causes.keys() & _PASSWORD_CAUSES) or user.get("status") == "PASSWORD_EXPIRED"
    )
    if not chosen and not need_password:
        return [], None, {}
    times = [t for g in chosen if (t := pe.time_of(g.event.get("published"))) is not None]
    firsts = [pe.time_of(g.events[-1].get("published")) for g in chosen]
    oldest = min((t for t in firsts if t is not None), default=None)

    policy: dict[str, Any] = {}
    rules: dict[str, Any] = {}
    listed: dict[str, Any] = {}
    shared: dict[str, Any] = {}
    cut: set[str] = set()
    """Lists that had more than their cap: what was read may be incomplete."""

    async def fetch_list(
        what: str,
        key: str,
        operation: str,
        path: Mapping[str, str] | None,
        params: Mapping[str, str] | None,
        cap: int,
    ) -> Any:
        async def job() -> list[Any]:
            items, more = await ctx.items(operation, path, params, mode="link", max_items=cap)
            if more:
                cut.add(key)
            return items

        return await _guard(store, what, job)

    async def get_policy(pid: str) -> None:
        if not _POLICY_ID.fullmatch(pid):
            policy[pid] = store.missing("policy", "a policy ID on the event isn't one")
            return
        policy[pid] = await _guard(store, "policy", lambda: ctx.get("getPolicy", {"policyId": pid}))

    async def get_rules(pid: str) -> None:
        if not _POLICY_ID.fullmatch(pid):
            rules[pid] = store.missing("policy rules", "a policy ID on the event isn't one")
            return
        rules[pid] = await fetch_list(
            "policy rules",
            f"rules:{pid}",
            "listPolicyRules",
            {"policyId": pid},
            None,
            _RULES_PER_POLICY,
        )

    async def list_type(kind: str) -> None:
        listed[kind] = await fetch_list(
            f"{kind} policies",
            f"policies:{kind}",
            "listPolicies",
            None,
            {"type": kind},
            _POLICIES_PER_TYPE,
        )

    async def zones() -> None:
        shared["zones"] = await fetch_list(
            "network zones", "zones", "listNetworkZones", None, None, _ZONES
        )

    async def user_groups() -> None:
        shared["groups"] = await fetch_list(
            "user groups", "groups", "listUserGroups", {"id": uid}, None, _GROUPS
        )

    async def membership() -> None:
        if oldest is None:
            shared["membership"] = []
            return
        params = {
            "filter": f'eventType sw "group.user_membership." and target.id eq "{uid}"',
            "since": _iso(oldest),
            "sortOrder": "DESCENDING",
            "limit": str(_MEMBERSHIP_EVENTS + 1),
        }
        shared["membership"] = await fetch_list(
            "group membership changes",
            "membership",
            "listLogEvents",
            None,
            params,
            _MEMBERSHIP_EVENTS,
        )

    async def authenticators() -> None:
        shared["authenticators"] = await fetch_list(
            "authenticators", "authenticators", "listAuthenticators", None, None, 100
        )

    async def verify_events() -> None:
        # One query over every denial's lookback window (the System Log's rate limit is low);
        # each denial takes its own window in memory.
        if not times:
            shared["verify"] = pe.Missing("the denials have no timestamp")
            return
        params = {
            "filter": f'eventType eq "user.authentication.verify" and actor.id eq "{uid}"',
            "since": _iso(min(times) - _VERIFY_LOOKBACK),
            "until": _iso(max(times) + timedelta(seconds=1)),
            "sortOrder": "DESCENDING",
            "limit": str(_VERIFY_EVENTS + 1),
        }
        shared["verify"] = await fetch_list(
            "verify events", "verify", "listLogEvents", None, params, _VERIFY_EVENTS
        )

    # Wave 1.
    async with anyio.create_task_group() as tg:
        for pid in policy_ids:
            tg.start_soon(get_policy, pid)
            tg.start_soon(get_rules, pid)
        if need_scan:
            tg.start_soon(list_type, "OKTA_SIGN_ON")
            tg.start_soon(list_type, "MFA_ENROLL")
        if need_password:
            tg.start_soon(list_type, "PASSWORD")
        if chosen:
            tg.start_soon(zones)
            tg.start_soon(membership)
            tg.start_soon(authenticators)
            tg.start_soon(verify_events)
        tg.start_soon(user_groups)
    enrolled = await enrollments()

    # Wave 2: rules of listed sign-on and enrollment policies, to place rules named without
    # their policy (the policy the event names first); authenticator methods.
    scan: list[str] = []
    if need_scan:
        names = {r.policy_name for r in refs if r.rule_id and not r.policy_id}
        for kind in ("OKTA_SIGN_ON", "MFA_ENROLL"):
            found = listed.get(kind)
            if isinstance(found, list):
                items = [pe.as_dict(p) for p in cast(list[Any], found)]
                items.sort(key=lambda p: p.get("name") not in names)
                scan += [_s(p.get("id")) for p in items[:_SCANNED_POLICIES] if _s(p.get("id"))]
                for p in items:
                    # A listed policy stands in for a `getPolicy` that failed for the same ID.
                    if not isinstance(policy.get(_s(p.get("id"))), dict):
                        policy[_s(p.get("id"))] = p
    auths = _by_key(shared.get("authenticators"))
    wanted_keys: set[str] = set()
    for pid in policy_ids:
        for r in _list(rules.get(pid)):
            wanted_keys |= pe.authenticator_ids_named(pe.as_dict(r))
    if not isinstance(enrolled, pe.Missing):
        wanted_keys |= {_s(e.get("key")) for e in enrolled if e.get("status") == "ACTIVE"}
    methods: dict[str, Any] = {}

    async def get_methods(aid: str) -> None:
        methods[aid] = await fetch_list(
            "authenticator methods",
            f"methods:{aid}",
            "listAuthenticatorMethods",
            {"authenticatorId": aid},
            None,
            50,
        )

    async with anyio.create_task_group() as tg:
        for pid in scan:
            if pid not in rules:
                tg.start_soon(get_rules, pid)
        if isinstance(auths, dict):
            ids = [_s(auths[k].get("id")) for k in sorted(wanted_keys) if k in auths]
            for aid in [a for a in ids if _AUTHENTICATOR_ID.fullmatch(a)][:_METHODS]:
                tg.start_soon(get_methods, aid)

    # Facts.
    raw_groups = shared.get("groups")
    if isinstance(raw_groups, list):
        groups_now: frozenset[str] | pe.Missing = frozenset(
            _s(pe.as_dict(g).get("id")) for g in cast(list[Any], raw_groups)
        ) - {""}
    else:
        groups_now = raw_groups if isinstance(raw_groups, pe.Missing) else pe.Missing("not read")
    membership_events = _events(shared.get("membership"))
    if "membership" in cut:
        membership_events = pe.Missing("more group membership changes than were read")
    facts = pe.Facts(
        user=user,
        zones=_by_id(shared.get("zones")),
        groups_now=groups_now,
        groups_complete="groups" not in cut,
        membership_events=membership_events,
        authenticators=auths if isinstance(auths, dict) else (auths or pe.Missing("not read")),
        methods={
            aid: (_by_type(m) if not isinstance(m, pe.Missing) else m) for aid, m in methods.items()
        },
        enrollments=enrolled,
    )
    verify = shared.get("verify", pe.Missing("not read"))
    out = [_evaluate_group(g, verify, policy, rules, scan, facts, cut) for g in chosen]
    if len(groups) > MAX_DENIALS:
        out.append({"not_evaluated": len(groups) - MAX_DENIALS, "note": "older distinct denials"})
    password = None
    if need_password:
        found = listed.get("PASSWORD")
        if isinstance(found, pe.Missing):
            password = {"evaluated": False, "note": found.reason}
        else:
            current = None if isinstance(groups_now, pe.Missing) else groups_now
            password = pe.password_policy(
                [pe.as_dict(p) for p in _list(found)],
                current,
                user,
                causes,
                now,
                complete="groups" not in cut and "policies:PASSWORD" not in cut,
            )
    return out, password, store.skipped


def _evaluate_group(
    group: DenialGroup,
    verify_events: Any,
    policy: Mapping[str, Any],
    rules: Mapping[str, Any],
    scan: Sequence[str],
    facts: pe.Facts,
    cut: set[str],
) -> dict[str, Any]:
    event = group.event
    t = pe.time_of(event.get("published"))
    verify, by = _match_verify(event, _window(verify_events, t))
    denial = pe.Denial(event=event, at=t, verify_events=verify, verify_by=by)
    if isinstance(facts.groups_now, pe.Missing):
        denial.groups_note = facts.groups_now.reason
    elif isinstance(facts.membership_events, pe.Missing):
        denial.groups_at = facts.groups_now
        denial.groups_note = (
            f"group membership as of now ({facts.membership_events.reason}): a group the rule "
            "needs that the user isn't in now is undecided"
        )
        facts = replace(facts, groups_complete=False)
    else:
        denial.groups_at = pe.groups_at(facts.groups_now, facts.membership_events, t)
    resolved: list[tuple[Mapping[str, Any], list[Mapping[str, Any]], Mapping[str, Any]]] = []
    unresolved: list[dict[str, Any]] = []
    for ref in group.refs():
        found = _resolve(ref, policy, rules, scan)
        if isinstance(found, str):
            unresolved.append(
                {
                    k: v
                    for k, v in (
                        ("rule_id", ref.rule_id),
                        ("policy_id", ref.policy_id),
                        ("policy_name", ref.policy_name),
                        ("reason", found),
                    )
                    if v
                }
            )
        else:
            resolved.append(found)
    denial.mfa_policy = next((p for p, _, _ in resolved if p.get("type") == "MFA_ENROLL"), None)
    out: dict[str, Any] = {
        "rule_ids": pe.clip(list(group.rule_ids)),
        "count": len(group.events),
        "first_seen": group.events[-1].get("published"),
        "last_seen": event.get("published"),
    }
    if group.app is not None:
        out["app"] = {
            k: pe.clip(group.app.get(k)) for k in ("id", "displayName") if group.app.get(k)
        }
    out["rules"] = [pe.diagnose_rule(p, rs, r, denial, facts) for p, rs, r in resolved]
    if unresolved:
        out["unresolved"] = unresolved
    if denial.groups_note:
        out["groups_note"] = denial.groups_note
    notes = [
        f"policy {pid} has more rules than were read ({_RULES_PER_POLICY}): candidates and the "
        "rule itself may be missing"
        for pid in sorted({_s(p.get("id")) for p, _, _ in resolved} - {""})
        if f"rules:{pid}" in cut
    ]
    if any(k.startswith("policies:") for k in cut) and any(
        u.get("reason", "").startswith("rule not found") for u in unresolved
    ):
        notes.append(f"more than {_POLICIES_PER_TYPE} policies of a type: not all were searched")
    if "zones" in cut:
        notes.append(f"more than {_ZONES} network zones: a zone not read is undecided")
    if notes:
        out["notes"] = notes
    out["verify_events_matched_by"] = by
    changed: list[dict[str, Any]] = []
    for p, rs, _ in resolved:
        changed += pe.changed_after(t, [p], "policy") + pe.changed_after(t, rs, "rule")
    if not isinstance(facts.zones, pe.Missing):
        named = {
            z
            for _, rs, r in resolved
            for c in (r, *rs)
            for side in ("include", "exclude")
            for z in pe.str_ids(pe.at(c, f"conditions.network.{side}"))
        }
        changed += pe.changed_after(
            t, [facts.zones[z] for z in sorted(named) if z in facts.zones], "zone"
        )
    if changed:
        out["changed_after_event"] = changed[:20]
        out["changed_note"] = (
            "read as of now: these changed after the denial, so may differ from what applied"
        )
    return out


def _resolve(
    ref: RuleRef, policy: Mapping[str, Any], rules: Mapping[str, Any], scan: Sequence[str]
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]], Mapping[str, Any]] | str:
    """(policy, its rules in priority order, the rule), or why not."""

    def ordered(pid: str) -> list[Mapping[str, Any]] | str:
        found = rules.get(pid)
        if isinstance(found, pe.Missing):
            return found.reason
        items = [pe.as_dict(r) for r in _list(found)]
        return sorted(items, key=_priority)

    if ref.policy_id:
        p = policy.get(ref.policy_id)
        if not isinstance(p, dict):
            return p.reason if isinstance(p, pe.Missing) else "policy not read"
        rs = ordered(ref.policy_id)
        if isinstance(rs, str):
            return rs
        if ref.rule_id is None:
            # A policy named without a rule: its context, through its highest-priority rule.
            if not rs:
                return "the policy has no rules"
            return cast(Mapping[str, Any], p), rs, rs[0]
        rule = next((r for r in rs if r.get("id") == ref.rule_id), None)
        return (cast(Mapping[str, Any], p), rs, rule) if rule else "rule not in its policy now"
    reasons: list[str] = []
    for pid in scan:
        rs = ordered(pid)
        if isinstance(rs, str):
            reasons.append(rs)
            continue
        rule = next((r for r in rs if r.get("id") == ref.rule_id), None)
        if rule is not None:
            found = policy.get(pid)
            if not isinstance(found, dict):
                return "the rule's policy wasn't read"
            return cast(Mapping[str, Any], found), rs, rule
    if reasons:
        return reasons[0]
    return "rule not found in the global session or enrollment policies"


def _priority(rule: Mapping[str, Any]) -> int:
    value = rule.get("priority")
    return value if isinstance(value, int) else 10**9


def _match_verify(event: Mapping[str, Any], found: Any) -> tuple[Any, str | None]:
    """Only verify events of the same sign-in count: same transaction, else same root session."""
    if isinstance(found, pe.Missing):
        return found, None
    events = [pe.as_dict(e) for e in _list(found)]
    for by, path in (
        ("transaction.id", "transaction.id"),
        ("rootSessionId", "authenticationContext.rootSessionId"),
    ):
        want = pe.at(event, path)
        if not want:
            continue
        matched = [e for e in events if pe.at(e, path) == want]
        if matched:
            return matched, by
    return [], None


def _window(found: Any, t: datetime | None) -> Any:
    """The verify events in one denial's lookback window."""
    if isinstance(found, pe.Missing):
        return found
    if t is None:
        return pe.Missing("the denial has no timestamp")
    out: list[Any] = []
    for e in _list(found):
        published = pe.time_of(pe.as_dict(e).get("published"))
        if published is not None and t - _VERIFY_LOOKBACK <= published <= t + timedelta(seconds=1):
            out.append(e)
    return out


def _by_id(found: Any) -> Mapping[str, Mapping[str, Any]] | pe.Missing:
    if isinstance(found, pe.Missing) or found is None:
        return found or pe.Missing("not read")
    return {_s(z.get("id")): z for z in (pe.as_dict(x) for x in _list(found)) if _s(z.get("id"))}


def _by_key(found: Any) -> dict[str, dict[str, Any]] | pe.Missing | None:
    if isinstance(found, pe.Missing) or found is None:
        return found
    return {_s(a.get("key")): a for a in (pe.as_dict(x) for x in _list(found)) if _s(a.get("key"))}


def _by_type(found: Any) -> dict[str, dict[str, Any]]:
    return {
        _s(m.get("type")): m for m in (pe.as_dict(x) for x in _list(found)) if _s(m.get("type"))
    }


def _events(found: Any) -> Sequence[Mapping[str, Any]] | pe.Missing:
    if isinstance(found, pe.Missing):
        return found
    return [pe.as_dict(e) for e in _list(found)]


def _list(value: Any) -> list[Any]:
    return cast(list[Any], value) if isinstance(value, list) else []


def _s(value: object) -> str:
    return value if isinstance(value, str) else ""


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
