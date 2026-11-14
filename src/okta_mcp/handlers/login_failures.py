"""`diagnostics login-failures`: triage one user's recent sign-in failures (plan 9.1, slice 1).

Order of work, so the cheap answer comes first and later calls are only made when a cause needs
them:

1. The user (`getUser`, through the resolver's rules) and their state: a locked, suspended or
   deprovisioned account explains every failure by itself.
2. One System Log query for the user's FAILURE and DENY events and account lock/unlock events in
   the window, newest first, capped at `MAX_EVENTS`.
3. Each event gets a cause (`_cause`); events are grouped by cause, and each group carries only
   the attributes that matter for that cause (`_ATTRS`): an IP summary for a wrong password, the
   app for a missing assignment, policy and rule IDs, device and risk signals for a policy DENY.
   No raw event leaves the server.
4. Follow-up checks, in parallel and only for the causes found: app assignment now, enrolled
   authenticators, unknown-device sign-in blocks. Each runs only if the service app holds its
   scopes; otherwise it is listed under `skipped`, and the rest of the result stands.
5. Policy causes the server doesn't evaluate yet are listed under `pending` with the policy and
   rule IDs from the events, for a role that can read policies (later slices of plan 9.1).

Everything Okta sends is data: strings are capped, nothing from an event is used as anything but
a value, and Okta-derived IDs are checked against their ID pattern before they go into a path.
"""

import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import anyio

from okta_mcp.exec.composite import Context, Unavailable
from okta_mcp.exec.resolve import USER_ID
from okta_mcp.okta.client import UpstreamError
from okta_mcp.okta.paginate import PaginationError
from okta_mcp.okta.ratelimit import RateLimited
from okta_mcp.registry.schema import InvalidArguments

DEFAULT_WINDOW = timedelta(hours=24)
MAX_LOOKBACK = timedelta(days=90)
"""Okta keeps System Log events for 90 days."""
MAX_EVENTS = 500
"""Newest events read; the result says when there were more."""
_PAGE = "500"
_TOP = 5
_APPS_CHECKED = 3
_TEXT_MAX = 200
_LOCK_WINDOW = timedelta(minutes=10)
_CLOCK_SKEW = timedelta(minutes=5)
APP_ID = re.compile(r"0oa[A-Za-z0-9]{17}")
TIMESTAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$"
"""The `since`/`until` arg pattern (the registry entry repeats it): UTC, `Z` suffix."""

_LOCK = "user.account.lock"
_UNLOCK = "user.account.unlock"

# Cause → (rank, plain-language meaning). Lower rank is listed first: a cause that blocks every
# sign-in by itself before one that a retry could get past.
CAUSES: Mapping[str, tuple[int, str]] = {
    "locked_out": (1, "the account was locked out after failed attempts"),
    "password_expired": (2, "the password expired and must be changed"),
    "not_assigned": (3, "the user is not assigned to the app"),
    "sign_on_policy_deny": (4, "a sign-on or authentication policy denied access"),
    "other_policy_deny": (5, "another policy denied the request"),
    "ip_or_threat_block": (6, "the request's IP or network was blocked"),
    "idp_failure": (7, "sign-in through an external identity provider failed"),
    "mfa_failed": (8, "an authenticator (MFA) verification failed"),
    "mfa_abandoned": (9, "an authenticator challenge was abandoned or not answered"),
    "invalid_credentials": (10, "wrong password or credential"),
    "oauth_token_error": (11, "an app's token request for the user failed"),
    "other": (12, "another failure; see reasons"),
}

# The attributes each cause's group carries ("only the relevant ones").
_ATTRS: Mapping[str, frozenset[str]] = {
    "locked_out": frozenset({"ips"}),
    "password_expired": frozenset(),
    "not_assigned": frozenset({"apps"}),
    "sign_on_policy_deny": frozenset(
        {"policies", "apps", "ips", "devices", "user_agents", "risk", "behaviors"}
    ),
    "other_policy_deny": frozenset({"policies", "apps", "ips", "devices", "risk"}),
    "ip_or_threat_block": frozenset({"ips"}),
    "idp_failure": frozenset({"idps", "apps"}),
    "mfa_failed": frozenset({"credential_types", "ips", "user_agents"}),
    "mfa_abandoned": frozenset({"credential_types", "user_agents"}),
    "invalid_credentials": frozenset({"credential_types", "ips"}),
    "oauth_token_error": frozenset({"clients", "apps"}),
    "other": frozenset({"apps", "ips"}),
}

_STATUS_NOTES: Mapping[str, str] = {
    "LOCKED_OUT": "locked out: unlock the account, or wait for the lockout to expire",
    "SUSPENDED": "suspended by an admin: no sign-in until unsuspended",
    "DEPROVISIONED": "deactivated: no sign-in until reactivated",
    "PASSWORD_EXPIRED": "password expired: the user must change it at the next sign-in",
    "RECOVERY": "a password reset is pending: the user must finish it",
    "PROVISIONED": "activation pending: the user hasn't finished activating the account",
    "STAGED": "staged: the account hasn't been activated",
}

# Okta's benign handshake errors on token requests: the client retries; not a failure.
_BENIGN_REASONS = frozenset({"use_dpop_nonce"})

_DEVICE_FIELDS = (
    "os_platform",
    "os_version",
    "managed",
    "registered",
    "disk_encryption_type",
    "screen_lock_type",
    "secure_hardware_present",
    "jailbreak",
)
_BEHAVIOR = re.compile(r"([A-Za-z][A-Za-z0-9 _-]{0,60})=POSITIVE")
_RISK_LEVEL = re.compile(r"level=([A-Z]+)")


def _now() -> datetime:
    return datetime.now(UTC)


async def run(ctx: Context, args: Mapping[str, Any]) -> dict[str, Any]:
    now = _now()
    since, until = _window(args, now)
    user = await ctx.user("user", args["user"])
    uid = user.get("id")
    if not isinstance(uid, str) or not USER_ID.fullmatch(uid):
        raise RuntimeError("the resolver returned a user without a valid ID")
    events, more = await ctx.items(
        "listLogEvents",
        params=_log_params(uid, since, until),
        mode="link",
        max_items=MAX_EVENTS,
    )
    about = [e for e in (_event(x) for x in events) if e is not None and _about(e, uid)]
    groups = _group(about)
    result: dict[str, Any] = {
        "user": _user(user),
        "window": {
            "since": _iso(since),
            "until": _iso(until) if until else None,
            "events_read": len(events),
            "events_about_user": len(about),
            "truncated": more,
        },
    }
    checks: list[dict[str, Any]] = [_status_check(user)]
    skipped: list[dict[str, str]] = []
    await _follow_ups(ctx, uid, user, groups, checks, skipped)
    result["causes"] = [g.render() for g in sorted(groups.values(), key=_order)]
    result["checks"] = checks
    if pending := _pending(groups):
        result["pending"] = pending
    if skipped:
        result["skipped"] = skipped
    result["headline"] = _headline(user, groups)
    result["notes"] = [
        "Attributes come from the events, as recorded when they happened; checks read state as "
        "it is now.",
        "IDs (policy, rule, app, device) are for a role that can look them up in detail.",
    ]
    return result


# --- arguments ---------------------------------------------------------------------------


def _parse(arg: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise InvalidArguments(f"arg {arg!r} must be a string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidArguments(f"arg {arg!r} is not a valid UTC timestamp") from None


def _window(args: Mapping[str, Any], now: datetime) -> tuple[datetime, datetime | None]:
    until = _parse("until", args["until"]) if "until" in args else None
    if until is not None and until > now + _CLOCK_SKEW:
        raise InvalidArguments("arg 'until' is in the future")
    end = until or now
    since = _parse("since", args["since"]) if "since" in args else end - DEFAULT_WINDOW
    if since >= end:
        raise InvalidArguments("arg 'since' must be before 'until' (or now)")
    if since < now - MAX_LOOKBACK:
        raise InvalidArguments("arg 'since' is more than 90 days ago (System Log retention)")
    return since, until


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _log_params(uid: str, since: datetime, until: datetime | None) -> dict[str, str]:
    # `uid` matched USER_ID, so it can't break out of the quoted value.
    who = f'(actor.id eq "{uid}" or target.id eq "{uid}")'
    what = (
        '(outcome.result eq "FAILURE" or outcome.result eq "DENY" '
        f'or eventType sw "{_LOCK}" or eventType sw "{_UNLOCK}")'
    )
    params = {
        "filter": f"{who} and {what}",
        "since": _iso(since),
        "sortOrder": "DESCENDING",
        "limit": _PAGE,
    }
    if until is not None:
        params["until"] = _iso(until)
    return params


# --- events ------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Event:
    raw: Mapping[str, Any]
    event_type: str
    result: str
    reason: str
    published: datetime | None


def _event(raw: object) -> _Event | None:
    if not isinstance(raw, dict):
        return None
    e = cast(dict[str, Any], raw)
    event_type = _str(e.get("eventType"))
    if not event_type:
        return None
    return _Event(
        e,
        event_type,
        _str(_at(e, "outcome.result")),
        _str(_at(e, "outcome.reason")),
        _time(e.get("published")),
    )


def _about(e: _Event, uid: str) -> bool:
    """The user acted (a sign-in), or is the subject of a token request or of a lock: not an
    admin's failed action on the account, whose IP and device would be the admin's."""
    if _at(e.raw, "actor.id") == uid:
        return True
    targeted = any(t.get("id") == uid and t.get("type") == "User" for t in _targets(e.raw))
    return targeted and (
        e.event_type.startswith("app.oauth2.")
        or e.event_type.startswith(("user.account.lock", _UNLOCK))
    )


def _cause(e: _Event) -> str | None:
    """The cause of one event, or None for an event that is context (lock, unlock) or benign."""
    t, reason, low = e.event_type, e.reason, e.reason.lower()
    if t.startswith(_UNLOCK):
        return None
    if t.startswith("app.oauth2.") and reason in _BENIGN_REASONS:
        return None
    if t.startswith(_LOCK) or "LOCKED_OUT" in reason:
        return "locked_out"
    if "PASSWORD_EXPIRED" in reason or "password expired" in low:
        return "password_expired"
    if "not assigned" in low or t == "app.generic.unauth_app_access_attempt":
        return "not_assigned"
    if t == "policy.evaluate_sign_on" and e.result == "DENY":
        return "sign_on_policy_deny"
    if "threat" in low or "blocked" in low or t.startswith("security.threat"):
        return "ip_or_threat_block"
    if t.startswith("policy.") and e.result == "DENY":
        return "other_policy_deny"
    if (
        "auth_via_idp" in t.lower()
        or "auth_via_social" in t
        or t.startswith("user.authentication.auth_via_inbound")
    ):
        return "idp_failure"
    if "abandoned" in low or "unanswered" in low:
        return "mfa_abandoned"
    if t.startswith("app.oauth2."):
        return "oauth_token_error"
    credential = _str(_at(e.raw, "authenticationContext.credentialType")).upper()
    if t == "user.authentication.auth_via_mfa" or (
        t == "user.authentication.verify" and credential not in ("", "PASSWORD")
    ):
        return "mfa_failed"
    if "INVALID_CREDENTIALS" in reason or "VERIFICATION_ERROR" in reason:
        return "mfa_failed" if credential not in ("", "PASSWORD") else "invalid_credentials"
    return "other"


@dataclass
class _Group:
    cause: str
    events: list[_Event] = field(default_factory=list[_Event])
    locks_after: int = 0
    unlocked_after_last_lock: bool = False

    def render(self) -> dict[str, Any]:
        meaning = CAUSES[self.cause][1]
        times = [e.published for e in self.events if e.published is not None]
        out: dict[str, Any] = {
            "cause": self.cause,
            "meaning": meaning,
            "count": len(self.events),
            "first_seen": _iso(min(times)) if times else None,
            "last_seen": _iso(max(times)) if times else None,
            "event_types": _top(e.event_type for e in self.events),
            "reasons": _top(_cap(e.reason) for e in self.events if e.reason),
        }
        if self.locks_after:
            out["followed_by_lock"] = self.locks_after
        if self.unlocked_after_last_lock:
            out["unlocked_after_last_lock"] = True
        for name in sorted(_ATTRS[self.cause]):
            if value := _EXTRACT[name](self.events):
                out[name] = value
        return out


def _group(events: list[_Event]) -> dict[str, _Group]:
    groups: dict[str, _Group] = {}
    locks = [e.published for e in events if e.event_type.startswith(_LOCK) and e.published]
    unlocks = [e.published for e in events if e.event_type.startswith(_UNLOCK) and e.published]
    for e in events:
        cause = _cause(e)
        if cause is None:
            continue
        group = groups.setdefault(cause, _Group(cause))
        group.events.append(e)
        if cause in ("invalid_credentials", "mfa_failed") and e.published is not None:
            t = e.published
            if any(timedelta(0) <= lock - t <= _LOCK_WINDOW for lock in locks):
                group.locks_after += 1
    if "locked_out" in groups and locks and unlocks and max(unlocks) > max(locks):
        groups["locked_out"].unlocked_after_last_lock = True
    return groups


def _order(g: _Group) -> tuple[int, float]:
    last = max((e.published for e in g.events if e.published), default=None)
    return CAUSES[g.cause][0], -(last.timestamp() if last else 0)


# --- attribute extraction ----------------------------------------------------------------


def _ips(events: list[_Event]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    first: dict[str, Mapping[str, Any]] = {}
    for e in events:
        ip = _str(_at(e.raw, "client.ipAddress"))
        if ip:
            counts[ip] += 1
            first.setdefault(ip, e.raw)
    out: list[dict[str, Any]] = []
    for ip, n in counts.most_common(_TOP):
        raw = first[ip]
        row: dict[str, Any] = {"ip": _cap(ip), "count": n}
        for key, path in (
            ("city", "client.geographicalContext.city"),
            ("state", "client.geographicalContext.state"),
            ("country", "client.geographicalContext.country"),
            ("zone", "client.zone"),
            ("proxy", "securityContext.isProxy"),
            ("asn", "securityContext.asNumber"),
            ("as_org", "securityContext.asOrg"),
            ("isp", "securityContext.isp"),
        ):
            value = _scalar(_at(raw, path))
            if value not in (None, "", "null"):
                row[key] = value
        out.append(row)
    return out


def _apps(events: list[_Event]) -> list[dict[str, Any]]:
    return _target_rows(events, lambda t: t == "AppInstance", ("signOnModeEvaluationResult",))


def _idps(events: list[_Event]) -> list[dict[str, Any]]:
    return _target_rows(events, lambda t: "IdentityProvider" in t or t == "IdP", ())


def _policies(events: list[_Event]) -> list[dict[str, Any]]:
    """One row per distinct rule (or policy) named on the events: IDs and names, and the type
    of policy a rule belongs to when the event says (an authentication policy rule carries its
    policy ID; global session and enrollment policy rules don't)."""
    counts: Counter[tuple[str | None, str | None]] = Counter()
    rows: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    for e in events:
        for t in _targets(e.raw):
            kind = _str(t.get("type"))
            if kind != "Rule" and "Policy" not in kind:
                continue
            detail = t.get("detailEntry")
            detail = cast(dict[str, Any], detail) if isinstance(detail, dict) else {}
            if kind == "Rule":
                policy_id = _str(detail.get("policyId")) or None
                key = (policy_id, _str(t.get("id")) or None)
                row = {
                    "rule_id": key[1],
                    "rule_name": _cap(_str(t.get("displayName"))) or None,
                    "policy_id": policy_id,
                    "policy_name": _cap(_str(detail.get("policyName"))) or None,
                    "policy_kind": (
                        "authentication policy (ACCESS_POLICY)"
                        if policy_id
                        else "global session or authenticator enrollment policy "
                        "(OKTA_SIGN_ON or MFA_ENROLL)"
                    ),
                }
            else:
                key = (_str(t.get("id")) or None, None)
                row = {
                    "policy_id": key[0],
                    "policy_name": _cap(_str(t.get("displayName"))) or None,
                    "policy_kind": _cap(kind),
                }
            counts[key] += 1
            rows.setdefault(key, {k: v for k, v in row.items() if v is not None})
    return [rows[k] | {"count": n} for k, n in counts.most_common()]


def _devices(events: list[_Event]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    rows: dict[str, dict[str, Any]] = {}
    for e in events:
        row: dict[str, Any] = {}
        for t in _targets(e.raw):
            if t.get("type") == "UDDevice":
                row["id"] = _cap(_str(t.get("id"))) or None
                row["name"] = _cap(_str(t.get("displayName"))) or None
                break
        device = e.raw.get("device")
        if isinstance(device, dict):
            d = cast(dict[str, Any], device)
            row.setdefault("id", _cap(_str(d.get("id"))) or None)
            row.setdefault("name", _cap(_str(d.get("name"))) or None)
            for name in _DEVICE_FIELDS:
                value = _scalar(d.get(name))
                if value is not None:
                    row[name] = value
            integrator = d.get("device_integrator")
            if "genericError" in (integrator if isinstance(integrator, str) else repr(integrator)):
                # A device integrator (osquery, EDR) returned an error instead of a signal: it
                # fails any assurance check that reads it.
                row["integrator_error"] = True
        row = {k: v for k, v in row.items() if v is not None}
        if not row:
            continue
        key = str(sorted(row.items()))
        counts[key] += 1
        rows.setdefault(key, row)
    return [rows[k] | {"count": n} for k, n in counts.most_common(_TOP)]


def _user_agents(events: list[_Event]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for e in events:
        os_ = _cap(_str(_at(e.raw, "client.userAgent.os")))
        browser = _cap(_str(_at(e.raw, "client.userAgent.browser")))
        if os_ or browser:
            counts[(os_, browser)] += 1
    return [
        {k: v for k, v in (("os", o), ("browser", b), ("count", n)) if v}
        for (o, b), n in counts.most_common(_TOP)
    ]


def _credential_types(events: list[_Event]) -> dict[str, int]:
    return _top(
        _cap(c) for e in events if (c := _str(_at(e.raw, "authenticationContext.credentialType")))
    )


def _risk(events: list[_Event]) -> dict[str, int]:
    levels: list[str] = []
    for e in events:
        level = _str(_at(e.raw, "securityContext.risk.level"))
        if not level:
            match = _RISK_LEVEL.search(_str(_at(e.raw, "debugContext.debugData.risk")))
            level = match[1] if match else ""
        if level:
            levels.append(_cap(level))
    return _top(levels)


def _behaviors(events: list[_Event]) -> dict[str, int]:
    """Behavior detections that were positive (`New Device`, `New Geo-Location`, …)."""
    found: list[str] = []
    for e in events:
        text = _str(_at(e.raw, "debugContext.debugData.behaviors"))
        found.extend(m.strip() for m in _BEHAVIOR.findall(text))
    return _top(_cap(f) for f in found)


def _clients(events: list[_Event]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for e in events:
        if e.event_type.startswith("app.oauth2."):
            key = (_cap(_str(_at(e.raw, "actor.id"))), _cap(_str(_at(e.raw, "actor.displayName"))))
            if any(key):
                counts[key] += 1
    return [
        {k: v for k, v in (("client_id", i), ("name", n), ("count", c)) if v}
        for (i, n), c in counts.most_common(_TOP)
    ]


_EXTRACT: Mapping[str, Callable[[list[_Event]], Any]] = {
    "ips": _ips,
    "apps": _apps,
    "idps": _idps,
    "policies": _policies,
    "devices": _devices,
    "user_agents": _user_agents,
    "credential_types": _credential_types,
    "risk": _risk,
    "behaviors": _behaviors,
    "clients": _clients,
}


def _target_rows(
    events: list[_Event], kind: Callable[[str], bool], details: tuple[str, ...]
) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    rows: dict[str, dict[str, Any]] = {}
    for e in events:
        for t in _targets(e.raw):
            if not kind(_str(t.get("type"))):
                continue
            target_id = _cap(_str(t.get("id")))
            if not target_id:
                continue
            counts[target_id] += 1
            if target_id not in rows:
                row: dict[str, Any] = {"id": target_id}
                if name := _cap(_str(t.get("displayName"))):
                    row["name"] = name
                detail = t.get("detailEntry")
                if isinstance(detail, dict):
                    for key in details:
                        if value := _cap(_str(cast(dict[str, Any], detail).get(key))):
                            row[key] = value
                rows[target_id] = row
    return [rows[k] | {"count": n} for k, n in counts.most_common(_TOP)]


# --- user state and follow-ups -----------------------------------------------------------


def _user(user: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"id": user.get("id")}
    for key, path in (
        ("login", "profile.login"),
        ("status", "status"),
        ("last_login", "lastLogin"),
        ("password_changed", "passwordChanged"),
        ("status_changed", "statusChanged"),
        ("credentials_provider", "credentials.provider.type"),
    ):
        value = _at(user, path)
        if isinstance(value, str) and value:
            out[key] = _cap(value)
    return out


def _status_check(user: Mapping[str, Any]) -> dict[str, Any]:
    status = _str(user.get("status"))
    row: dict[str, Any] = {"check": "user_status", "actual": _cap(status) or None}
    row["pass"] = status == "ACTIVE"
    if note := _STATUS_NOTES.get(status):
        row["note"] = note
    provider = _str(_at(user, "credentials.provider.type"))
    if provider and provider != "OKTA":
        row["provider_note"] = (
            f"the password is checked by {_cap(provider)}, not Okta: a wrong-password failure "
            "or an expired password may need fixing there"
        )
    return row


async def _follow_ups(
    ctx: Context,
    uid: str,
    user: Mapping[str, Any],
    groups: Mapping[str, _Group],
    checks: list[dict[str, Any]],
    skipped: list[dict[str, str]],
) -> None:
    """The checks the causes call for, at the same time. Each appends its own rows; a failure
    of one is reported in `skipped` and doesn't stop the others."""
    jobs: list[tuple[str, str, Callable[[], Any]]] = []
    if "not_assigned" in groups:
        apps = [a for a in _apps(groups["not_assigned"].events) if APP_ID.fullmatch(a["id"])]
        for app in apps[:_APPS_CHECKED]:
            jobs.append(
                ("app_assignment", "getApplicationUser", _assignment(ctx, uid, app, checks))
            )
    if groups.keys() & {"mfa_failed", "mfa_abandoned", "sign_on_policy_deny"}:
        jobs.append(
            (
                "authenticator_enrollment",
                "listAuthenticatorEnrollments",
                _enrollments(ctx, uid, groups, checks),
            )
        )
    if "locked_out" in groups or user.get("status") == "LOCKED_OUT":
        jobs.append(("sign_in_blocks", "listUserBlocks", _blocks(ctx, uid, checks)))

    async def one(check: str, operation: str, job: Callable[[], Any]) -> None:
        if not ctx.available(operation):
            skipped.append(
                {"check": check, "reason": f"the service app needs {ctx.needs(operation)}"}
            )
            return
        try:
            await job()
        except Unavailable:
            skipped.append(
                {"check": check, "reason": f"the service app needs {ctx.needs(operation)}"}
            )
        except (UpstreamError, PaginationError, RateLimited) as e:
            skipped.append({"check": check, "reason": f"Okta request failed: {e}"})

    async with anyio.create_task_group() as tg:
        for check, operation, job in jobs:
            tg.start_soon(one, check, operation, job)


def _assignment(
    ctx: Context, uid: str, app: Mapping[str, Any], checks: list[dict[str, Any]]
) -> Callable[[], Any]:
    async def job() -> None:
        row: dict[str, Any] = {"check": "app_assignment", "app_id": app["id"]}
        if "name" in app:
            row["app_name"] = app["name"]
        try:
            await ctx.get("getApplicationUser", {"appId": app["id"], "userId": uid})
        except UpstreamError as e:
            if e.status != 404:
                raise
            row |= {"pass": False, "actual": "not assigned now"}
        else:
            row |= {
                "pass": True,
                "actual": "assigned now",
                "note": "assigned now, so it may have been fixed since the failure",
            }
        checks.append(row)

    return job


def _enrollments(
    ctx: Context, uid: str, groups: Mapping[str, _Group], checks: list[dict[str, Any]]
) -> Callable[[], Any]:
    async def job() -> None:
        body = await ctx.get("listAuthenticatorEnrollments", {"userId": uid})
        items = cast(list[Any], body) if isinstance(body, list) else []
        enrolled = [
            {
                k: _cap(v)
                for k in ("key", "type", "name", "status")
                if isinstance(v := i.get(k), str)
            }
            for i in cast(list[dict[str, Any]], [x for x in items if isinstance(x, dict)])
        ]
        failing = Counter[str]()
        for cause in ("mfa_failed", "mfa_abandoned"):
            if cause in groups:
                failing.update(_credential_types(groups[cause].events))
        row: dict[str, Any] = {"check": "authenticator_enrollment", "enrolled": enrolled}
        active = [e for e in enrolled if e.get("status") == "ACTIVE"]
        row["pass"] = bool(active)
        if not active:
            row["note"] = "no active authenticator enrollment: the user may need to enroll one"
        if failing:
            row["failing_credential_types"] = dict(failing.most_common(_TOP))
        checks.append(row)

    return job


def _blocks(ctx: Context, uid: str, checks: list[dict[str, Any]]) -> Callable[[], Any]:
    async def job() -> None:
        body = await ctx.get("listUserBlocks", {"id": uid})
        items = cast(list[Any], body) if isinstance(body, list) else []
        blocks = [
            {k: _cap(v) for k in ("type", "appliesTo") if isinstance(v := i.get(k), str)}
            for i in cast(list[dict[str, Any]], [x for x in items if isinstance(x, dict)])
        ]
        checks.append(
            {
                "check": "sign_in_blocks",
                "pass": not blocks,
                "actual": blocks,
                **(
                    {"note": "blocked from unknown devices only; a known device can still sign in"}
                    if any(b.get("appliesTo") == "UNKNOWN_DEVICES" for b in blocks)
                    else {}
                ),
            }
        )

    return job


def _pending(groups: Mapping[str, _Group]) -> list[dict[str, Any]]:
    """Checks a later slice will make, with what the events name, so a role that can read
    policies knows where to look."""
    out: list[dict[str, Any]] = []
    for cause in ("sign_on_policy_deny", "other_policy_deny"):
        if cause in groups:
            out.append(
                {
                    "check": "policy_evaluation",
                    "cause": cause,
                    "policies": _policies(groups[cause].events),
                    "note": "not evaluated by this server yet: read the named rules' conditions",
                }
            )
    if groups.keys() & {"invalid_credentials", "locked_out", "password_expired"}:
        out.append(
            {
                "check": "password_policy",
                "note": "not evaluated by this server yet: lockout and expiry settings of the "
                "user's password policy",
            }
        )
    return out


def _headline(user: Mapping[str, Any], groups: Mapping[str, _Group]) -> str:
    status = _str(user.get("status"))
    if status in _STATUS_NOTES and status != "PASSWORD_EXPIRED":
        return f"Account is {status}: {_STATUS_NOTES[status]}."
    if not groups:
        return "No failed sign-ins for this user in the window."
    first = min(groups.values(), key=_order)
    count = len(first.events)
    more = len(groups) - 1
    tail = f"; {more} other cause{'s' if more != 1 else ''}" if more else ""
    return (
        f"Most likely: {CAUSES[first.cause][1]} ({count} event{'s' if count != 1 else ''}){tail}."
    )


# --- small helpers -----------------------------------------------------------------------


def _at(value: Any, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = cast(dict[str, Any], value).get(key)
    return value


def _targets(e: Mapping[str, Any]) -> list[dict[str, Any]]:
    targets = e.get("target")
    if not isinstance(targets, list):
        return []
    return [cast(dict[str, Any], t) for t in cast(list[Any], targets) if isinstance(t, dict)]


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _cap(text: str) -> str:
    return text if len(text) <= _TEXT_MAX else text[: _TEXT_MAX - 1] + "…"


def _scalar(value: object) -> str | int | float | bool | None:
    if isinstance(value, str):
        return _cap(value)
    if isinstance(value, bool | int | float):
        return value
    return None


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo is not None else t.replace(tzinfo=UTC)


def _top(values: Iterable[str]) -> dict[str, int]:
    return dict(Counter(v for v in values if v).most_common(_TOP))
