"""Policy rule evaluation for `diagnostics login-failures` (plan 9.1, slice 2). Pure: no I/O.

Given a DENY event and what the handler fetched (policies, rules, zones, the user's groups and
enrollments, authenticators), say why each rule the event names did or didn't let the user in.
Every check is a row `{check, required, actual, pass, note}` where `pass` is True, False or None
(the server can't decide: a lookup it couldn't make, a signal the event doesn't carry, Okta
Expression Language). Only failing and undecided rows leave the server; passing ones are counted.

Behavior follows okta-skills `okta-logs` `diagnose_login.py` (reference only, re-implemented):
the rule named on the event is read as of now and evaluated against the signals the event
recorded; a catch-all DENY means no ALLOW rule above it matched, so those rules are the
candidates and the one with the fewest failures is the likely reason. Assumptions it makes are
kept and said in notes: legacy dynamic zones combine their criteria with OR; OS version
expressions aren't evaluated; device assurance is `device_eval`'s (slice 3).
"""

import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

from okta_mcp.handlers.geo import COUNTRIES, US_STATES

Row = dict[str, Any]
CANDIDATES_SHOWN = 5
_TEXT_MAX = 200
_LIST_MAX = 20


@dataclass(frozen=True)
class Missing:
    """A lookup the handler couldn't make; `reason` is safe to return."""

    reason: str


@dataclass
class Facts:
    """What the evaluation reads, fetched once per call. Each lookup is its value or `Missing`."""

    user: Mapping[str, Any]
    zones: Mapping[str, Mapping[str, Any]] | Missing
    groups_now: frozenset[str] | Missing
    groups_complete: bool
    """False when the user's group list was cut: a group not found is then undecided."""
    membership_events: Sequence[Mapping[str, Any]] | Missing
    """`group.user_membership.*` events on the user since the oldest denial, newest first."""
    authenticators: Mapping[str, Mapping[str, Any]] | Missing
    """By authenticator key."""
    methods: Mapping[str, Mapping[str, Mapping[str, Any]] | Missing] = field(
        default_factory=dict[str, Mapping[str, Mapping[str, Any]] | Missing]
    )
    """Authenticator ID → method type → method."""
    enrollments: Sequence[Mapping[str, Any]] | Missing = Missing("not read")
    assurance: Mapping[str, Mapping[str, Any] | Missing] = field(
        default_factory=dict[str, Mapping[str, Any] | Missing]
    )
    """Device assurance policy ID → the policy (slice 3)."""
    posture_checks: Mapping[str, Mapping[str, Any]] | Missing | None = None
    """Posture check variable name → its definition; None when no policy needs one."""


@dataclass
class Denial:
    """One DENY event and what belongs to it."""

    event: Mapping[str, Any]
    at: datetime | None
    verify_events: Sequence[Mapping[str, Any]] | Missing
    verify_by: str | None
    mfa_policy: Mapping[str, Any] | None = None
    groups_at: frozenset[str] | None = None
    groups_note: str | None = None

    @property
    def device(self) -> Mapping[str, Any]:
        device = self.event.get("device")
        return cast(Mapping[str, Any], device) if isinstance(device, dict) else {}


# --- rows ----------------------------------------------------------------------------------


def row(check: str, required: Any, actual: Any, ok: bool | None, note: str | None = None) -> Row:
    out: Row = {"check": check, "required": clip(required), "actual": clip(actual), "pass": ok}
    if note:
        out["note"] = note
    return out


def _bare(r: Row) -> Row:
    return {k: v for k, v in r.items() if k != "pass"}


def any3(oks: Iterable[bool | None]) -> bool | None:
    """Tri-state OR: one True wins; else None if any is None; else False."""
    values = list(oks)
    return True if True in values else (None if None in values else False)


def status(rows: Sequence[Row]) -> str:
    if any(r["pass"] is False for r in rows):
        return "blocked"
    return "undetermined" if any(r["pass"] is None for r in rows) else "would_allow"


def summary(rows: Sequence[Row]) -> dict[str, Any]:
    """Only what isn't a pass: failing and undecided rows, and how many passed."""
    out: dict[str, Any] = {}
    # The list says the verdict, so rows go out without `pass` (a null would be pruned anyway).
    if failing := [_bare(r) for r in rows if r["pass"] is False]:
        out["failing"] = failing
    if undecided := [_bare(r) for r in rows if r["pass"] is None]:
        out["undecided"] = undecided
    out["passed"] = sum(r["pass"] is True for r in rows)
    return out


# --- event helpers -------------------------------------------------------------------------


def at(value: Any, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = cast(dict[str, Any], value).get(key)
    return value


def targets(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = event.get("target")
    if not isinstance(raw, list):
        return []
    return [cast(dict[str, Any], t) for t in cast(list[Any], raw) if isinstance(t, dict)]


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def as_dict(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def as_list(value: object) -> list[Any]:
    return cast(list[Any], value) if isinstance(value, list) else []


def str_ids(value: object) -> list[str]:
    return [v for v in as_list(value) if isinstance(v, str)]


def clip(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _TEXT_MAX else value[: _TEXT_MAX - 1] + "…"
    if isinstance(value, list):
        items = [clip(v) for v in cast(list[Any], value)[:_LIST_MAX]]
        more = len(cast(list[Any], value)) - _LIST_MAX
        return [*items, f"… (+{more})"] if more > 0 else items
    if isinstance(value, dict):
        return {k: clip(v) for k, v in cast(dict[str, Any], value).items()}
    return value


def time_of(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# --- network zones -------------------------------------------------------------------------


def _ip_in(ip: str, entry: Mapping[str, Any]) -> bool | None:
    try:
        address = ipaddress.ip_address(ip)
        value = _str(entry.get("value"))
        if entry.get("type") == "RANGE":
            lo, hi = (ipaddress.ip_address(x.strip()) for x in value.split("-", 1))
            if lo.version != address.version or hi.version != address.version:
                return False
            return int(lo) <= int(address) <= int(hi)
        return address in ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _location_hit(locations: list[Any], event: Mapping[str, Any]) -> bool | None:
    country = _str(at(event, "client.geographicalContext.country"))
    code = COUNTRIES.get(country.lower()) or (country.upper() if len(country) == 2 else None)
    state = _str(at(event, "client.geographicalContext.state")).lower()
    region = US_STATES.get(state) if code == "US" else None
    hits: list[bool | None] = []
    for raw in locations:
        loc = as_dict(raw)
        want = _str(loc.get("country")).upper()
        want_region = _str(loc.get("region")).split("-")[-1].upper()
        if code is None:
            hits.append(None)
        elif want != code:
            hits.append(False)
        elif not want_region:
            hits.append(True)
        else:
            hits.append(None if region is None else region == want_region)
    return any3(hits)


def _asn_hit(asns: list[Any], event: Mapping[str, Any]) -> bool | None:
    asn = at(event, "securityContext.asNumber")
    return None if asn is None else str(asn) in {str(a) for a in asns}


def _service_hit(categories: list[Any], event: Mapping[str, Any]) -> bool | None:
    details = at(event, "securityContext.ipDetails")
    if not isinstance(details, dict):
        return None
    detail = cast(dict[str, Any], details)
    services = [as_dict(s) for s in as_list(detail.get("ipServiceCategories"))]
    operators = [_str(s.get("operator")).upper() for s in services]
    kinds = [_str(s.get("type")).lower() for s in services]
    anonymous = [bool(s.get("isAnonymous")) for s in services]
    tor = "tor" in kinds or any("TOR" in o.split("_") for o in operators)
    known = {
        "ALL_IP_SERVICES": bool(services),
        "ALL_ANONYMIZERS": any(anonymous),
        "ALL_ANONYMIZERS_EXCEPT_TOR": any(
            a and k != "tor" for a, k in zip(anonymous, kinds, strict=True)
        ),
        "ANONYMIZER_TOR": tor,
        "ALL_PROXIES_VPNS": any(k in ("proxy", "vpn") for k in kinds),
    }
    hits: list[bool | None] = []
    for raw in categories:
        category = _str(raw)
        if category in known:
            hits.append(known[category])
        else:
            # A provider-specific category: a match is certain, a miss only with no service at all.
            hit = any(len(o) > 2 and o in category for o in operators)
            hits.append(True if hit else (False if not services else None))
    return any3(hits)


def _criteria(event: Mapping[str, Any], side: Mapping[str, Any]) -> list[bool | None]:
    out: list[bool | None] = []
    if locations := as_list(side.get("locations")):
        out.append(_location_hit(locations, event))
    if asns := as_list(side.get("asns")):
        out.append(_asn_hit(asns, event))
    if categories := as_list(side.get("ipServiceCategories")):
        out.append(_service_hit(categories, event))
    return out


def zone_hit(zone: Mapping[str, Any], event: Mapping[str, Any]) -> bool | None:
    """Is the event's client inside the zone?"""
    if zone.get("status") == "INACTIVE":
        return False  # a policy's inactive zone never matches
    kind = zone.get("type")
    if kind == "IP":
        ip = _str(at(event, "client.ipAddress"))
        gateways = [as_dict(g) for g in as_list(zone.get("gateways"))]
        return any3(_ip_in(ip, g) for g in gateways) if ip else None
    if _str(at(event, "client.zone")) and at(event, "client.zone") == zone.get("name"):
        return True
    if kind == "DYNAMIC_V2":
        include = _criteria(
            event,
            {k: as_dict(zone.get(k)).get("include") for k in ("locations", "asns")}
            | {"ipServiceCategories": as_dict(zone.get("ipServiceCategories")).get("include")},
        )
        exclude = _criteria(
            event,
            {k: as_dict(zone.get(k)).get("exclude") for k in ("locations", "asns")}
            | {"ipServiceCategories": as_dict(zone.get("ipServiceCategories")).get("exclude")},
        )
        if True in exclude:
            return False
        hit = any3(include) if include else None
        return None if hit is None or (hit and None in exclude) else hit
    # Legacy DYNAMIC: location, ASN and proxy criteria as alternatives (assumed OR).
    parts = _criteria(event, {"locations": zone.get("locations"), "asns": zone.get("asns")})
    proxy = zone.get("proxyType")
    if proxy not in (None, "", "null"):
        if proxy == "Any":
            flag = at(event, "securityContext.isProxy")
            parts.append(
                flag if isinstance(flag, bool) else _service_hit(["ALL_IP_SERVICES"], event)
            )
        else:
            wanted = "ANONYMIZER_TOR" if proxy == "Tor" else "ALL_ANONYMIZERS_EXCEPT_TOR"
            parts.append(_service_hit([wanted], event))
    return any3(parts) if parts else None


# --- conditions ----------------------------------------------------------------------------


def _network(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    ip = _str(at(d.event, "client.ipAddress"))
    zone = _str(at(d.event, "client.zone"))
    actual = {
        k: v
        for k, v in (
            ("ip", ip),
            ("zone", zone if zone not in ("", "null") else None),
            ("country", at(d.event, "client.geographicalContext.country")),
            ("state", at(d.event, "client.geographicalContext.state")),
            ("asn", at(d.event, "securityContext.asNumber")),
        )
        if v not in (None, "")
    }
    if cond.get("connection") in (None, "ANYWHERE"):
        return [row("network", "ANYWHERE", actual, True)]
    zones = facts.zones
    rows: list[Row] = []
    for side in ("include", "exclude"):
        ids = str_ids(cond.get(side))
        if not ids:
            continue
        if isinstance(zones, Missing):
            rows.append(row(f"network.{side}", ids, actual, None, zones.reason))
            continue
        found = [zones.get(i) for i in ids]
        hits = [zone_hit(z, d.event) if z is not None else None for z in found]
        ok = (
            any3(hits)
            if side == "include"
            else (False if True in hits else (None if None in hits else True))
        )
        names = [_str(z.get("name")) or i if z else i for z, i in zip(found, ids, strict=True)]
        note = None
        if ok is None:
            note = "a zone couldn't be decided from the event's IP, geo, ASN or IP-service data"
        rows.append(
            row(
                f"network.{side}",
                {
                    "zones": names,
                    "zone_ids": ids,
                    "rule": "in one" if side == "include" else "in none",
                },
                actual,
                ok,
                note,
            )
        )
    return rows


def _people(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    groups, users = as_dict(cond.get("groups")), as_dict(cond.get("users"))
    gi, ge = set(str_ids(groups.get("include"))), set(str_ids(groups.get("exclude")))
    ui, ue = set(str_ids(users.get("include"))), set(str_ids(users.get("exclude")))
    uid = facts.user.get("id")
    member = d.groups_at
    complete = facts.groups_complete

    def in_groups(ids: set[str]) -> bool | None:
        if member is None:
            return None
        if ids & member:
            return True
        return False if complete else None

    rows: list[Row] = []
    if gi or ui:
        by_group = in_groups(gi) if gi else False
        ok = True if uid in ui or by_group else (None if by_group is None else False)
        actual = sorted(member & gi) if member is not None and gi else None
        rows.append(
            row(
                "people.include",
                {"groups": sorted(gi)} | _users_listed(ui, uid),
                {"member_of": actual},
                ok,
                d.groups_note,
            )
        )
    if ge or ue:
        by_group = in_groups(ge) if ge else False
        ok = False if uid in ue or by_group else (None if by_group is None else True)
        actual = sorted(member & ge) if member is not None and ge else None
        rows.append(
            row(
                "people.exclude",
                {"not_groups": sorted(ge)} | _users_listed(ue, uid, prefix="not_"),
                {"member_of": actual},
                ok,
                d.groups_note,
            )
        )
    return rows


def _users_listed(ids: set[str], uid: object, prefix: str = "") -> dict[str, Any]:
    """A rule's user list without the other users' IDs (it can name exempt or break-glass
    accounts): how many, and whether the named user is one (security review, 9.1)."""
    if not ids:
        return {}
    return {f"{prefix}users_listed": len(ids), f"{prefix}named_user_listed": uid in ids}


def _user_type(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    type_id = _str(at(facts.user, "type.id")) or None
    rows: list[Row] = []
    note = "the user's type as of now" if type_id else "the user object carries no type"
    if inc := str_ids(cond.get("include")):
        rows.append(
            row("userType.include", inc, type_id, None if type_id is None else type_id in inc, note)
        )
    if exc := str_ids(cond.get("exclude")):
        rows.append(
            row(
                "userType.exclude",
                {"not": exc},
                type_id,
                None if type_id is None else type_id not in exc,
                note,
            )
        )
    return rows


def _device(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    rows: list[Row] = []
    for name in ("registered", "managed"):
        wanted = cond.get(name)
        if not isinstance(wanted, bool):
            continue
        if not d.device:
            rows.append(
                row(
                    f"device.{name}",
                    wanted,
                    False,
                    not wanted,
                    "the event carries no device: not registered, not managed",
                )
            )
            continue
        actual = d.device.get(name)
        if not isinstance(actual, bool):
            rows.append(row(f"device.{name}", wanted, None, None, "the event's device doesn't say"))
            continue
        rows.append(row(f"device.{name}", wanted, actual, actual == wanted))
    if ids := str_ids(as_dict(cond.get("assurance")).get("include")):
        # Here, not at the top: device_eval builds on this module's rows.
        from okta_mcp.handlers.device_eval import assurance

        rows += assurance(ids, d, facts)
    return rows


_UA_OS = (
    ("mac", "OSX"),
    ("windows", "WINDOWS"),
    ("ios", "IOS"),
    ("iphone", "IOS"),
    ("ipad", "IOS"),
    ("android", "ANDROID"),
    ("chrome", "CHROMEOS"),
    ("linux", "LINUX"),
)
_COND_OS = {"MACOS": "OSX", "MAC": "OSX", "CHROME_OS": "CHROMEOS"}


def _platform(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    os_actual = _str(d.device.get("os_platform")).upper()
    os_actual = _COND_OS.get(os_actual, os_actual)
    if not os_actual:
        agent = _str(at(d.event, "client.userAgent.os")).lower()
        os_actual = next((v for k, v in _UA_OS if k in agent), "")
    kind = {"computer": "DESKTOP", "mobile": "MOBILE"}.get(
        _str(at(d.event, "client.device")).lower()
    )
    actual = {"os": os_actual or None, "type": kind}
    if not os_actual and not kind:
        return [
            row("platform", "platform condition", actual, None, "the event carries no platform")
        ]

    def match(entry: Mapping[str, Any]) -> bool | None:
        want_os = _str(as_dict(entry.get("os")).get("type")).upper() or "ANY"
        want_os = _COND_OS.get(want_os, want_os)
        want_kind = _str(entry.get("type")).upper() or "ANY"
        oks: list[bool | None] = [
            True if want_os == "ANY" else (None if not os_actual else want_os == os_actual),
            True if want_kind == "ANY" else (None if not kind else want_kind == kind),
        ]
        return False if False in oks else (None if None in oks else True)

    rows: list[Row] = []
    for side in ("include", "exclude"):
        entries = [as_dict(e) for e in as_list(cond.get(side))]
        if not entries:
            continue
        hit = any3(match(e) for e in entries)
        ok = hit if side == "include" else (None if hit is None else not hit)
        wanted = [
            f"{_str(as_dict(e.get('os')).get('type')) or 'ANY'}/{_str(e.get('type')) or 'ANY'}"
            for e in entries
        ]
        versioned = any(as_dict(e.get("os")).get("version") for e in entries)
        rows.append(
            row(
                f"platform.{side}",
                wanted,
                actual,
                ok,
                "OS version expressions aren't evaluated" if versioned else None,
            )
        )
    return rows


_RISK_LEVEL = re.compile(r"level=(\w+)")


def event_risk(event: Mapping[str, Any]) -> str | None:
    level = _str(at(event, "securityContext.risk.level"))
    if not level:
        match = _RISK_LEVEL.search(_str(at(event, "debugContext.debugData.risk")))
        level = match[1] if match else ""
    return level.upper() or None


def _risk_score(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    want = _str(cond.get("level")).upper() or "ANY"
    actual = event_risk(d.event)
    if want == "ANY":
        return [row("riskScore.level", "ANY", actual, True)]
    if actual is None:
        return [row("riskScore.level", want, None, None, "the event carries no risk level")]
    return [row("riskScore.level", want, actual, actual == want)]


_BEHAVIOR = re.compile(r"([A-Za-z][A-Za-z0-9 _-]{0,60})=POSITIVE")


def _risk_behaviors(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    wanted = str_ids(cond.get("behaviors"))
    if not wanted:
        return []
    seen = sorted(
        {
            m.strip()
            for m in _BEHAVIOR.findall(_str(at(d.event, "debugContext.debugData.behaviors")))
        }
    )
    return [
        row(
            "risk.behaviors",
            wanted,
            {"detected": seen},
            None,
            "behavior conditions aren't evaluated: compare the rule's with those detected",
        )
    ]


_EL_ATTRIBUTE = re.compile(r"\buser\.(?:profile\.)?([A-Za-z_][A-Za-z0-9_]*)(\()?")


def _el(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    expression = _str(cond.get("condition"))
    names = sorted({m[1] for m in _EL_ATTRIBUTE.finditer(expression) if not m[2]})
    # Attribute names only, never the user's values: this command doesn't grant profile reads.
    return [
        row(
            "elCondition",
            expression,
            {"user_attributes_named": names},
            None,
            "Okta Expression Language isn't evaluated",
        )
    ]


def _app(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    apps = [t for t in targets(d.event) if t.get("type") == "AppInstance"]
    app: dict[str, Any] = apps[0] if apps else {}
    app_id = _str(app.get("id")) or None

    def ids(side: str) -> set[str]:
        return {_str(as_dict(a).get("id")) for a in as_list(cond.get(side))} - {""}

    rows: list[Row] = []
    if inc := ids("include"):
        rows.append(
            row("app.include", sorted(inc), app_id, None if app_id is None else app_id in inc)
        )
    if exc := ids("exclude"):
        rows.append(
            row(
                "app.exclude",
                {"not": sorted(exc)},
                app_id,
                None if app_id is None else app_id not in exc,
            )
        )
    return rows


def _auth_context(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    kind = _str(cond.get("authType")).upper() or "ANY"
    if kind == "ANY":
        return [row("authContext.authType", "ANY", None, True)]
    return [
        row("authContext.authType", kind, None, None, "the authentication type isn't on the event")
    ]


def _identity_provider(cond: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    provider = _str(cond.get("provider")).upper() or "ANY"
    if provider == "ANY":
        return [row("identityProvider", "ANY", None, True)]
    actual = _str(at(d.event, "authenticationContext.authenticationProvider")) or None
    return [
        row(
            "identityProvider",
            {"provider": provider, "idp_ids": str_ids(cond.get("idpIds"))},
            actual,
            None,
            "compare the provider the event names with the rule's",
        )
    ]


_CHECKS: Mapping[str, Callable[[Mapping[str, Any], Denial, Facts], list[Row]]] = {
    "network": _network,
    "people": _people,
    "userType": _user_type,
    "device": _device,
    "platform": _platform,
    "riskScore": _risk_score,
    "risk": _risk_behaviors,
    "elCondition": _el,
    "app": _app,
    "authContext": _auth_context,
    "identityProvider": _identity_provider,
}


def conditions(raw: object, d: Denial, facts: Facts) -> list[Row]:
    """Every condition on a rule; one the server doesn't know is an undecided row."""
    rows: list[Row] = []
    for key, cond in as_dict(raw).items():
        if not cond:
            continue
        check = _CHECKS.get(key)
        if check is not None and isinstance(cond, dict):
            rows += check(cast(dict[str, Any], cond), d, facts)
        else:
            rows.append(row(key, cond, None, None, "condition type isn't evaluated by this server"))
    return rows


# --- verification gate (authentication policy rules) ---------------------------------------

_PROPS = {
    "phishingResistant": "PHISHING_RESISTANT",
    "hardwareProtection": "HARDWARE_PROTECTED",
    "userVerification": "USER_VERIFYING",
    "userPresence": "USER_PRESENCE",
    "deviceBound": "DEVICE_BOUND",
}
# Enrollment `type` values offering each method (enrollments don't list their methods).
_METHOD_TYPE = {
    "PASSWORD": "password",
    "SECURITY_QUESTION": "security_question",
    "SMS": "phone",
    "VOICE": "phone",
    "EMAIL": "email",
    "PUSH": "app",
    "SIGNED_NONCE": "app",
    "OTP": "app",
    "TOTP": "app",
    "DUO": "app",
    "WEBAUTHN": "security_key",
    "IDP": "federated",
    "CERT": "cert",
}


@dataclass(frozen=True)
class _Slot:
    """One requirement met by ONE of its candidates."""

    candidates: tuple[tuple[str, str | None, frozenset[str]], ...]
    types: frozenset[str]
    methods: tuple[str, ...]
    props: frozenset[str]
    excluded: tuple[tuple[str, str | None], ...]


def _required(part: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(f for f in _PROPS if part.get(f) == "REQUIRED")


def _slot(part: Mapping[str, Any], per_method: bool = False) -> _Slot:
    methods = [as_dict(m) for m in as_list(part.get("authenticationMethods"))]
    excluded_raw: object = part.get("excludedAuthenticationMethods")
    # The spec's schema says a list; its examples show one object.
    raw_list: list[Any] = (
        [excluded_raw] if isinstance(excluded_raw, dict) else as_list(excluded_raw)
    )
    excluded = [as_dict(x) for x in raw_list]
    return _Slot(
        tuple(
            (
                _str(m.get("key")),
                _str(m.get("method")) or None,
                _required(m if per_method else part),
            )
            for m in methods
        ),
        frozenset(t.lower() for t in str_ids(part.get("types"))),
        tuple(str_ids(part.get("methods"))),
        _required(part),
        tuple((_str(x.get("key")), _str(x.get("method")) or None) for x in excluded),
    )


def _paths(step: Mapping[str, Any]) -> list[list[_Slot]]:
    own = _slot(step, per_method=True)
    following = [as_dict(n) for n in as_list(step.get("next"))]
    if not following:
        return [[own]]
    return [[own, *rest] for n in following for rest in _paths(n)]


def _options(method: Mapping[str, Any]) -> list[list[_Slot]] | None:
    """Alternatives (OR) of slots, every slot of one needed (AND); None for a type not read."""
    kind = method.get("type")
    if kind == "ASSURANCE":
        constraints = [as_dict(c) for c in as_list(method.get("constraints"))] or [{}]
        return [
            [
                _slot(as_dict(c[p]))
                for p in ("knowledge", "possession")
                if isinstance(c.get(p), dict)
            ]
            for c in constraints
        ]
    if kind == "AUTH_METHOD_CHAIN":
        chains = [as_dict(c) for c in as_list(method.get("chains"))] or [dict(method)]
        return [path for chain in chains for path in _paths(chain)]
    return None


def _verified_props(d: Denial, key: str | None) -> set[str] | None:
    if isinstance(d.verify_events, Missing):
        return None
    for e in d.verify_events:
        for t in targets(e):
            detail = as_dict(t.get("detailEntry"))
            if t.get("type") == "AuthenticatorMethod" and (
                key is None or detail.get("authenticatorKey") == key
            ):
                return set(re.findall(r"[A-Z_]+", _str(detail.get("methodUsedVerifiedProperties"))))
    return None


def _used_keys(d: Denial) -> set[str] | None:
    if isinstance(d.verify_events, Missing) or not d.verify_events:
        return None
    return {
        _str(as_dict(t.get("detailEntry")).get("authenticatorKey"))
        for e in d.verify_events
        for t in targets(e)
        if t.get("type") == "AuthenticatorMethod"
    } - {""}


def _no_verify(d: Denial) -> str:
    if isinstance(d.verify_events, Missing):
        return d.verify_events.reason
    return "no user.authentication.verify event shares this DENY's transaction or root session"


def _prop_rows(props: frozenset[str], key: str | None, d: Denial) -> list[Row]:
    if not props:
        return []
    got = _verified_props(d, key)
    label = f" ({key})" if key else ""
    if got is None:
        return [
            row(
                f"verified properties{label}",
                sorted(_PROPS[f] for f in props),
                None,
                None,
                _no_verify(d),
            )
        ]
    return [
        row(f"verified property {_PROPS[f]}{label}", "REQUIRED", sorted(got), _PROPS[f] in got)
        for f in sorted(props)
    ]


def _enrolled_before(e: Mapping[str, Any], d: Denial) -> bool:
    created = time_of(e.get("created"))
    return not (created and d.at and created > d.at)


def either(groups: list[tuple[str, list[Row]]], check: str, required: str) -> list[Row]:
    """Alternatives: one fully met satisfies; else the closest one's rows."""
    met = next((name for name, rows in groups if status(rows) == "would_allow"), None)
    if met is not None:
        return [row(check, required, f"met by {met}", True)]
    return min(
        (rows for _, rows in groups),
        key=lambda rows: (
            sum(r["pass"] is False for r in rows),
            sum(r["pass"] is None for r in rows),
        ),
    )


def _methods_for(auth_id: str, facts: Facts) -> Mapping[str, Mapping[str, Any]] | Missing:
    return facts.methods.get(auth_id, Missing("authenticator methods weren't read"))


def _candidate_rows(
    key: str, method: str | None, props: frozenset[str], d: Denial, facts: Facts
) -> list[Row]:
    what = f"{key}/{method}" if method else key
    rows: list[Row] = []
    if d.mfa_policy is not None:
        settings = {
            _str(as_dict(a).get("key")): as_dict(a)
            for a in as_list(at(d.mfa_policy, "settings.authenticators"))
        }
        self_enroll = _str(at(settings.get(key, {}), "enroll.self")) or None
        rows.append(
            row(
                f"{what}: enrollment policy allows it",
                "enroll.self is not NOT_ALLOWED",
                self_enroll or "not in the policy",
                self_enroll not in (None, "NOT_ALLOWED"),
                f"enrollment policy {_str(d.mfa_policy.get('id'))}",
            )
        )
    else:
        rows.append(
            row(
                f"{what}: enrollment policy allows it",
                "enroll.self is not NOT_ALLOWED",
                None,
                None,
                "no authenticator enrollment rule is among the event's targets",
            )
        )
    auths = facts.authenticators
    auth = auths.get(key) if not isinstance(auths, Missing) else None
    rows.append(
        row(
            f"{what}: authenticator active org-wide",
            "ACTIVE",
            auth.get("status") if auth else None,
            (auth.get("status") == "ACTIVE") if auth else None,
            auths.reason
            if isinstance(auths, Missing)
            else (None if auth else "not in the org's authenticators"),
        )
    )
    if auth is not None and method:
        methods = _methods_for(_str(auth.get("id")), facts)
        found = methods.get(method) if not isinstance(methods, Missing) else None
        rows.append(
            row(
                f"{what}: method active org-wide",
                "ACTIVE",
                found.get("status") if found else None,
                (found.get("status") == "ACTIVE") if found else None,
                methods.reason
                if isinstance(methods, Missing)
                else (None if found else "method not listed"),
            )
        )
    enrollments = facts.enrollments
    if isinstance(enrollments, Missing):
        rows.append(
            row(f"{what}: user enrolled", "ACTIVE enrollment", None, None, enrollments.reason)
        )
    else:
        mine = [e for e in enrollments if e.get("key") == key]
        active = [e for e in mine if e.get("status") == "ACTIVE"]
        late = bool(active) and not any(_enrolled_before(e, d) for e in active)
        rows.append(
            row(
                f"{what}: user enrolled at the time",
                "ACTIVE enrollment before the event",
                [e.get("status") for e in mine] or "none",
                bool(active) and not late,
                "enrolled only after the event" if late else None,
            )
        )
    if all(r["pass"] is not False for r in rows):
        rows += _prop_rows(props, key, d)
    return rows


def _excluded_row(excluded: tuple[tuple[str, str | None], ...], d: Denial) -> Row:
    used = _used_keys(d)
    required = [f"not {k}" + (f"/{m}" if m else "") for k, m in excluded]
    if used is None:
        return row("excludedAuthenticationMethods", required, None, None, _no_verify(d))
    hit = [(k, m) for k, m in excluded if k in used]
    if any(m is None for _, m in hit):
        return row("excludedAuthenticationMethods", required, sorted(used), False)
    return row(
        "excludedAuthenticationMethods",
        required,
        sorted(used),
        None if hit else True,
        "an excluded authenticator was used; the event doesn't say which method" if hit else None,
    )


def _slot_rows(slot: _Slot, d: Denial, facts: Facts) -> list[Row]:
    if slot.candidates:
        groups = [
            (f"{k}/{m}" if m else k, _candidate_rows(k, m, p, d, facts))
            for k, m, p in slot.candidates
        ]
        return (
            groups[0][1]
            if len(groups) == 1
            else either(groups, "authentication method", "any one listed")
        )
    enrollments = facts.enrollments
    enrolled = (
        {
            _str(e.get("type"))
            for e in enrollments
            if e.get("status") == "ACTIVE" and _enrolled_before(e, d)
        }
        if not isinstance(enrollments, Missing)
        else set[str]()
    )
    rows: list[Row] = []
    allowed: set[str] | None = None
    if slot.types or slot.methods:
        sets: list[set[str]] = []
        if slot.types:
            sets.append(set(slot.types))
        if slot.methods:
            sets.append({_METHOD_TYPE[m] for m in slot.methods if m in _METHOD_TYPE})
        allowed = set[str](sets[0]).intersection(*sets[1:])
        ok: bool | None = None if isinstance(enrollments, Missing) else bool(enrolled & allowed)
        note = enrollments.reason if isinstance(enrollments, Missing) else None
        if ok and slot.methods and not isinstance(enrollments, Missing):
            before = [e for e in enrollments if _enrolled_before(e, d)]
            ok, note = _methods_enabled(slot.methods, allowed, before, facts)
        required = {"type_in": sorted(allowed)} | (
            {"offering": list(slot.methods)} if slot.methods else {}
        )
        rows.append(row("enrolled authenticator", required, sorted(enrolled), ok, note))
    if slot.excluded:
        rows.append(_excluded_row(slot.excluded, d))
    if allowed is None and not slot.props and not slot.excluded:
        return []
    if all(r["pass"] is not False for r in rows):
        rows += _prop_rows(slot.props, None, d)
    return rows


def _methods_enabled(
    wanted: tuple[str, ...],
    allowed: set[str],
    enrollments: Sequence[Mapping[str, Any]],
    facts: Facts,
) -> tuple[bool | None, str | None]:
    want = {m.lower() for m in wanted}
    keys = {
        _str(e.get("key"))
        for e in enrollments
        if e.get("status") == "ACTIVE" and e.get("type") in allowed
    }
    auths = facts.authenticators
    if isinstance(auths, Missing):
        return None, auths.reason
    results: list[bool] = []
    for key in keys:
        auth = auths.get(key)
        if auth is None:
            return None, "an enrolled authenticator isn't in the org's list"
        methods = _methods_for(_str(auth.get("id")), facts)
        if isinstance(methods, Missing):
            return None, methods.reason
        results.append(
            any(m.get("status") == "ACTIVE" and t.lower() in want for t, m in methods.items())
        )
    note = (
        "methods are checked org-wide on the enrolled authenticator; "
        "per-user enablement isn't visible"
    )
    return any(results), note


def gate(rule: Mapping[str, Any], d: Denial, facts: Facts) -> list[Row]:
    """Could this user satisfy the rule's verification method?"""
    method = as_dict(at(rule, "actions.appSignOn.verificationMethod"))
    if not method:
        return []
    options = _options(method)
    if options is None:
        return [
            row(
                "verificationMethod",
                method.get("type"),
                None,
                None,
                "verification method type isn't evaluated",
            )
        ]
    groups: list[tuple[str, list[Row]]] = []
    for n, slots in enumerate(options, 1):
        tag = f"option {n}: " if len(options) > 1 else ""
        rows = [r for slot in slots for r in _slot_rows(slot, d, facts)]
        groups.append((f"option {n}", [{**r, "check": tag + r["check"]} for r in rows]))
    return (
        groups[0][1] if len(groups) == 1 else either(groups, "verificationMethod", "any one option")
    )


def assurance_ids_named(rule: Mapping[str, Any]) -> set[str]:
    """Device assurance policy IDs a rule's device condition names."""
    return set(str_ids(as_dict(at(rule, "conditions.device.assurance")).get("include")))


def authenticator_ids_named(rule: Mapping[str, Any]) -> set[str]:
    """Authenticator keys a rule's verification method names (for fetching their methods)."""
    method = as_dict(at(rule, "actions.appSignOn.verificationMethod"))
    options = _options(method) or []
    keys = {k for slots in options for slot in slots for k, _, _ in slot.candidates}
    return {k for k in keys if k}


# --- rules ---------------------------------------------------------------------------------


def access(rule: Mapping[str, Any]) -> str | None:
    return (
        _str(at(rule, "actions.appSignOn.access"))
        or _str(at(rule, "actions.signon.access"))
        or None
    )


def _brief(rule: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in (
            ("id", rule.get("id")),
            ("name", clip(_str(rule.get("name"))) or None),
            ("priority", rule.get("priority")),
        )
        if v is not None
    }


def diagnose_rule(
    policy: Mapping[str, Any],
    rules: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    d: Denial,
    facts: Facts,
) -> dict[str, Any]:
    """Why one rule the event names did what it did. `rules` in priority order."""
    kind_of_policy = _str(policy.get("type"))
    action = access(rule)
    out: dict[str, Any] = {
        "policy": {
            "id": policy.get("id"),
            "name": clip(_str(policy.get("name"))),
            "type": kind_of_policy,
        },
        "rule": _brief(rule) | ({"access": action} if action else {}),
    }
    catch_all = action == "DENY" and (
        bool(rule["system"]) if "system" in rule else not rule.get("conditions")
    )
    if kind_of_policy == "MFA_ENROLL":
        out["kind"] = "enrollment_policy_context"
        out["note"] = (
            "the enrollment policy that set which authenticators the user may enroll; a cause "
            "only if an authentication rule needs one it doesn't allow"
        )
        out |= summary(conditions(rule.get("conditions"), d, facts))
        return out
    if kind_of_policy not in ("ACCESS_POLICY", "OKTA_SIGN_ON"):
        # Another policy type the event names (IdP routing, entity risk, post-auth session…):
        # its conditions as the event's signals meet them.
        out["kind"] = "rule_context"
        out |= summary(conditions(rule.get("conditions"), d, facts))
        return out
    if kind_of_policy == "OKTA_SIGN_ON" or (action == "DENY" and not catch_all):
        out["kind"] = "explicit_deny_rule" if action == "DENY" else "allow_rule_matched"
        out |= summary(conditions(rule.get("conditions"), d, facts))
        return out
    if catch_all:
        priority = rule.get("priority") if isinstance(rule.get("priority"), int) else 0
        candidates = [
            r
            for r in rules
            if r.get("status") == "ACTIVE"
            and isinstance(r.get("priority"), int)
            and cast(int, r["priority"]) < cast(int, priority)
            and access(r) == "ALLOW"
        ]
    else:
        candidates = [rule]
    evaluated: list[dict[str, Any]] = []
    for c in candidates:
        rows = conditions(c.get("conditions"), d, facts) + gate(c, d, facts)
        evaluated.append({"rule": _brief(c), "status": status(rows)} | summary(rows))
    states = [c["status"] for c in evaluated]
    if not catch_all:
        out["kind"] = (
            "allow_rule_gate_failed"
            if states and states[0] == "blocked"
            else "allow_rule_unexplained"
        )
    elif not states:
        out["kind"] = "no_allow_rule_above_catch_all"
    elif "would_allow" in states:
        out["kind"] = "allow_rule_unexplained"
    elif "undetermined" in states:
        out["kind"] = "undetermined"
    else:
        out["kind"] = "no_allow_rule_matched"
    evaluated.sort(key=lambda c: (len(c.get("failing", [])), len(c.get("undecided", []))))
    if out["kind"] in ("no_allow_rule_matched", "allow_rule_gate_failed"):
        best = evaluated[0]
        out["reason"] = clip(
            f"closest ALLOW rule {best['rule'].get('name') or best['rule'].get('id')!r} failed: "
            + "; ".join(r["check"] for r in best.get("failing", []))
        )
    out["candidates"] = evaluated[:CANDIDATES_SHOWN]
    if len(evaluated) > CANDIDATES_SHOWN:
        out["candidates_total"] = len(evaluated)
    return out


# --- state as of the event -----------------------------------------------------------------


def groups_at(
    now: frozenset[str], changes: Sequence[Mapping[str, Any]], t: datetime | None
) -> frozenset[str]:
    """The user's groups as of `t`: today's, with membership changes after `t` undone.
    `changes` newest first."""
    groups = set(now)
    for e in changes:
        published = time_of(e.get("published"))
        if t is None or published is None or published <= t:
            break
        added = _str(e.get("eventType")).endswith(".add")
        for target in targets(e):
            if "Group" in _str(target.get("type")) and (gid := _str(target.get("id"))):
                (groups.discard if added else groups.add)(gid)
    return frozenset(groups)


def changed_after(
    t: datetime | None, objects: Iterable[Mapping[str, Any]], kind: str
) -> list[dict[str, Any]]:
    """Policies or rules edited after the event: what was read may not be what was in force."""
    out: list[dict[str, Any]] = []
    for obj in objects:
        updated = time_of(obj.get("lastUpdated"))
        if t is not None and updated is not None and updated > t:
            out.append({"type": kind, "id": obj.get("id"), "last_updated": obj.get("lastUpdated")})
    return out


# --- password policy -----------------------------------------------------------------------


def password_policy(
    policies: Sequence[Mapping[str, Any]],
    groups: frozenset[str] | None,
    user: Mapping[str, Any],
    causes: Mapping[str, int],
    now: datetime,
    *,
    complete: bool = True,
) -> dict[str, Any]:
    """The password policy that applies to the user (first active one by priority whose groups
    include theirs and whose provider is theirs), and only the settings the causes concern:
    lockout for wrong passwords and lockouts, age for an expired password."""
    provider = _str(at(user, "credentials.provider.type")) or "OKTA"

    def priority(p: Mapping[str, Any]) -> int:
        value = p.get("priority")
        return value if isinstance(value, int) else 1_000_000

    ordered = sorted((p for p in policies if p.get("status") == "ACTIVE"), key=priority)
    chosen: Mapping[str, Any] | None = None
    undecided = False
    for p in ordered:
        wanted_provider = _str(at(p, "conditions.authProvider.provider")) or "OKTA"
        if wanted_provider != provider:
            continue
        include = set(str_ids(at(p, "conditions.people.groups.include")))
        if groups is None:
            undecided = True
            break
        if include & groups:
            chosen = p
            break
    if chosen is None and not complete and not undecided:
        return {
            "evaluated": False,
            "note": "the user's groups or the password policies were cut short: the policy "
            "that applies can't be picked",
        }
    if chosen is None:
        note = (
            "the user's groups weren't read, so the policy that applies can't be picked"
            if undecided
            else "no active password policy for the user's groups and provider"
        )
        return {"evaluated": False, "note": note}
    out: dict[str, Any] = {
        "policy": {"id": chosen.get("id"), "name": clip(_str(chosen.get("name")))}
    }
    if not complete:
        out["note"] = (
            "the user's groups or the password policies were cut short: a higher-priority "
            "policy may apply instead"
        )
    rows: list[Row] = []
    lockout = as_dict(at(chosen, "settings.password.lockout"))
    if causes.keys() & {"invalid_credentials", "locked_out"}:
        attempts = lockout.get("maxAttempts")
        unlock = lockout.get("autoUnlockMinutes")
        failures = causes.get("invalid_credentials", 0)
        if isinstance(attempts, int) and attempts > 0:
            rows.append(
                row(
                    "password.lockout.maxAttempts",
                    f"fewer than {attempts} failed attempts in a row",
                    {"failures_in_window": failures},
                    False if "locked_out" in causes else (None if failures >= attempts else True),
                    "failures in a row aren't visible: this counts the window's wrong passwords",
                )
            )
        else:
            rows.append(row("password.lockout.maxAttempts", "lockout off", None, True))
        if "locked_out" in causes:
            text = (
                f"unlocks by itself after {unlock} minutes"
                if isinstance(unlock, int) and unlock > 0
                else "doesn't unlock by itself: an admin or self-service unlock is needed"
            )
            rows.append(row("password.lockout.autoUnlockMinutes", "unlock", unlock, None, text))
    if "password_expired" in causes or _str(user.get("status")) == "PASSWORD_EXPIRED":
        age = as_dict(at(chosen, "settings.password.age"))
        max_days = age.get("maxAgeDays")
        changed = time_of(user.get("passwordChanged"))
        if isinstance(max_days, int) and max_days > 0 and changed is not None:
            expires = changed.timestamp() + max_days * 86400
            rows.append(
                row(
                    "password.age.maxAgeDays",
                    f"changed within {max_days} days",
                    {"password_changed": user.get("passwordChanged")},
                    expires > now.timestamp(),
                )
            )
        else:
            rows.append(
                row(
                    "password.age.maxAgeDays",
                    "no maximum age",
                    max_days,
                    None,
                    "the policy sets no age, so an admin may have expired the password",
                )
            )
    out |= summary(rows)
    return out
