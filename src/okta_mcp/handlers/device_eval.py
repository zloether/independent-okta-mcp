"""Device assurance and advanced posture checks for `diagnostics login-failures` (plan 9.1,
slice 3). Pure: no I/O. Called by `policy_eval` for a rule's `conditions.device.assurance`.

A rule needs the device to meet ONE of its listed assurance policies; a policy for another
platform doesn't apply. Each requirement of the applicable policies becomes a row against the
device signals the DENY event recorded (`device`, and the `UDDevice` target's `detailEntry`):
OS version (static minimum, Windows per-major constraints), disk encryption, screen lock, secure
hardware, jailbreak, third-party signal providers and advanced posture checks.

Undecided, with the reason: dynamic OS requirements (they need Okta's latest-release list,
which isn't in the Management API), third-party signal values (only an integrator error is a
decision: an unreadable signal fails), and a posture check whose result isn't on the event. The
event shape for posture check results is unverified (plan 9.1 live check): the result is looked
for under the check's `variableName` in the event's device data.

Behavior follows okta-skills `okta-logs` `diagnose_login.py` where it covers the same ground
(reference only, re-implemented); posture checks are new.
"""

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any, cast

from okta_mcp.handlers import eval_model as pe

# Events say OSX where assurance policies say MACOS (the other names match).
_PLATFORM = {"OSX": "MACOS", "MAC": "MACOS", "CHROME_OS": "CHROMEOS"}
_GENERIC_ERROR = re.compile(r"genericError\([^)]*\)")
_SEARCH_DEPTH = 6
# Known orderings, weakest first: a value below every listed one fails; above, undecided.
_STRENGTH: dict[str, dict[str, int]] = {
    "screenLockType": {"NONE": 0, "PASSCODE": 1, "BIOMETRIC": 2},
    "diskEncryptionType": {"NONE": 0},
}


def version(text: object) -> tuple[int, ...]:
    """A version string as four comparable integers (`15.1` → (15, 1, 0, 0))."""
    parts = [int(x) for x in re.findall(r"\d+", text if isinstance(text, str) else "")][:4]
    return tuple(parts + [0] * (4 - len(parts)))


def _platform(d: pe.Denial) -> str:
    """The device's platform as assurance policies name it (`MACOS`, not `OSX`)."""
    found = pe.device_os(d)
    return _PLATFORM.get(found, found)


def _device_detail(d: pe.Denial) -> dict[str, Any]:
    for t in pe.targets(d.event):
        if t.get("type") == "UDDevice":
            return pe.as_dict(t.get("detailEntry"))
    return {}


def integrator_errors(d: pe.Denial) -> list[str]:
    """`genericError(…)` texts in the device's integrator signals (osquery, EDR, Chrome DTC)."""
    text = str(d.device.get("device_integrator") or "")
    text += str(_device_detail(d).get("deviceIntegrator") or "")
    return sorted(set(_GENERIC_ERROR.findall(text)))[:5]


def _grace(policy: Mapping[str, Any], d: pe.Denial) -> str | None:
    grace = pe.as_dict(policy.get("gracePeriod"))
    if not grace:
        return None
    kind, expiry = grace.get("type"), grace.get("expiry")
    if kind == "BY_DATE_TIME":
        ends = pe.time_of(expiry)
        if ends is not None and d.at is not None and ends <= d.at:
            return None  # ended before the denial: it can't be why
    # BY_DURATION counts from when the device fell out of compliance, which isn't visible.
    return (
        f"the policy has a grace period ({kind}: {expiry}): a non-compliant device may be let "
        "in until it ends"
    )


def _os_version(label: str, policy: Mapping[str, Any], actual: Any) -> list[pe.Row]:
    rows: list[pe.Row] = []
    os_version = pe.as_dict(policy.get("osVersion"))
    if minimum := os_version.get("minimum"):
        ok = version(actual) >= version(minimum) if actual else None
        note = None if actual else "the event carries no OS version"
        rows.append(pe.row(f"{label}: osVersion.minimum", minimum, actual, ok, note))
    elif dynamic := pe.as_dict(os_version.get("dynamicVersionRequirement")):
        rows.append(_dynamic(f"{label}: osVersion", dynamic, actual))
    constraints = [pe.as_dict(c) for c in pe.as_list(policy.get("osVersionConstraints"))]
    if constraints:
        rows.append(_constraints(label, constraints, actual))
    return rows


def _dynamic(check: str, dynamic: Mapping[str, Any], actual: Any) -> pe.Row:
    kind = dynamic.get("type")
    required = {
        k: v
        for k, v in (
            ("type", kind),
            ("distance_from_latest_major", dynamic.get("distanceFromLatestMajor")),
            ("latest_security_patch", dynamic.get("latestSecurityPatch")),
        )
        if v is not None
    }
    if kind == "NOT_ALLOWED":
        return pe.row(check, required, actual, False)
    return pe.row(
        check,
        required,
        actual,
        None,
        "dynamic OS requirements need Okta's latest-release list, which this server doesn't "
        "read: compare the device's version with the newest release",
    )


def _constraints(label: str, constraints: list[dict[str, Any]], actual: Any) -> pe.Row:
    check = f"{label}: osVersionConstraints"
    if not actual:
        return pe.row(
            check, "a per-major-version requirement", None, None, "the event carries no OS version"
        )
    # Windows 11 is NT build 22000 and later.
    major = "WINDOWS_11" if version(actual)[:3] >= (10, 0, 22000) else "WINDOWS_10"
    match = next((c for c in constraints if c.get("majorVersionConstraint") == major), None)
    check += f"[{major}]"
    if match is None:
        # The spec: a major version without a requirement bypasses it.
        return pe.row(check, "no requirement for this major version", actual, True)
    if minimum := match.get("minimum"):
        return pe.row(check, minimum, actual, version(actual) >= version(minimum))
    if dynamic := pe.as_dict(match.get("dynamicVersionRequirement")):
        return _dynamic(check, dynamic, actual)
    return pe.row(check, "any version of this major", actual, True)


def _included(
    label: str, key: str, field: str, policy: Mapping[str, Any], d: pe.Denial
) -> list[pe.Row]:
    wanted = pe.str_ids(pe.as_dict(policy.get(key)).get("include"))
    if not wanted:
        return []
    actual = d.device.get(field)
    if not isinstance(actual, str):
        return [pe.row(f"{label}: {key}", wanted, None, None, "the event's device doesn't say")]
    if actual.upper() in {w.upper() for w in wanted}:
        return [pe.row(f"{label}: {key}", wanted, actual, True)]
    rank = _STRENGTH.get(key, {})
    have = rank.get(actual.upper())
    weakest = min((rank[w.upper()] for w in wanted if w.upper() in rank), default=None)
    if actual.upper() == "NONE" or (have is not None and weakest is not None and have < weakest):
        return [pe.row(f"{label}: {key}", wanted, actual, False, "weaker than every listed value")]
    # Okta may count a stronger value (BIOMETRIC for PASSCODE) as meeting the requirement.
    return [
        pe.row(
            f"{label}: {key}",
            wanted,
            actual,
            None,
            "not one of the listed values; Okta may accept a stronger one",
        )
    ]


def _flag(label: str, key: str, field: str, want: bool, d: pe.Denial) -> pe.Row:
    actual = d.device.get(field)
    if not isinstance(actual, bool):
        return pe.row(f"{label}: {key}", want, None, None, "the event's device doesn't say")
    return pe.row(f"{label}: {key}", want, actual, actual == want)


def _third_party(label: str, providers: Mapping[str, Any], d: pe.Denial) -> pe.Row:
    required = sorted(k for k, v in providers.items() if v)
    errors = integrator_errors(d)
    if errors:
        return pe.row(
            f"{label}: thirdPartySignalProviders",
            required,
            {"errors": errors},
            False,
            "a signal the provider couldn't read fails the check",
        )
    return pe.row(
        f"{label}: thirdPartySignalProviders",
        required,
        None,
        None,
        "provider signal values aren't compared; no integrator error on the event",
    )


def _find(value: Any, name: str, depth: int = 0) -> tuple[bool, Any]:
    """The value under key `name` (case-insensitive) anywhere in `value`, JSON strings included."""
    if depth > _SEARCH_DEPTH:
        return False, None
    if isinstance(value, str) and value[:1] in "{[":
        try:
            value = json.loads(value)
        except ValueError:
            return False, None
    if isinstance(value, dict):
        for k, v in cast(dict[str, Any], value).items():
            if k.lower() == name.lower():
                return True, v
        for v in cast(dict[str, Any], value).values():
            found, inner = _find(v, name, depth + 1)
            if found:
                return True, inner
    if isinstance(value, list):
        for v in cast(list[Any], value):
            found, inner = _find(v, name, depth + 1)
            if found:
                return True, inner
    return False, None


def _same(actual: Any, wanted: Any) -> bool:
    def norm(v: Any) -> str:
        if isinstance(v, bool):
            return "1" if v else "0"
        text = str(v).strip().lower()
        return {"true": "1", "false": "0", "yes": "1", "no": "0"}.get(text, text)

    return norm(actual) == norm(wanted)


def _posture(
    label: str, entries: Iterable[Mapping[str, Any]], d: pe.Denial, facts: pe.Facts
) -> list[pe.Row]:
    """Advanced posture checks the policy requires: `{variableName, value}` each."""
    definitions = facts.posture_checks
    sources = {
        "device": d.event.get("device"),
        "device_detail": _device_detail(d),
        "debug": pe.at(d.event, "debugContext.debugData"),
    }
    errors = integrator_errors(d)
    rows: list[pe.Row] = []
    for entry in entries:
        name = entry.get("variableName")
        if not isinstance(name, str) or not name:
            continue
        wanted = entry.get("value", entry.get("values"))
        check = f"{label}: posture check {name}"
        required: dict[str, Any] = {"value": wanted}
        note: str | None = None
        if isinstance(definitions, Mapping):
            definition = pe.as_dict(definitions.get(name))
            if definition:
                required["name"] = definition.get("name")
                required["type"] = definition.get("type")
                # What the user is told to do; helpdesk can repeat it.
                if remedy := pe.at(definition, "remediationSettings.message.customText"):
                    required["remediation"] = remedy
            elif facts.posture_incomplete:
                note = facts.posture_incomplete
            else:
                note = "no posture check has this variable name now"
        elif isinstance(definitions, pe.Missing):
            note = definitions.reason
        found = False
        actual: Any = None
        for source in sources.values():
            found, actual = _find(source, name)
            if found and actual is not None:
                break
            found = False  # a null result was not reported
        options: list[Any] = (
            pe.as_list(cast(object, wanted)) if isinstance(wanted, list) else [wanted]
        )
        if found:
            ok = any(_same(actual, w) for w in options)
            rows.append(pe.row(check, required, actual, ok, note))
        elif errors:
            rows.append(
                pe.row(
                    check,
                    required,
                    {"errors": errors},
                    False,
                    "the device couldn't run its posture checks",
                )
            )
        else:
            rows.append(
                pe.row(check, required, None, None, note or "the check's result isn't on the event")
            )
    return rows


def _policy_rows(policy: Mapping[str, Any], d: pe.Denial, facts: pe.Facts) -> list[pe.Row]:
    label = f"assurance {pe.clip(str(policy.get('name') or policy.get('id')))!r}"
    rows = _os_version(label, policy, d.device.get("os_version"))
    rows += _included(label, "diskEncryptionType", "disk_encryption_type", policy, d)
    rows += _included(label, "screenLockType", "screen_lock_type", policy, d)
    if policy.get("secureHardwarePresent") is True:
        rows.append(_flag(label, "secureHardwarePresent", "secure_hardware_present", True, d))
    if policy.get("jailbreak") is False:
        rows.append(_flag(label, "jailbreak", "jailbreak", False, d))
    if providers := pe.as_dict(policy.get("thirdPartySignalProviders")):
        rows.append(_third_party(label, providers, d))
    posture = [
        pe.as_dict(e)
        for e in pe.as_list(pe.as_dict(policy.get("devicePostureChecks")).get("include"))
    ]
    rows += _posture(label, posture, d, facts)
    if (grace := _grace(policy, d)) and any(r["pass"] is not True for r in rows):
        rows = [{**r, "note": f"{r['note']}; {grace}" if r.get("note") else grace} for r in rows]
    return rows


def assurance(ids: list[str], d: pe.Denial, facts: pe.Facts) -> list[pe.Row]:
    """`conditions.device.assurance.include`: the device must meet ONE listed policy."""
    if not d.device and not pe.device_os(d):
        # Consistent with device.registered: no device signals, no assurance policy met.
        return [
            pe.row(
                "device.assurance",
                {"one_of": ids},
                None,
                False,
                "the event carries no device: no assurance policy can be met",
            )
        ]
    platform = _platform(d)
    groups: list[tuple[str, list[pe.Row]]] = []
    for aid in ids:
        found = facts.assurance.get(aid, pe.Missing("the assurance policy wasn't read"))
        if isinstance(found, pe.Missing):
            groups.append(
                (aid, [pe.row(f"assurance {aid}", "policy read", None, None, found.reason)])
            )
            continue
        policy_platform = str(found.get("platform") or "").upper()
        if platform and policy_platform and policy_platform != platform:
            continue  # for another platform: doesn't apply to this device
        if not platform:
            groups.append(
                (
                    aid,
                    [
                        pe.row(
                            f"assurance {aid}",
                            "a device platform",
                            None,
                            None,
                            "the event carries no device platform",
                        )
                    ],
                )
            )
            continue
        groups.append((str(found.get("name") or aid), _policy_rows(found, d, facts)))
    if not groups:
        return [
            pe.row(
                "device.assurance",
                {"one_of": ids, "for_platform": platform},
                platform,
                False,
                "none of the rule's assurance policies covers this platform",
            )
        ]
    return pe.either(groups, "device.assurance", "any one listed policy")


def posture_check_names(policies: Iterable[Mapping[str, Any]]) -> set[str]:
    """Posture check variable names the assurance policies require."""
    return {
        name
        for p in policies
        for e in pe.as_list(pe.as_dict(p.get("devicePostureChecks")).get("include"))
        if isinstance(name := pe.as_dict(e).get("variableName"), str) and name
    }
