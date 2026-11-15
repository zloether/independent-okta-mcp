"""What the evaluators of `diagnostics login-failures` share (plan 9.1): the facts a handler
fetched, one denial, tri-state rows and the helpers that read untrusted Okta data. Pure."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, cast

Row = dict[str, Any]
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
    posture_incomplete: str | None = None
    """Why the posture check definitions may be missing some (a list failed or was cut)."""


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


def str_of(value: object) -> str:
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


def policy_os(name: str) -> str:
    """An OS name as policy platform conditions spell it (`MACOS` → `OSX`)."""
    return _COND_OS.get(name.upper(), name.upper())


def device_os(d: "Denial") -> str:
    """The device's OS as policy platform conditions name it (`OSX`, `WINDOWS`, …): from the
    event's device, else its user agent; empty when neither says."""
    name = d.device.get("os_platform")
    found = _COND_OS.get(name.upper(), name.upper()) if isinstance(name, str) else ""
    if not found:
        agent = str_of(at(d.event, "client.userAgent.os")).lower()
        found = next((v for k, v in _UA_OS if k in agent), "")
    return found
