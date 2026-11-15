"""Device assurance and advanced posture checks (plan 9.1 slice 3), pure."""

from datetime import UTC, datetime
from typing import Any

import pytest

from okta_mcp.handlers import device_eval as de
from okta_mcp.handlers import policy_eval as pe

UID = "00u1alice00000000000"
AID = "dae1emaKYZTWRYYRRTSK"
T = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def denial(device: dict[str, Any] | None = None, **extra: Any) -> pe.Denial:
    event: dict[str, Any] = {"published": "2026-11-14T10:00:00.000Z", "target": []}
    if device is not None:
        event["device"] = device
    event.update(extra)
    return pe.Denial(event=event, at=T, verify_events=[], verify_by=None)


def facts(*policies: dict[str, Any], posture: Any = None) -> pe.Facts:
    return pe.Facts(
        user={"id": UID},
        zones={},
        groups_now=frozenset(),
        groups_complete=True,
        membership_events=[],
        authenticators={},
        assurance={p["id"]: p for p in policies},
        posture_checks=posture,
    )


def mac(**fields: Any) -> dict[str, Any]:
    return {"id": AID, "name": "Mac baseline", "platform": "MACOS", **fields}


MAC = {
    "os_platform": "OSX",
    "os_version": "14.6.1",
    "disk_encryption_type": "ALL_INTERNAL_VOLUMES",
    "screen_lock_type": "PASSCODE",
    "secure_hardware_present": True,
}


def checks(rows: list[pe.Row]) -> dict[str, bool | None]:
    return {r["check"]: r["pass"] for r in rows}


def test_version() -> None:
    assert de.version("15.1") == (15, 1, 0, 0)
    assert de.version("10.0.22631.4249") > de.version("10.0.19045.1")
    assert de.version(None) == (0, 0, 0, 0)


def test_a_met_policy_is_one_passing_row() -> None:
    policy = mac(
        osVersion={"minimum": "14.0"},
        diskEncryptionType={"include": ["ALL_INTERNAL_VOLUMES"]},
        secureHardwarePresent=True,
    )
    (row,) = de.assurance([AID], denial(MAC), facts(policy))
    assert row["pass"] is True and row["actual"] == "met by Mac baseline"


def test_every_failed_requirement_is_a_row() -> None:
    policy = mac(osVersion={"minimum": "15.0"}, screenLockType={"include": ["BIOMETRIC"]})
    rows = de.assurance([AID], denial(MAC), facts(policy))
    assert checks(rows) == {
        "assurance 'Mac baseline': osVersion.minimum": False,
        "assurance 'Mac baseline': screenLockType": False,
    }


def test_a_device_that_doesn_t_say_is_undecided() -> None:
    policy = mac(
        diskEncryptionType={"include": ["ALL_INTERNAL_VOLUMES"]}, secureHardwarePresent=True
    )
    rows = de.assurance([AID], denial({"os_platform": "MACOS"}), facts(policy))
    assert set(checks(rows).values()) == {None}


def test_a_policy_for_another_platform_doesn_t_apply() -> None:
    windows = {"id": "dae2emaKYZTWRYYRRTSK", "name": "Win", "platform": "WINDOWS"}
    (row,) = de.assurance([windows["id"]], denial(MAC), facts(windows))
    assert row["pass"] is False and "covers this platform" in row["note"]


def test_any_one_listed_policy_suffices() -> None:
    strict = mac(id="dae3emaKYZTWRYYRRTSK", name="Strict", osVersion={"minimum": "99"})
    loose = mac(name="Loose", osVersion={"minimum": "14"})
    (row,) = de.assurance([strict["id"], AID], denial(MAC), facts(strict, loose))
    assert row["pass"] is True and row["actual"] == "met by Loose"


def test_no_platform_on_the_event_is_undecided() -> None:
    (row,) = de.assurance([AID], denial({}), facts(mac()))
    assert row["pass"] is None and "platform" in row["note"]


def test_a_policy_not_read_is_undecided_with_the_reason() -> None:
    f = facts()
    f.assurance = {AID: pe.Missing("the service app needs okta.deviceAssurance.read")}
    (row,) = de.assurance([AID], denial(MAC), f)
    assert row["pass"] is None and "deviceAssurance" in row["note"]


@pytest.mark.parametrize(
    ("version", "constraints", "expected"),
    [
        (
            "10.0.22631.1",
            [{"majorVersionConstraint": "WINDOWS_11", "minimum": "10.0.22631.0"}],
            True,
        ),
        (
            "10.0.22000.1",
            [{"majorVersionConstraint": "WINDOWS_11", "minimum": "10.0.22631.0"}],
            False,
        ),
        # No requirement for Windows 10: the spec says it is bypassed.
        (
            "10.0.19045.1",
            [{"majorVersionConstraint": "WINDOWS_11", "minimum": "10.0.22631.0"}],
            True,
        ),
        (
            "10.0.19045.1",
            [
                {
                    "majorVersionConstraint": "WINDOWS_10",
                    "dynamicVersionRequirement": {"type": "NOT_ALLOWED"},
                }
            ],
            False,
        ),
        (
            "10.0.22631.1",
            [
                {
                    "majorVersionConstraint": "WINDOWS_11",
                    "dynamicVersionRequirement": {"type": "MINIMUM", "distanceFromLatestMajor": 0},
                }
            ],
            None,
        ),
    ],
)
def test_windows_constraints(
    version: str, constraints: list[dict[str, Any]], expected: bool | None
) -> None:
    policy = {"id": AID, "name": "Win", "platform": "WINDOWS", "osVersionConstraints": constraints}
    rows = de.assurance(
        [AID], denial({"os_platform": "WINDOWS", "os_version": version}), facts(policy)
    )
    if expected is True:
        assert rows[0]["pass"] is True  # the one policy met
    else:
        assert [r["pass"] for r in rows] == [expected]


def test_a_dynamic_requirement_is_undecided_with_what_to_compare() -> None:
    policy = mac(
        osVersion={"dynamicVersionRequirement": {"type": "EXACT", "distanceFromLatestMajor": 1}}
    )
    (row,) = de.assurance([AID], denial(MAC), facts(policy))
    assert row["pass"] is None
    assert row["required"] == {"type": "EXACT", "distance_from_latest_major": 1}
    assert row["actual"] == "14.6.1"


def test_an_integrator_error_fails_third_party_signals() -> None:
    device = {**MAC, "device_integrator": '{"CHROME_DTC":{"genericError(timeout)":1}}'}
    policy = mac(thirdPartySignalProviders={"dtc": {"osFirewall": True}})
    (row,) = de.assurance([AID], denial(device), facts(policy))
    assert row["pass"] is False and row["actual"] == {"errors": ["genericError(timeout)"]}
    (row,) = de.assurance([AID], denial(MAC), facts(policy))
    assert row["pass"] is None


def test_a_grace_period_is_noted_on_a_failure() -> None:
    policy = mac(
        osVersion={"minimum": "15"},
        gracePeriod={"type": "BY_DATE", "expiry": "2026-12-01T00:00:00Z"},
    )
    (row,) = de.assurance([AID], denial(MAC), facts(policy))
    assert "grace period (BY_DATE: 2026-12-01T00:00:00Z)" in row["note"]


# --- advanced posture checks -----------------------------------------------------------------

FIREWALL = {"variableName": "macOSFirewall", "value": "1"}
DEFINITION = {
    "variableName": "macOSFirewall",
    "name": "Firewall on",
    "type": "CUSTOM",
    "query": "SELECT 1 AS secret_query;",
    "remediationSettings": {"message": {"customText": "Turn on the firewall in System Settings"}},
}


def test_posture_check_names() -> None:
    assert de.posture_check_names([mac(devicePostureChecks={"include": [FIREWALL]}), mac()]) == {
        "macOSFirewall"
    }


@pytest.mark.parametrize(
    ("where", "value", "expected"),
    [
        ({"device": {**MAC, "macOSFirewall": "0"}}, "0", False),
        ({"device": {**MAC, "macosfirewall": True}}, True, True),
        ({"device": {**MAC, "device_integrator": '{"OSQUERY":{"macOSFirewall":"1"}}'}}, "1", True),
        (
            {
                "device": MAC,
                "target": [
                    {"type": "UDDevice", "detailEntry": {"postureChecks": {"macOSFirewall": 0}}}
                ],
            },
            0,
            False,
        ),
    ],
)
def test_a_posture_check_result_found_on_the_event(
    where: dict[str, Any], value: Any, expected: bool
) -> None:
    device = where.pop("device")
    policy = mac(devicePostureChecks={"include": [FIREWALL]})
    rows = de.assurance(
        [AID], denial(device, **where), facts(policy, posture={"macOSFirewall": DEFINITION})
    )
    if expected:
        assert rows[0]["pass"] is True
        return
    (row,) = rows
    assert row["pass"] is False and row["actual"] == value
    assert row["required"]["remediation"] == "Turn on the firewall in System Settings"
    assert "secret_query" not in str(row)  # the osquery isn't sent


def test_a_posture_check_result_not_on_the_event_is_undecided() -> None:
    policy = mac(devicePostureChecks={"include": [FIREWALL]})
    (row,) = de.assurance([AID], denial(MAC), facts(policy, posture={"macOSFirewall": DEFINITION}))
    assert row["pass"] is None and "isn't on the event" in row["note"]


def test_posture_checks_that_couldn_t_run_fail() -> None:
    device = {**MAC, "device_integrator": '{"OSQUERY":{"genericError(osquery down)":1}}'}
    policy = mac(devicePostureChecks={"include": [FIREWALL]})
    (row,) = de.assurance([AID], denial(device), facts(policy, posture={}))
    assert row["pass"] is False
    assert row["note"] == "the device couldn't run its posture checks"


def test_posture_definitions_not_read_keep_the_reason() -> None:
    policy = mac(devicePostureChecks={"include": [FIREWALL]})
    posture = pe.Missing("the service app needs okta.devicePostureChecks.read")
    (row,) = de.assurance(
        [AID], denial({**MAC, "macOSFirewall": "0"}), facts(policy, posture=posture)
    )
    assert row["pass"] is False and "devicePostureChecks" in row["note"]
