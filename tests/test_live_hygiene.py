"""The live tests' report hook (`tests/live/_hygiene.py`, plan 8.2.1 output hygiene): a secret
in any captured section, or in a failure's own text, is blanked and the test fails; nothing else
changes."""

import pytest
from live._hygiene import ID_LABEL, LEAK, REMOVED, blank_secrets, redact_ids, redact_report_ids

SECRET = "tok-0123456789abcdefghijklmnopqrstuvwxyz"  # noqa: S105 - a fake, to be blanked


def _report(
    sections: list[tuple[str, str]], *, outcome: str = "passed", longrepr: object = None
) -> pytest.TestReport:
    return pytest.TestReport(
        nodeid="tests/live/test_x.py::test_x",
        location=("tests/live/test_x.py", 1, "test_x"),
        keywords={},
        outcome=outcome,  # pyright: ignore[reportArgumentType]
        longrepr=longrepr,  # pyright: ignore[reportArgumentType]
        when="setup",
        sections=sections,
    )


def test_secret_in_setup_output_is_blanked_and_fails() -> None:
    report = _report([("Captured stdout setup", f"token={SECRET}\n"), ("Captured log setup", "ok")])
    assert blank_secrets(report, [SECRET])
    assert report.outcome == "failed"
    assert report.sections == [("Captured stdout setup", REMOVED), ("Captured log setup", "ok")]
    assert report.longrepr == LEAK
    assert SECRET not in str(report.sections) + str(report.longrepr)


def test_secret_in_failure_text_is_blanked() -> None:
    report = _report(
        [("Captured stdout call", "clean")], outcome="failed", longrepr=f"E   boom {SECRET}"
    )
    assert blank_secrets(report, [SECRET])
    assert report.longrepr == LEAK
    assert report.sections == [("Captured stdout call", "clean")]


def test_clean_failure_text_is_kept_when_a_section_leaks() -> None:
    report = _report(
        [("Captured stderr setup", SECRET)], outcome="failed", longrepr="E   assert 1 == 2"
    )
    assert blank_secrets(report, [SECRET])
    assert report.longrepr == f"E   assert 1 == 2\n{LEAK}"


def test_clean_report_is_untouched() -> None:
    report = _report([("Captured stdout call", "nothing here")])
    assert not blank_secrets(report, [SECRET])
    assert report.outcome == "passed" and report.longrepr is None
    assert report.sections == [("Captured stdout call", "nothing here")]


def test_no_secrets_known_is_a_no_op() -> None:
    report = _report([("Captured stdout call", SECRET)])
    assert not blank_secrets(report, [])
    assert report.outcome == "passed"


# Okta object IDs: 20 characters, starting with 0 (users 00u…, groups 00g…, apps 0oa…).
GROUP = "00g1a2b3c4d5e6f7g8h9"
APP = "0oaZ9y8X7w6V5u4T3s2r"


def test_redact_ids_replaces_okta_shaped_ids() -> None:
    text = f'"/api/v1/groups/{GROUP}.": 404, app {APP}'
    assert redact_ids(text) == f'"/api/v1/groups/{ID_LABEL}.": 404, app {ID_LABEL}'


def test_redact_ids_leaves_other_values() -> None:
    others = ["E0000006", "E0000015", "okta.users.read", "00g1a2b3", "users me.smith@example.com"]
    for kept in others:
        assert redact_ids(kept) == kept
    # Longer runs of the same characters aren't an ID.
    assert redact_ids("x" + GROUP + "x") == "x" + GROUP + "x"


def test_report_ids_are_redacted_without_failing() -> None:
    report = _report(
        [("Captured stdout call", f"probe groups/{GROUP}.\n"), ("Captured log call", "ok")],
        outcome="failed",
        longrepr=f"AssertionError: changed: groups/{GROUP}.",
    )
    assert redact_report_ids(report)
    assert report.outcome == "failed"
    assert report.sections == [
        ("Captured stdout call", f"probe groups/{ID_LABEL}.\n"),
        ("Captured log call", "ok"),
    ]
    assert report.longrepr == f"AssertionError: changed: groups/{ID_LABEL}."


def test_report_without_ids_is_untouched() -> None:
    longrepr = object()
    report = _report([("Captured stdout call", "ok")], longrepr=longrepr)
    assert not redact_report_ids(report)
    assert report.longrepr is longrepr
    assert report.outcome == "passed"
