"""The live tests' report hook (`tests/live/_hygiene.py`, plan 8.2.1 output hygiene): a secret
in any captured section, or in a failure's own text, is blanked and the test fails; nothing else
changes."""

import pytest
from live._hygiene import LEAK, REMOVED, blank_secrets

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
