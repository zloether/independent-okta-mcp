"""Output hygiene for the live tests (plan 8.2.1): the part of `conftest.py`'s report hook that
can be tested without a live org (`tests/test_live_hygiene.py`)."""

from collections.abc import Sequence

import pytest

LEAK = "a secret value appeared in captured output"
REMOVED = "[removed: held a secret value]"


def blank_secrets(report: pytest.TestReport, secrets: Sequence[str]) -> bool:
    """Blank every part of `report` pytest would print that holds one of `secrets`: its
    captured sections (stdout, stderr, log, per phase) and its failure text (`longrepr`, which
    `--tb=line` and `-rA` print). A report that held one fails. A failure text with no secret is
    kept, with the leak noted after it. True if anything was blanked."""
    if not secrets:
        return False
    leaked = False
    sections: list[tuple[str, str]] = []
    for title, text in report.sections:
        if any(s in text for s in secrets):
            leaked, text = True, REMOVED
        sections.append((title, text))
    failure = str(report.longrepr) if report.longrepr is not None else ""
    failure_leaked = any(s in failure for s in secrets)
    if not (leaked or failure_leaked):
        return False
    report.sections = sections
    report.outcome = "failed"
    if failure_leaked or not failure:
        report.longrepr = LEAK
    else:
        report.longrepr = f"{failure}\n{LEAK}"
    return True
