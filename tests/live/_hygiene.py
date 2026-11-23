"""Output hygiene for the live tests (plan 8.2.1): the part of `conftest.py`'s report hook that
can be tested without a live org (`tests/test_live_hygiene.py`)."""

import re
from collections.abc import Sequence

import pytest

LEAK = "a secret value appeared in captured output"
REMOVED = "[removed: held a secret value]"

# Okta object IDs (users 00u…, groups 00g…, apps 0oa…, policies 00p…): 20 characters starting
# with 0. Not secrets, but they name objects in the CI org, and the run logs and summaries are
# public once the repository is (2026-11-23, user decision): redacted, not failed.
OKTA_ID = re.compile(r"(?<![0-9A-Za-z])0[0-9A-Za-z]{19}(?![0-9A-Za-z])")
ID_LABEL = "<okta-id>"


def redact_ids(text: str) -> str:
    """`text` with every Okta-shaped object ID replaced by `ID_LABEL`."""
    return OKTA_ID.sub(ID_LABEL, text)


def redact_report_ids(report: pytest.TestReport) -> bool:
    """Redact Okta IDs in every part of `report` pytest would print: its captured sections and
    its failure text. The outcome is unchanged. True if anything was redacted."""
    changed = False
    sections: list[tuple[str, str]] = []
    for title, text in report.sections:
        clean = redact_ids(text)
        changed |= clean != text
        sections.append((title, clean))
    if report.longrepr is not None:
        failure = str(report.longrepr)
        clean = redact_ids(failure)
        if clean != failure:
            changed = True
            report.longrepr = clean
    if changed:
        report.sections = sections
    return changed


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
