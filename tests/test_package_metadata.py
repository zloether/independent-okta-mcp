"""Package metadata (plan 8.3.2): what PyPI shows must say what the README says."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
README = (ROOT / "README.md").read_text()
REPO = "https://github.com/zloether/independent-okta-mcp"


def test_summary_says_it_is_not_okta_s() -> None:
    assert "Not affiliated with or endorsed by Okta" in PROJECT["description"]
    # The README's opening paragraphs say the same (nominative use, NOTICE).
    opening = README.split("## ", 1)[0]
    assert "not affiliated with, endorsed by or supported by Okta" in opening


def test_development_status_matches_the_readme() -> None:
    status = [c for c in PROJECT["classifiers"] if c.startswith("Development Status ::")]
    assert status == ["Development Status :: 2 - Pre-Alpha"]
    # Move both together: the classifier names the README's status line.
    assert "**Pre-alpha." in README


def test_python_classifiers_match_requires_python() -> None:
    assert PROJECT["requires-python"] == ">=3.12"
    versions = {
        m[1]
        for c in PROJECT["classifiers"]
        if (m := re.fullmatch(r"Programming Language :: Python :: (3\.\d+)", c))
    }
    # The versions CI's full matrix tests (plan 8.3.1 puts 3.13 and 3.14 back once public).
    assert versions == {"3.12", "3.13", "3.14", "3.15"}


def test_no_license_classifier() -> None:
    # The license isn't OSI-approved, so no `License ::` classifier fits; PEP 639 also forbids
    # one alongside a license expression.
    assert not [c for c in PROJECT["classifiers"] if c.startswith("License ::")]


def test_project_urls_point_at_the_repository() -> None:
    urls = PROJECT["urls"]
    assert {"Homepage", "Source", "Issues", "Changelog", "Documentation"} <= set(urls)
    assert all(u == REPO or u.startswith(REPO + "/") for u in urls.values())
