"""Package metadata (plan 8.3.2): what PyPI shows must say what the README says."""

import email.parser
import re
import shutil
import subprocess
import tomllib
import zipfile
from pathlib import Path

import pytest

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
    assert status == ["Development Status :: 3 - Alpha"]
    # Move both together (plan 8.4): from the first release, 0.1.0, the classifier is Alpha and
    # the README says so; "under active development" and "no release" went with Pre-Alpha.
    assert "**Alpha." in README
    for doc in ("README.md", "SECURITY.md", "CONTRIBUTING.md"):
        text = (ROOT / doc).read_text().lower()
        for retired in ("no release yet", "there is no release", "under active development"):
            assert retired not in text, (doc, retired)
        assert "pre-alpha" not in text, doc


def test_readme_links_work_on_pypi() -> None:
    """PyPI shows the README as the project description: a relative link resolves against
    pypi.org and 404s (seen on TestPyPI for 0.1.0rc1), and its headings get no anchors."""
    links = [
        *re.findall(r"\]\(([^)\s]+)\)", README),  # inline
        *re.findall(r"^ {0,3}\[[^\]]+\]:\s*<?([^\s>]+)", README, re.M),  # reference definitions
        *re.findall(r"""\b(?:href|src)\s*=\s*["']?([^"'\s>]+)""", README),  # HTML
    ]
    assert links
    assert [u for u in links if not u.startswith("https://")] == []
    for url in links:
        if url.startswith(REPO + "/"):
            m = re.fullmatch(rf"{REPO}/(?:(?:blob|tree)/main/([^#]+)(?:#.*)?|releases)", url)
            assert m, url  # main, not another branch: what the project URLs point at
            assert m[1] is None or (ROOT / m[1]).exists(), url


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
    # The license isn't OSI-approved, so no `License ::` classifier fits (and PEP 639 forbids
    # one if `license` ever becomes an SPDX expression).
    assert not [c for c in PROJECT["classifiers"] if c.startswith("License ::")]


def test_project_urls_point_at_the_repository() -> None:
    urls = PROJECT["urls"]
    assert {"Homepage", "Source", "Issues", "Changelog", "Documentation"} <= set(urls)
    assert all(u == REPO or u.startswith(REPO + "/") for u in urls.values())


LICENSE_ID = "LicenseRef-Commons-Clause-Apache-2.0"


def test_license_is_an_expression_with_its_files() -> None:
    # PEP 639: an SPDX expression (`LicenseRef-` for a license not on the SPDX list; user
    # decision 2026-11-23) and the files that hold the terms. NOTICE carries the vendored Okta
    # spec's attribution, which Apache-2.0 §4(d) asks redistributions to keep.
    assert PROJECT["license"] == LICENSE_ID
    assert PROJECT["license-files"] == ["LICENSE", "NOTICE"]
    # The readable name the README gives is the one the expression stands for.
    assert "Apache-2.0 with the Commons Clause" in README


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build the wheel")
def test_built_wheel_carries_the_license(tmp_path: Path) -> None:
    subprocess.run(  # noqa: S603
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path), str(ROOT)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    (wheel,) = tmp_path.glob("*.whl")
    # The name runbook §3.6 and docs/releasing.md download and verify.
    assert wheel.name == f"independent_okta_mcp-{PROJECT['version']}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        (meta,) = [n for n in names if n.endswith(".dist-info/METADATA")]
        headers = email.parser.Parser().parsestr(z.read(meta).decode(), headersonly=True)
        dist_info = meta.rsplit("/", 1)[0]
        bundled = {
            n.removeprefix(f"{dist_info}/licenses/"): z.read(n)
            for n in names
            if n.startswith(f"{dist_info}/licenses/") and not n.endswith("/")
        }
    assert headers["License-Expression"] == LICENSE_ID
    assert headers["License"] is None  # not the whole LICENSE text in one field
    assert sorted(headers.get_all("License-File") or []) == ["LICENSE", "NOTICE"]
    assert bundled == {
        "LICENSE": (ROOT / "LICENSE").read_bytes(),
        "NOTICE": (ROOT / "NOTICE").read_bytes(),
    }
