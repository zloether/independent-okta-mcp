"""The CI workflow's path filter (2026-11-23, while the repository is private and Actions
minutes are metered): docs-only changes skip CI, but never a file a test reads."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _on() -> dict[str, Any]:
    data = yaml.safe_load(CI.read_text())
    return data.get(True, data.get("on"))


def _match(pattern: str, path: str) -> bool:
    """GitHub's path globs: `**` crosses `/`, `*` doesn't."""
    regex = re.escape(pattern).replace(r"\*\*", "\0").replace(r"\*", "[^/]*")
    return re.fullmatch(regex.replace("\0", ".*"), path) is not None


def _runs(patterns: list[str], path: str) -> bool:
    """Whether a change to `path` alone triggers the workflow: the last matching pattern wins."""
    hit = False
    for p in patterns:
        if p.startswith("!"):
            if _match(p[1:], path):
                hit = False
        elif _match(p, path):
            hit = True
    return hit


def _docs_read_by_tests() -> set[str]:
    found: set[str] = set()
    for test in (ROOT / "tests").rglob("*.py"):
        if test == Path(__file__):
            continue
        text = test.read_text(encoding="utf-8")
        # Path expressions: `"docs" / "a" / "b.md"`, or `/ "README.md"` at the root.
        for parts in re.findall(r'"docs"((?:\s*/\s*"[^"]+")+)', text):
            found.add("/".join(["docs", *re.findall(r'"([^"]+)"', parts)]))
        found.update(
            name
            for base, name in re.findall(r'(\w+)\)?\s*/\s*"(\w+\.md)"', text)
            if base != "tmp_path"
        )
    return {f for f in found if (ROOT / f).is_file()}


def test_same_filter_on_push_and_pull_request() -> None:
    on = _on()
    assert on["push"]["paths"] == on["pull_request"]["paths"]
    assert on["push"]["branches"] == ["main"]


def test_docs_only_changes_skip_ci() -> None:
    paths = _on()["pull_request"]["paths"]
    for doc in ["docs/decisions-log.md", "docs/implementation-plan.md", "CHANGELOG.md"]:
        assert not _runs(paths, doc), doc


def test_code_and_guides_run_ci() -> None:
    paths = _on()["pull_request"]["paths"]
    for path in [
        "src/okta_mcp/server.py",
        "src/okta_mcp/data/resources/groups.md",
        "tests/test_app.py",
        "pyproject.toml",
        "uv.lock",
        "Dockerfile",
        ".github/workflows/ci.yml",
        "scripts/okta-setup.py",
    ]:
        assert _runs(paths, path), path


def test_docs_read_by_tests_run_ci() -> None:
    docs = _docs_read_by_tests()
    # The three known today; the scan above catches a new one.
    assert {"docs/design/mcp-server.md", "docs/runbook.md", "docs/okta-setup.md"} <= docs
    paths = _on()["pull_request"]["paths"]
    for doc in docs:
        assert _runs(paths, doc), doc


def test_glob_helper() -> None:
    assert _match("*.md", "README.md") and not _match("*.md", "docs/a.md")
    assert _match("docs/**", "docs/design/mcp-server.md")
