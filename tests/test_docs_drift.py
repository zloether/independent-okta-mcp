"""Docs that describe what ships, checked against it (plan 8.3): drift a test can catch, so the
documentation pass needn't be repeated by hand."""

import re
from pathlib import Path

import pytest
import yaml

from okta_mcp.config import Config
from okta_mcp.exec.executor import tool_name

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "okta_mcp"
DESIGN = ROOT / "docs" / "design" / "mcp-server.md"
RUNBOOK = ROOT / "docs" / "runbook.md"
AGENTS = ROOT / "AGENTS.md"
README = ROOT / "README.md"
SCENARIOS = ROOT / "docs" / "deployment-scenarios.md"


def section(path: Path, start: str, end: str) -> str:
    """The text from the line starting with `start` to the next line starting with `end`."""
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(start)}.*?(?=^{re.escape(end)})", text, re.M | re.S)
    assert match, f"{path.name}: no section {start!r} … {end!r}"
    return match[0]


def domains() -> set[str]:
    # The loader requires each file's name to be its domain.
    return {p.stem for p in (SRC / "data" / "registry").glob("*.yaml")}


def emitted_events() -> set[str]:
    found: set[str] = set()
    for module in SRC.rglob("*.py"):
        found.update(re.findall(r'\bevent\(\s*"([a-z_]+)"', module.read_text(encoding="utf-8")))
    return found


def test_config_reference_lists_every_variable() -> None:
    rows = re.findall(r"^\| (`[^|]+) \|", section(DESIGN, "### 11.3", "### 11.4"), re.M)
    documented = {name for row in rows for name in re.findall(r"`([A-Z][A-Z0-9_]+)`", row)}
    aliases = {f.alias for f in Config.model_fields.values() if f.alias}
    assert documented == aliases


def test_design_lists_every_log_event() -> None:
    events = emitted_events()
    assert events, "no event(...) calls found: the pattern is stale"
    text = section(DESIGN, "## 13.", "## 14.")
    assert sorted(e for e in events if f"`{e}`" not in text) == []


def test_runbook_alerts_name_real_events() -> None:
    table = section(RUNBOOK, "### 4.7", "### 4.8")
    named = set(re.findall(r"^\| `([a-z_]+)`", table, re.M))
    assert named, "no event rows found in runbook §4.7"
    assert named <= emitted_events()


def test_design_tool_list_matches_registry() -> None:
    text = section(DESIGN, "### 5.1", "### 5.2")
    listed = set(re.findall(r"`(okta_[a-z_]+)`", text)) - {"okta_help", "okta_status"}
    assert listed == {tool_name(d) for d in domains()}


def test_design_and_readme_counts_match_registry() -> None:
    n = len(domains())
    summary = section(DESIGN, "## 1. Summary", "---")
    assert re.search(rf"composite commands \(\*\*{n}\*\*\)", summary)
    assert re.search(rf"One MCP tool per domain\*\* \({n}\)", summary)
    assert re.search(rf"\({n + 2} total\)", summary)
    assert f"{n} command domains" in README.read_text(encoding="utf-8")


def _tree() -> tuple[set[str], set[str]]:
    """Design §4.1's tree: (bare names on tree lines, `dir/{a,b}.py` expanded to paths)."""
    tree = section(DESIGN, "### 4.1", "## 5.")
    names = set(re.findall(r"── ([\w.\-]+)", tree))
    expanded: set[str] = set()
    for prefix, group, suffix in re.findall(r"([\w/]+/)\{([\w.,\-]+)\}([\w.]*)", tree):
        expanded.update(f"{prefix}{item}{suffix}" for item in group.split(","))
    return names, expanded


def test_design_tree_names_every_module_and_script() -> None:
    names, expanded = _tree()
    missing = []
    for module in sorted(SRC.rglob("*.py")):
        rel = module.relative_to(SRC)
        if module.name == "__init__.py" or rel.parts[0] in ("handlers", "data"):
            continue
        listed = module.name in names if len(rel.parts) == 1 else rel.as_posix() in expanded
        if not listed:
            missing.append(rel.as_posix())
    missing += [f"scripts/{p.name}" for p in (ROOT / "scripts").glob("*.py") if p.name not in names]
    assert missing == []


def test_design_tree_paths_exist() -> None:
    _, expanded = _tree()
    bases = (ROOT, SRC, ROOT / "docs", ROOT / ".github", SRC / "data")
    assert sorted(p for p in expanded if not any((b / p).exists() for b in bases)) == []


def _paths(text: str) -> set[str]:
    """Backticked repo paths in `text`, resolved: AGENTS.md and design §12.2 abbreviate paths
    under `src/okta_mcp/`, and the design abbreviates those under its `data/`."""
    found: set[str] = set()
    for token in re.findall(r"`([^`\s]+)`", text):
        if "*" in token or token.startswith("/") or ("/" not in token and "." not in token):
            continue
        for base in (ROOT, SRC, SRC / "data"):
            if (base / token).exists():
                found.add((base / token).relative_to(ROOT).as_posix().rstrip("/"))
                break
        else:
            pytest.fail(f"{token!r} names no file in the repository")
    return found


def test_trust_boundaries_match_between_agents_and_design() -> None:
    text = AGENTS.read_text(encoding="utf-8")
    agents = _paths(text[text.index("## Trust boundaries") :])  # the file's last section
    design = _paths(section(DESIGN, "### 12.2", "### 12.3")) - {"AGENTS.md"}
    assert agents == design


def test_agents_docs_table_links_exist() -> None:
    text = AGENTS.read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)#]+)\)", text)
    assert links
    assert sorted(link for link in links if not (ROOT / link).exists()) == []


def test_kubernetes_example_matches_image_and_config() -> None:
    """Deployment scenario C's manifest (plan 7.4) is unverified against a cluster; this keeps it
    in step with the image's user and the server's variables."""
    text = SCENARIOS.read_text(encoding="utf-8")
    blocks = [yaml.safe_load(b) for b in re.findall(r"```yaml\n(.*?)```", text, re.S)]
    kustomize, deployment = blocks
    assert kustomize["configMapGenerator"][0]["files"] == ["policy.yaml"]
    pod = deployment["spec"]["template"]["spec"]
    user = re.search(r"^USER (\d+):(\d+)$", (ROOT / "Dockerfile").read_text(), re.M)
    assert user
    uid, gid = int(user[1]), int(user[2])
    ctx = pod["securityContext"]
    assert (ctx["runAsUser"], ctx["runAsGroup"], ctx["fsGroup"]) == (uid, gid, gid)
    assert pod["automountServiceAccountToken"] is False
    for volume in pod["volumes"]:
        source = volume.get("configMap") or volume["secret"]
        assert source["defaultMode"] & 0o040, "group 10001 must be able to read it"
    (container,) = pod["containers"]
    assert container["securityContext"] == {
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    env = {e["name"]: e["value"] for e in container["env"]}
    aliases = {f.alias for f in Config.model_fields.values() if f.alias}
    assert set(env) <= aliases | {f"{a}_FILE" for a in aliases}
    mounts = [m["mountPath"] for m in container["volumeMounts"]]
    assert all(m["readOnly"] for m in container["volumeMounts"])
    assert not any(m == "/run/secrets" or m.startswith("/var/run") for m in mounts)
    for name in ("MCP_POLICY_FILE", "MCP_CURSOR_KEY_FILE", "OKTA_PRIVATE_KEY_FILE"):
        assert str(Path(env[name]).parent) in mounts, name


def _anchors(path: Path) -> set[str]:
    """GitHub's heading anchors: lower case, punctuation but `-` dropped, spaces to `-`."""
    headings = re.findall(r"^#+ (.+)$", path.read_text(encoding="utf-8"), re.M)
    return {re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-") for h in headings}


@pytest.mark.parametrize(
    "doc",
    [DESIGN, RUNBOOK, SCENARIOS, ROOT / "docs" / "okta-setup.md", README, AGENTS],
    ids=lambda p: p.name,
)
def test_links_to_docs_resolve(doc: Path) -> None:
    broken = []
    for target, anchor in re.findall(r"\]\(([^)\s#]*\.md)?#([^)\s]+)\)", doc.read_text("utf-8")):
        path = (doc.parent / target).resolve() if target else doc
        if not path.is_file() or anchor not in _anchors(path):
            broken.append(f"{target}#{anchor}")
    assert broken == []
