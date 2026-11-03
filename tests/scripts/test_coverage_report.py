from pathlib import Path
from typing import Any

import pytest
import yaml
from _load import load_script

from okta_mcp.registry.loader import Registry, build_registry
from okta_mcp.registry.spec import SpecIndex, load_spec

report = load_script("coverage-report")

GET = {
    "operation": "getUser",
    "summary": "Get a user",
    "args": {"user": {"path_param": "id"}},
    "data_classes": ["pii"],
}
GET_GROUPS = {
    "operation": "listUserGroups",
    "summary": "Groups the user belongs to",
    "args": {"user": {"path_param": "id", "resolve": "user_id"}},
    "paginate": "link",
    "page_size": 200,
    "view": ["id", "type", "profile.name"],
    "data_classes": ["pii"],
}
CATALOGUE: dict[str, Any] = {
    "domains": {
        "users": {
            "get": {"operations": ["getUser"], "kind": "simple", "paginate": "none"},
            "get-groups": {
                "operations": ["listUserGroups"],
                "kind": "resolved",
                "paginate": "link",
            },
            "get-apps": {
                "operations": ["listAppLinks"],
                "kind": "resolved",
                "paginate": "none",
                "gotcha": "tricky",
            },
            "get-factors-questions": {
                "operations": ["listSupportedSecurityQuestions"],
                "kind": "excluded",
                "reason": "apiToken only",
            },
        },
        "logs": {
            "timeline": {"operations": ["listLogEvents", "listGroupUsers"], "kind": "composite"},
        },
    }
}


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def registry(spec: SpecIndex) -> Registry:
    docs = {
        "users.yaml": {
            "domain": "users",
            "description": "Read users.",
            "commands": {"get": GET, "get-groups": GET_GROUPS},
        },
        "groups.yaml": {
            "domain": "groups",
            "description": "Read groups.",
            "commands": {
                "get": {
                    "operation": "getGroup",
                    "summary": "Get a group",
                    "args": {"group": {"path_param": "groupId"}},
                    "data_classes": ["org-config"],
                }
            },
        },
    }
    return build_registry(docs, spec)


def _errors(doc: Any, spec: SpecIndex) -> list[str]:
    with pytest.raises(report.CatalogueError) as e:
        report.parse_catalogue(doc, spec)
    return e.value.errors


def test_checked_in_catalogue_is_valid(spec: SpecIndex) -> None:
    catalogue = report.parse_catalogue(yaml.safe_load(report.CATALOGUE.read_text()), spec)
    assert sum(len(c) for c in catalogue.values()) > 0
    assert all(e["kind"] in report.KINDS for c in catalogue.values() for e in c.values())


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"operations": ["getUser"]}, "users get: kind must be one of"),
        ({"operations": ["getUser"], "kind": "easy"}, "users get: kind must be one of"),
        ({"kind": "simple"}, "users get: operations must be a non-empty list"),
        ({"operations": [], "kind": "simple"}, "users get: operations must be a non-empty list"),
        ({"operations": ["nope"], "kind": "simple"}, "users get: nope is not a GET operation"),
        ({"operations": ["getUser"], "kind": "excluded"}, "users get: excluded needs a reason"),
        (
            {"operations": ["getUser"], "kind": "simple", "reason": "x"},
            "users get: only excluded entries take a reason",
        ),
        (
            {"operations": ["getUser"], "kind": "simple", "paginate": "pages"},
            "users get: paginate must be one of",
        ),
        (
            {"operations": ["getUser"], "kind": "simple", "colour": 1},
            "users get: unknown keys: colour",
        ),
        (
            {"operations": ["getAerialConsnet"], "kind": "excluded", "reason": "r"},
            "users get: getAerialConsnet is not a GET operation",
        ),
        (
            {"operations": ["getUser"], "kind": "simple", "paginate": "link"},
            "users get: paginate link but getUser does not page",
        ),
        (
            {"operations": ["listUserGroups"], "kind": "resolved", "paginate": "none"},
            "users get: paginate none but listUserGroups pages",
        ),
        (
            {"operations": ["listUserGroups"], "kind": "resolved", "paginate": "link_or_body"},
            "users get: link_or_body goes with items_key",
        ),
        (
            {
                "operations": ["listRoles"],
                "kind": "simple",
                "paginate": "link_or_body",
                "items_key": "x",
            },
            "users get: items_key x is not a list property of listRoles",
        ),
    ],
)
def test_bad_entry_is_rejected(spec: SpecIndex, entry: dict[str, Any], message: str) -> None:
    errors = _errors({"domains": {"users": {"get": entry}}}, spec)
    assert len(errors) == 1
    assert errors[0].startswith(message)


def test_wrapped_list_entry_is_valid(spec: SpecIndex) -> None:
    entry = {"operations": ["listRoles"], "kind": "simple", "paginate": "link_or_body"}
    doc = {"domains": {"iam": {"list-roles": {**entry, "items_key": "roles"}}}}
    assert report.parse_catalogue(doc, spec)["iam"]["list-roles"]["items_key"] == "roles"


@pytest.mark.parametrize(
    "doc", [None, [], {"domains": []}, {"domains": {"users": []}}, {"other": {}}]
)
def test_malformed_catalogue_is_rejected(spec: SpecIndex, doc: Any) -> None:
    assert _errors(doc, spec)


def test_every_error_is_reported(spec: SpecIndex) -> None:
    doc = {"domains": {"users": {"a": {"kind": "simple"}, "b": {"operations": ["getUser"]}}}}
    assert len(_errors(doc, spec)) == 2


def test_status_of_each_kind(spec: SpecIndex, registry: Registry) -> None:
    catalogue = report.parse_catalogue(CATALOGUE, spec)
    status = report.statuses(catalogue, registry)
    assert status == {
        ("users", "get"): "done",
        ("users", "get-groups"): "done",
        ("users", "get-apps"): "todo",
        ("users", "get-factors-questions"): "excluded",
        ("logs", "timeline"): "deferred",
    }


def test_operation_registered_in_another_domain_does_not_count(
    spec: SpecIndex, registry: Registry
) -> None:
    doc = {"domains": {"apps": {"get-user": {"operations": ["getUser"], "kind": "simple"}}}}
    assert report.statuses(report.parse_catalogue(doc, spec), registry) == {
        ("apps", "get-user"): "todo"
    }


def test_report_contents(spec: SpecIndex, registry: Registry) -> None:
    text = report.render(report.parse_catalogue(CATALOGUE, spec), registry, spec)
    assert f"spec {spec.version}" in text
    summary = text.split("## By domain")[0]
    assert "| simple | 1 | 1 |" in summary
    assert "| resolved | 2 | 1 |" in summary
    assert "| composite (post-v1) | 1 | — |" in summary
    assert "| excluded | 1 | — |" in summary
    assert "| **total** | **5** | **2** |" in summary
    assert "Gotcha endpoints (record a fixture): 1, 1 to do" in summary
    assert "| users | 4 | 1 | 2 | 0 | 1 | 2 | 1 |" in text
    assert "- **users**: get-apps" in text
    # registry commands outside the catalogue
    assert "| groups | get | `getGroup` |" in text
    # spec GET operations nobody covers: not catalogued, not registered
    uncovered = text.split("## Spec GET operations")[1]
    assert "`listGroups`" in uncovered
    for op in ("getUser", "getGroup", "listLogEvents", "listSupportedSecurityQuestions"):
        assert f"`{op}`" not in uncovered


def test_report_is_deterministic(spec: SpecIndex, registry: Registry) -> None:
    catalogue = report.parse_catalogue(CATALOGUE, spec)
    assert report.render(catalogue, registry, spec) == report.render(catalogue, registry, spec)


def test_run_writes_report(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    assert report.run(["--out", str(out)]) == 0
    assert out.read_text().startswith("# Coverage report")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("domains: {users: {get: {operations: [getUser]}}}\n", "users get: kind must be one of"),
        ("domains: {users: {get: {kind: simple\n", "error: while parsing"),
        (
            "domains:\n  users:\n    get: {operations: [getUser], kind: simple}\n"
            "    get: {operations: [getUser], kind: simple}\n",
            "duplicate key",
        ),
        (None, "No such file"),
    ],
)
def test_run_reports_invalid_catalogue(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str | None, message: str
) -> None:
    bad = tmp_path / "catalogue.yaml"
    if text is not None:
        bad.write_text(text)
    out = tmp_path / "report.md"
    assert report.run(["--catalogue", str(bad), "--out", str(out)]) == 2
    assert message in capsys.readouterr().err
    assert not out.exists()
