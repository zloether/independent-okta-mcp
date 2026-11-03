import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx2
import pytest
import yaml
from conftest import load_script

update = load_script("update-spec")

OLD_SHA = "a" * 40
NEW_SHA = "b" * 40


def _op(op_id: str, scope: str = "okta.users.read") -> dict[str, Any]:
    return {
        "operationId": op_id,
        "security": [{"oauth2": [scope]}],
        "responses": {"200": {"description": "ok"}},
    }


OLD_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "Okta Admin Management", "version": "2026.41.0"},
    "paths": {
        "/api/v1/users/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True}],
            "get": _op("getUser"),
            "delete": _op("deleteUser", "okta.users.manage"),
        },
        "/api/v1/groups": {"get": _op("listGroups", "okta.groups.read")},
        "/api/v1/zones": {"get": _op("listNetworkZones", "okta.networkZones.read")},
    },
}


def _new_spec() -> dict[str, Any]:
    spec = copy.deepcopy(OLD_SPEC)
    spec["info"]["version"] = "2026.42.1"
    paths = spec["paths"]
    del paths["/api/v1/zones"]
    paths["/api/v1/groups"]["get"]["security"] = [{"oauth2": ["okta.groups.manage"]}]
    paths["/api/v1/users/{id}"]["delete"]["summary"] = "non-GET change is ignored"
    paths["/api/v1/apps"] = {"get": _op("listApplications", "okta.apps.read"), "post": _op("x")}
    return spec


def _dump(spec: dict[str, Any]) -> bytes:
    return yaml.safe_dump(spec).encode()


class FakeGitHub:
    def __init__(self, sha: str, body: bytes | None, commits: Any = None) -> None:
        self.sha = sha
        self.body = body
        self.commits = commits
        self.requests: list[httpx2.URL] = []

    def client(self) -> httpx2.Client:
        return httpx2.Client(transport=httpx2.MockTransport(self.handle))

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request.url)
        if request.url.host == "api.github.com":
            assert request.url.params["path"] == update.SPEC_PATH
            if self.commits is not None:
                return httpx2.Response(200, json=self.commits)
            return httpx2.Response(
                200,
                json=[{"sha": self.sha, "commit": {"committer": {"date": "2026-10-27T13:04:35Z"}}}],
            )
        raw_path = f"/{update.REPO}/{self.sha}/{update.SPEC_PATH}"
        if self.body is not None and request.url.path == raw_path:
            return httpx2.Response(200, content=self.body)
        return httpx2.Response(404)


def _pin(spec_dir: Path, sha: str, body: bytes) -> None:
    rc = update.run([], http=FakeGitHub(sha, body).client(), spec_dir=spec_dir)
    assert rc == 0


def _snapshot(spec_dir: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in spec_dir.iterdir()}


def test_get_operations_ignores_other_methods() -> None:
    ops = update.get_operations(OLD_SPEC)
    assert set(ops) == {"getUser", "listGroups", "listNetworkZones"}


def test_diff_reports_added_removed_changed_get_operations() -> None:
    added, removed, changed = update.diff(
        update.get_operations(OLD_SPEC), update.get_operations(_new_spec())
    )
    assert added == ["listApplications"]
    assert removed == ["listNetworkZones"]
    assert changed == ["listGroups"]


def test_path_level_parameter_change_counts_as_changed() -> None:
    new = copy.deepcopy(OLD_SPEC)
    new["paths"]["/api/v1/users/{id}"]["parameters"][0]["schema"] = {"pattern": "^00u"}
    _, _, changed = update.diff(update.get_operations(OLD_SPEC), update.get_operations(new))
    assert changed == ["getUser"]


def _ref_spec() -> dict[str, Any]:
    """Path parameter and response schema through $ref, as in the real spec; Group is cyclic."""
    return {
        "openapi": "3.0.3",
        "info": {"version": "1"},
        "paths": {
            "/api/v1/groups/{groupId}": {
                "parameters": [{"$ref": "#/components/parameters/pathGroupId"}],
                "get": {
                    "operationId": "getGroup",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Group"}
                                }
                            }
                        }
                    },
                },
            },
            "/api/v1/users": {"get": _op("listUsers")},
        },
        "components": {
            "parameters": {
                "pathGroupId": {"name": "groupId", "in": "path", "schema": {"type": "string"}}
            },
            "schemas": {
                "Group": {
                    "properties": {"parent": {"$ref": "#/components/schemas/Group"}},
                    # Okta's examples embed JSON Schema documents; their refs are data.
                    "example": {"allOf": [{"$ref": "#/definitions/custom"}]},
                }
            },
        },
    }


@pytest.mark.parametrize(
    "edit",
    [
        lambda c: c["parameters"]["pathGroupId"]["schema"].update(pattern="^00g"),
        lambda c: c["schemas"]["Group"]["properties"].update(name={"type": "string"}),
    ],
)
def test_change_to_referenced_component_counts_as_changed(edit) -> None:
    new = _ref_spec()
    edit(new["components"])
    _, _, changed = update.diff(update.get_operations(_ref_spec()), update.get_operations(new))
    assert changed == ["getGroup"]


@pytest.mark.parametrize(
    "spec",
    [
        {"openapi": "3.0.3", "info": None, "paths": {}},
        {"openapi": "3.0.3", "info": {"version": "1"}, "paths": {"/x": None}},
    ],
)
def test_malformed_spec_is_rejected(spec: dict[str, Any]) -> None:
    with pytest.raises(update.SpecError):
        update.parse(_dump(spec))


@pytest.mark.parametrize(
    ("paths", "message"),
    [
        ({"/x": {"get": {"responses": {}}}}, "GET /x has no operationId"),
        ({"/x": {"get": _op("getX")}, "/y": {"get": _op("getX")}}, "duplicate operationId: getX"),
        (
            {"/x": {"get": {"operationId": "getX", "parameters": [{"$ref": "#/components/no"}]}}},
            "dangling $ref: #/components/no",
        ),
    ],
)
def test_bad_operations_are_rejected(paths: dict[str, Any], message: str) -> None:
    with pytest.raises(update.SpecError, match=message.replace("$", r"\$")):
        update.get_operations({"paths": paths})


def test_first_pin_writes_spec_and_pin(tmp_path: Path) -> None:
    body = _dump(OLD_SPEC)
    github = FakeGitHub(OLD_SHA, body)
    assert update.run([], http=github.client(), spec_dir=tmp_path) == 0

    assert (tmp_path / update.SPEC_FILE).read_bytes() == body
    pin = json.loads((tmp_path / update.PIN_FILE).read_text())
    assert (
        pin["url"]
        == f"https://raw.githubusercontent.com/{update.REPO}/{OLD_SHA}/{update.SPEC_PATH}"
    )
    assert pin["commit"] == OLD_SHA
    assert pin["version"] == "2026.41.0"
    assert pin["sha256"] == hashlib.sha256(body).hexdigest()
    assert pin["fetched"]
    # The download names the resolved commit, never a moving branch.
    assert github.requests[-1].path == f"/{update.REPO}/{OLD_SHA}/{update.SPEC_PATH}"


def test_update_prints_diff_and_rewrites_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _pin(tmp_path, OLD_SHA, _dump(OLD_SPEC))
    capsys.readouterr()
    new_body = _dump(_new_spec())

    assert update.run([], http=FakeGitHub(NEW_SHA, new_body).client(), spec_dir=tmp_path) == 0

    out = capsys.readouterr().out
    assert "+ listApplications" in out
    assert "- listNetworkZones" in out
    assert "~ listGroups" in out
    assert "getUser" not in out
    assert (tmp_path / update.SPEC_FILE).read_bytes() == new_body
    assert json.loads((tmp_path / update.PIN_FILE).read_text())["commit"] == NEW_SHA


def test_check_is_a_no_op_when_up_to_date(tmp_path: Path) -> None:
    body = _dump(OLD_SPEC)
    _pin(tmp_path, OLD_SHA, body)
    before = _snapshot(tmp_path)

    rc = update.run(["--check"], http=FakeGitHub(OLD_SHA, body).client(), spec_dir=tmp_path)

    assert rc == 0
    assert _snapshot(tmp_path) == before


def test_check_reports_newer_spec_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _pin(tmp_path, OLD_SHA, _dump(OLD_SPEC))
    before = _snapshot(tmp_path)
    capsys.readouterr()

    github = FakeGitHub(NEW_SHA, _dump(_new_spec()))
    assert update.run(["--check"], http=github.client(), spec_dir=tmp_path) == 1

    assert "+ listApplications" in capsys.readouterr().out
    assert _snapshot(tmp_path) == before


def test_check_fails_when_local_spec_does_not_match_pin(tmp_path: Path) -> None:
    body = _dump(OLD_SPEC)
    _pin(tmp_path, OLD_SHA, body)
    (tmp_path / update.SPEC_FILE).write_bytes(body + b"# edited\n")

    rc = update.run(["--check"], http=FakeGitHub(OLD_SHA, body).client(), spec_dir=tmp_path)

    assert rc == 2


def test_repin_replaces_spec_that_does_not_match_pin(tmp_path: Path) -> None:
    """A run interrupted between writing the spec and the pin is repaired by a plain re-pin."""
    _pin(tmp_path, OLD_SHA, _dump(OLD_SPEC))
    (tmp_path / update.SPEC_FILE).write_bytes(b"partial")
    new_body = _dump(_new_spec())

    assert update.run([], http=FakeGitHub(NEW_SHA, new_body).client(), spec_dir=tmp_path) == 0

    assert (tmp_path / update.SPEC_FILE).read_bytes() == new_body
    assert sorted(p.name for p in tmp_path.iterdir()) == [update.PIN_FILE, update.SPEC_FILE]


def test_check_with_nothing_pinned_fails_and_writes_nothing(tmp_path: Path) -> None:
    github = FakeGitHub(OLD_SHA, _dump(OLD_SPEC))
    assert update.run(["--check"], http=github.client(), spec_dir=tmp_path) == 2
    assert list(tmp_path.iterdir()) == []
    assert github.requests == []


def test_pin_without_spec_file_fails(tmp_path: Path) -> None:
    _pin(tmp_path, OLD_SHA, _dump(OLD_SPEC))
    (tmp_path / update.SPEC_FILE).unlink()
    github = FakeGitHub(OLD_SHA, _dump(OLD_SPEC))
    assert update.run([], http=github.client(), spec_dir=tmp_path) == 2


@pytest.mark.parametrize("commits", [[], {"message": "Not Found"}])
def test_bad_commit_lookup_writes_nothing(tmp_path: Path, commits: Any) -> None:
    github = FakeGitHub(OLD_SHA, _dump(OLD_SPEC), commits=commits)
    assert update.run([], http=github.client(), spec_dir=tmp_path) == 2
    assert list(tmp_path.iterdir()) == []


def test_ref_is_passed_to_commit_lookup(tmp_path: Path) -> None:
    github = FakeGitHub(OLD_SHA, _dump(OLD_SPEC))
    assert update.run(["--ref", "2026.41.0"], http=github.client(), spec_dir=tmp_path) == 0
    assert github.requests[0].params["sha"] == "2026.41.0"


@pytest.mark.parametrize(
    "body",
    [
        b"<html>not found</html>",
        b"- a list\n",
        _dump({"openapi": "3.0.3", "info": {}}),
        _dump({"openapi": "3.0.3", "info": {"version": "1"}, "paths": {"/x": {"get": {}}}}),
    ],
)
def test_bad_download_writes_nothing(tmp_path: Path, body: bytes) -> None:
    assert update.run([], http=FakeGitHub(OLD_SHA, body).client(), spec_dir=tmp_path) == 2
    assert list(tmp_path.iterdir()) == []


def test_http_error_writes_nothing(tmp_path: Path) -> None:
    github = FakeGitHub(OLD_SHA, None)
    assert update.run([], http=github.client(), spec_dir=tmp_path) == 2
    assert list(tmp_path.iterdir()) == []
