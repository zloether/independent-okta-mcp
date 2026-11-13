import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import pytest
from _load import load_script

from okta_mcp.registry.loader import Command, Registry, load_registry
from okta_mcp.registry.model import ResponseOverride
from okta_mcp.registry.spec import SpecIndex, load_spec

gen = load_script("gen-fixtures")
lib = load_script("fixturelib")

OKTA_ID = re.compile(r"^[0-9a-z]{3}[0-9A-Za-z]{17}$")


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


@pytest.fixture(scope="module")
def registry(spec: SpecIndex) -> Registry:
    return load_registry(spec)


@pytest.fixture(scope="module")
def raw() -> dict[str, Any]:
    return gen.raw_spec()


def synth(schemas: dict[str, Any], node: Any, seed: str = "s") -> Any:
    return gen.Synth({"components": {"schemas": schemas}}, seed).value(node)


# --- schema synthesis ---


def test_scalars_by_format_and_name() -> None:
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "userId": {"type": "string"},
            "created": {"type": "string", "format": "date-time"},
            "email": {"type": "string", "format": "email"},
            "href": {"type": "string"},
            "status": {"type": "string", "enum": ["ACTIVE", "INACTIVE"]},
            "count": {"type": "integer", "minimum": 1},
            "ratio": {"type": "number"},
            "on": {"type": "boolean"},
            "secret": {"type": "string", "writeOnly": True},
            "tags": {"type": "array", "items": {"type": "string"}},
            "kind": {"type": "string", "default": "X"},
        },
    }
    v = synth({}, schema)
    assert OKTA_ID.match(v["id"]) and OKTA_ID.match(v["userId"])
    assert v["id"] != v["userId"]
    assert v["created"] == "2026-01-01T00:00:00.000Z"
    assert v["email"] == "user@example.com"
    assert v["href"] == "https://example.okta.com/"
    assert v["status"] == "ACTIVE"
    assert (v["count"], v["ratio"], v["on"]) == (1, 0, False)
    assert "secret" not in v
    assert v["tags"] == ["tags"]
    assert v["kind"] == "X"


def test_example_wins_over_schema() -> None:
    assert synth({}, {"type": "object", "example": {"a": 1}, "properties": {"b": {}}}) == {"a": 1}
    assert synth({}, {"type": "string", "format": "email", "example": "x@example.com"}) == (
        "x@example.com"
    )


def test_refs_allof_and_first_variant() -> None:
    schemas = {
        "Base": {"type": "object", "properties": {"id": {"type": "string"}}},
        "Child": {"allOf": [{"$ref": "#/components/schemas/Base"}, {"properties": {"x": {}}}]},
        "A": {"type": "object", "properties": {"a": {"type": "boolean"}}},
        "B": {"type": "object", "properties": {"b": {"type": "boolean"}}},
    }
    child = synth(schemas, {"$ref": "#/components/schemas/Child"})
    assert set(child) == {"id", "x"}
    one = synth(schemas, {"oneOf": [{"$ref": "#/components/schemas/A"}, {"$ref": "#/x/B"}]})
    assert one == {"a": False}


def test_recursive_schema_terminates() -> None:
    schemas = {
        "Node": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "child": {"$ref": "#/components/schemas/Node"},
                "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}},
            },
        }
    }
    assert synth(schemas, {"$ref": "#/components/schemas/Node"}) == {
        "name": "name",
        "children": [],
    }


def test_ids_are_deterministic_and_seeded() -> None:
    schema = {"type": "object", "properties": {"id": {"type": "string"}}}
    assert synth({}, schema, "a") == synth({}, schema, "a")
    assert synth({}, schema, "a") != synth({}, schema, "b")
    assert OKTA_ID.match(gen.okta_id("x", "00g")) and gen.okta_id("x", "00g").startswith("00g")


# --- fixture bodies ---


def test_body_uses_first_spec_example(raw: dict[str, Any], registry: Registry) -> None:
    body = gen.body(raw, registry.domains["groups"].commands["get"])
    assert body["id"] == "00g1emaKYZTWRYYRRTSK"  # group-example in the pinned spec
    links = json.dumps(body["_links"])
    assert "{yourOktaDomain}" not in links and "https://example.okta.com/api/v1/groups/" in links


def test_body_is_synthesized_without_examples(raw: dict[str, Any], registry: Registry) -> None:
    command = registry.domains["groups"].commands["get"]
    stripped = json.loads(json.dumps(raw))
    for item in stripped["paths"].values():
        op = item.get("get")
        if op and op["operationId"] == "getGroup":
            op["responses"]["200"]["content"]["application/json"].pop("examples")
    stripped["components"]["schemas"]["Group"]["properties"]["id"].pop("example")
    body = gen.body(stripped, command)
    assert OKTA_ID.match(body["id"])
    assert body["created"] == "2026-01-01T00:00:00.000Z"


def test_empty_example_falls_back_to_schema(raw: dict[str, Any], registry: Registry) -> None:
    command = registry.domains["groups"].commands["get"]
    stripped = json.loads(json.dumps(raw))
    content = stripped["paths"][command.operation.path]["get"]["responses"]["200"]["content"]
    content["application/json"]["examples"] = {"Empty": {"value": {}}}
    stripped["components"]["schemas"]["Group"]["properties"]["id"].pop("example")
    assert OKTA_ID.match(gen.body(stripped, command)["id"])


def test_response_override_wraps_object_in_list(raw: dict[str, Any], registry: Registry) -> None:
    command = registry.domains["groups"].commands["get"]
    override = ResponseOverride(kind="list", reason="test")
    entry = command.entry.model_copy(update={"response_override": override})
    body = gen.body(raw, dataclasses.replace(command, entry=entry))
    assert isinstance(body, list) and body[0]["id"] == "00g1emaKYZTWRYYRRTSK"


def test_array_schema_with_item_examples_is_wrapped(
    raw: dict[str, Any], registry: Registry
) -> None:
    # listAuthenticatorMethods declares an array; each of its examples is one method.
    command = registry.domains["authenticators"].commands["list-methods"]
    body = gen.body(raw, command)
    assert isinstance(body, list) and len(body) == 1 and body[0]["type"] == "nfc_pin"


def _with_example(raw: dict[str, Any], path: str, example: Any) -> dict[str, Any]:
    """`raw` with one 200 example on `path`'s GET; `raw` itself is left alone."""
    op = raw["paths"][path]["get"]
    content = {**op["responses"]["200"]["content"]["application/json"]}
    content["examples"] = {"x": {"value": example}}
    responses = {"200": {"content": {"application/json": content}}}
    return {**raw, "paths": {**raw["paths"], path: {"get": {**op, "responses": responses}}}}


def test_array_schema_keeps_a_wrapper_example(raw: dict[str, Any], registry: Registry) -> None:
    # An example that isn't shaped like an item stays exactly as it is, for the fixture test
    # to refuse: not wrapped, and no view columns filled in.
    command = registry.domains["authenticators"].commands["list-methods"]
    path = command.operation.path
    assert gen.body(_with_example(raw, path, {"items": [1]}), command) == {"items": [1]}
    # `_links` sits on wrappers as well as items, so it doesn't make a wrapper an item.
    wrapper = {"_links": {"self": {"href": "https://example.okta.com/"}}, "items": [1]}
    assert gen.body(_with_example(raw, path, wrapper), command) == wrapper


def test_view_path_missing_from_example_is_filled(raw: dict[str, Any], registry: Registry) -> None:
    # The pinned spec's listUserGroups example has no `type`; the schema gives one.
    command = registry.domains["users"].commands["get-groups"]
    example = raw["components"]["examples"]
    body = gen.body(raw, command)
    assert body[0]["type"] in {"OKTA_GROUP", "APP_GROUP", "BUILT_IN"}
    assert all("type" not in item for item in body[1:])  # only the first item gains it
    assert body[0]["profile"]["name"] == "Cloud app users"  # the example is kept
    assert example == raw["components"]["examples"]  # the spec isn't modified


def test_view_path_in_example_is_left_alone(raw: dict[str, Any], registry: Registry) -> None:
    command = registry.domains["groups"].commands["list"]
    filled = gen.body(raw, command)
    plain = gen.body(
        raw, dataclasses.replace(command, entry=command.entry.model_copy(update={"view": None}))
    )
    assert filled == plain


def _cmd(registry: Registry, view: tuple[str, ...]) -> Command:
    command = registry.domains["groups"].commands["get"]
    return dataclasses.replace(command, entry=command.entry.model_copy(update={"view": view}))


def test_fill_view_skips_a_path_through_a_non_object(registry: Registry) -> None:
    built = {"profile": {"name": "x"}, "tags": ["a"]}
    for example in ({"profile": None}, {"profile": ["a"]}, {"profile": "s"}):
        out = gen._fill_view(example, lambda: built, _cmd(registry, ("profile.name",)))
        assert out == example  # no TypeError, nothing written


def test_fill_view_treats_empty_lists_as_blank(registry: Registry) -> None:
    out = gen._fill_view({"tags": []}, lambda: {"tags": ["a"]}, _cmd(registry, ("tags",)))
    assert out == {"tags": ["a"]}


def test_fill_view_synthesizes_only_when_needed(registry: Registry) -> None:
    def fail() -> Any:
        raise AssertionError("synthesized")

    example = {"id": "00g1emaKYZTWRYYRRTSK"}
    assert gen._fill_view(example, fail, _cmd(registry, ("id",))) == example


def test_fill_view_does_not_change_its_input(registry: Registry) -> None:
    example = {"id": "x"}
    gen._fill_view(example, lambda: {"id": "x", "type": "OKTA_GROUP"}, _cmd(registry, ("type",)))
    assert example == {"id": "x"}


# --- neutralizing (shared with sanitize-fixture.py) ---


def test_neutralizer_rewrites_consistently() -> None:
    n = lib.Neutralizer()
    out = n(
        {
            "a": "https://{yourOktaDomain}/api/v1/users",
            "b": "${yourOktaDomain}",
            "c": ["https://acme.test/x", "http://acme.test:8443/y", "https://other.test"],
            "d": "jane@acme.test, Jane@ACME.test, bob@acme.test, ok@example.com, n@example.net",
            "e": "https://dev-1.okta.com/a https://dev-1-admin.okta.com/b dev-1.oktapreview.com",
            "f": "8.8.4.4/32 8.8.4.4-8.8.8.8 10.0.0.1 2606:4700::1111 2001:db8::5",
            "g": "https://user:pw@acme.test/",
            "h": "10:11:28 aa:bb:cc:dd:ee:ff http://localhost:8080 https://idp.example.com",
        }
    )
    assert out["a"] == "https://example.okta.com/api/v1/users"
    assert out["b"] == "example.okta.com"
    assert out["c"] == [
        "https://host-1.example.com/x",
        "http://host-1.example.com:8443/y",
        "https://host-2.example.com",
    ]
    assert out["d"] == (
        "user-1@example.com, user-1@example.com, user-2@example.com, ok@example.com, "
        "user-3@example.com"
    )
    assert out["e"] == (
        "https://example.okta.com/a https://example-admin.okta.com/b example.okta.com"
    )
    assert out["f"] == "203.0.113.1/32 203.0.113.1-203.0.113.2 10.0.0.1 2001:db8::1 2001:db8::5"
    assert out["g"] == "https://user@host-1.example.com/"
    assert out["h"] == "10:11:28 aa:bb:cc:dd:ee:ff http://localhost:8080 https://idp.example.com"


def test_neutralizer_leaves_keys() -> None:
    assert lib.Neutralizer()({"jane@acme.test": 1}) == {"jane@acme.test": 1}


# --- writing and --check ---


def test_main_writes_then_check_is_clean(tmp_path: Path) -> None:
    assert gen.main(["--domain", "network-zones"], root=tmp_path) == 0
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*.json"))
    assert written == ["network-zones/get.json", "network-zones/list.json"]
    doc = json.loads((tmp_path / "network-zones" / "list.json").read_text())
    assert doc["source"] == "generated" and doc["operation"] == "listNetworkZones"
    assert gen.main(["--domain", "network-zones", "--check"], root=tmp_path) == 0
    assert gen.main(["--check"], root=tmp_path) == 1  # groups missing
    (tmp_path / "groups").mkdir()
    (tmp_path / "groups" / "gone.json").write_text("{}")
    assert gen.main(["--domain", "network-zones", "--check"], root=tmp_path) == 0


def test_check_reports_stale_missing_and_orphans(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gen.main([], root=tmp_path) == 0
    (tmp_path / "groups" / "get.json").write_text("{}")
    (tmp_path / "groups" / "list.json").unlink()
    (tmp_path / "groups" / "gone.json").write_text('{"source": "generated"}')
    capsys.readouterr()
    assert gen.main(["--check"], root=tmp_path) == 1
    out = capsys.readouterr().out.splitlines()
    assert sorted(out) == [
        "groups/get.json: out of date",
        "groups/gone.json: no such command",
        "groups/list.json: missing",
    ]


def test_recorded_fixture_is_never_overwritten(tmp_path: Path) -> None:
    recorded = tmp_path / "network-zones" / "get.json"
    recorded.parent.mkdir()
    text = '{"source": "recorded", "operation": "getNetworkZone", "body": {}}\n'
    recorded.write_text(text)
    assert gen.main(["--domain", "network-zones"], root=tmp_path) == 0
    assert recorded.read_text() == text
    assert gen.main(["--domain", "network-zones", "--check"], root=tmp_path) == 0


def test_malformed_fixture_is_reported_then_regenerated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "network-zones" / "get.json"
    bad.parent.mkdir()
    bad.write_text("[1,")
    assert gen.main(["--domain", "network-zones", "--check"], root=tmp_path) == 1
    assert "network-zones/get.json: out of date" in capsys.readouterr().out
    assert gen.main(["--domain", "network-zones"], root=tmp_path) == 0
    assert json.loads(bad.read_text())["source"] == "generated"


def test_spec_error_while_planning_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*_: Any) -> Any:
        raise gen.SpecError("allOf cycle")

    monkeypatch.setattr(gen, "plan", broken)
    assert gen.main(["--check"], root=tmp_path) == 2
    assert "allOf cycle" in capsys.readouterr().err


def test_unknown_domain(tmp_path: Path) -> None:
    assert gen.main(["--domain", "nope"], root=tmp_path) == 2


def test_one_item_list_example_under_object_schema_is_unwrapped(
    raw: dict[str, Any], registry: Registry
) -> None:
    # getOAuth2Claim's 200 example is the list operation's: one claim in an array.
    command = registry.domains["authorization-servers"].commands["get-claim"]
    body = gen.body(raw, command)
    assert isinstance(body, dict) and body["claimType"] == "IDENTITY"


def test_wrapped_override_puts_the_list_under_items_key(
    raw: dict[str, Any], registry: Registry
) -> None:
    command = registry.domains["authorization-servers"].commands["list-resource-server-keys"]
    body = gen.body(raw, command)
    assert isinstance(body, dict) and set(body) == {"keys"}
    assert isinstance(body["keys"], list) and body["keys"][0]["kty"] == "RSA"


def test_bare_list_example_under_wrapper_schema_is_wrapped(
    raw: dict[str, Any], registry: Registry
) -> None:
    # listOktaSupportCases: the schema is {"supportCases": [...]}, the example the bare list.
    command = registry.domains["org-settings"].commands["list-support-cases"]
    body = gen.body(raw, command)
    assert isinstance(body, dict) and set(body) == {"supportCases"}
    assert isinstance(body["supportCases"], list) and body["supportCases"][0]["caseNumber"]
