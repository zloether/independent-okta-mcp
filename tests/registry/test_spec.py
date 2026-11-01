import time
from typing import Any

import pytest

from okta_mcp.registry.spec import SpecError, SpecIndex, build_index, load_spec


@pytest.fixture(scope="module")
def pinned() -> SpecIndex:
    return load_spec()


def test_load_time_under_two_seconds() -> None:
    start = time.perf_counter()
    load_spec()
    assert time.perf_counter() - start < 2


def test_known_operations_resolve(pinned: SpecIndex) -> None:
    get_user = pinned.operations["getUser"]
    assert get_user.path == "/api/v1/users/{id}"
    assert get_user.params["id"].location == "path"
    assert get_user.params["id"].required
    assert get_user.scopes == frozenset({"okta.users.read"})
    assert get_user.tags == ("User",)
    assert get_user.response.kind == "object"

    groups = pinned.operations["listUserGroups"]
    assert groups.path == "/api/v1/users/{id}/groups"
    assert {"id", "after", "limit"} <= groups.params.keys()
    assert groups.params["after"].location == "query"
    assert groups.response.kind == "list"

    enrollments = pinned.operations["listAuthenticatorEnrollments"]
    assert enrollments.params["userId"].location == "path"
    assert enrollments.params["discloseIdentifiers"].location == "query"


def test_non_get_operations_absent(pinned: SpecIndex) -> None:
    assert "createUser" not in pinned.operations
    assert pinned.non_get["createUser"] == "post"
    assert pinned.non_get["deleteUser"] == "delete"
    assert not pinned.operations.keys() & pinned.non_get.keys()


def test_operations_without_oauth2_have_empty_scopes(pinned: SpecIndex) -> None:
    assert pinned.operations["listSupportedSecurityQuestions"].scopes == frozenset()


def test_query_param_schema_keeps_enum_and_type(pinned: SpecIndex) -> None:
    zones = pinned.operations["listNetworkZones"]
    assert zones.params["limit"].schema["type"] == "integer"
    assert zones.response.kind == "list"


def test_wrapped_response_reports_list_key_and_next_link(pinned: SpecIndex) -> None:
    response = pinned.operations["listResourceSets"].response
    assert response.kind == "object"
    assert response.list_keys == ("resource-sets",)
    assert response.links_next


def _spec(paths: dict[str, Any], components: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"version": "1"},
        "paths": paths,
        "components": components or {},
    }


def _ok(schema: dict[str, Any]) -> dict[str, Any]:
    return {"200": {"content": {"application/json": {"schema": schema}}}}


def test_operation_level_param_overrides_path_level() -> None:
    spec = _spec(
        {
            "/x/{id}": {
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
                "get": {
                    "operationId": "getX",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string", "pattern": "^x$"},
                        },
                        {"name": "If-None-Match", "in": "header", "schema": {"type": "string"}},
                    ],
                    "responses": _ok({"type": "object"}),
                },
            }
        }
    )
    op = build_index(spec).operations["getX"]
    assert op.params["id"].schema == {"type": "string", "pattern": "^x$"}
    assert op.params["id"].required
    assert "If-None-Match" not in op.params


def test_param_and_schema_refs_are_inlined() -> None:
    spec = _spec(
        {
            "/x": {
                "get": {
                    "operationId": "listX",
                    "parameters": [{"$ref": "#/components/parameters/status"}],
                    "responses": _ok(
                        {"type": "array", "items": {"$ref": "#/components/schemas/X"}}
                    ),
                }
            }
        },
        {
            "parameters": {
                "status": {
                    "name": "status",
                    "in": "query",
                    "schema": {"$ref": "#/components/schemas/Status"},
                }
            },
            "schemas": {"Status": {"type": "string", "enum": ["A", "B"]}, "X": {"type": "object"}},
        },
    )
    op = build_index(spec).operations["listX"]
    assert op.params["status"].schema == {"type": "string", "enum": ["A", "B"]}
    assert op.response.kind == "list"


def test_scopes_union_across_oauth2_entries() -> None:
    spec = _spec(
        {
            "/x": {
                "get": {
                    "operationId": "getX",
                    "security": [{"apiToken": []}, {"oauth2": ["a.read"]}, {"oauth2": ["b.read"]}],
                    "responses": _ok({"type": "object"}),
                }
            }
        }
    )
    assert build_index(spec).operations["getX"].scopes == frozenset({"a.read", "b.read"})


@pytest.mark.parametrize(
    ("schema", "kind", "list_keys", "links_next"),
    [
        ({"type": "array"}, "list", (), False),
        ({"type": "object", "properties": {"id": {"type": "string"}}}, "object", (), False),
        (
            {
                "allOf": [
                    {"properties": {"items": {"type": "array"}}},
                    {"properties": {"_links": {"properties": {"next": {"type": "object"}}}}},
                ]
            },
            "object",
            ("items",),
            True,
        ),
        ({"oneOf": [{"type": "object"}, {"type": "array"}]}, "other", (), False),
    ],
)
def test_response_shapes(
    schema: dict[str, Any], kind: str, list_keys: tuple[str, ...], links_next: bool
) -> None:
    spec = _spec({"/x": {"get": {"operationId": "getX", "responses": _ok(schema)}}})
    response = build_index(spec).operations["getX"].response
    assert (response.kind, response.list_keys, response.links_next) == (kind, list_keys, links_next)


def test_non_json_response_is_other() -> None:
    responses = {"200": {"content": {"text/csv": {"schema": {"type": "string"}}}}}
    spec = _spec({"/x": {"get": {"operationId": "getX", "responses": responses}}})
    assert build_index(spec).operations["getX"].response.kind == "other"


@pytest.mark.parametrize(
    "paths",
    [
        {"/x": {"get": {"responses": {}}}},
        {
            "/x": {"get": {"operationId": "dup", "responses": {}}},
            "/y": {"get": {"operationId": "dup", "responses": {}}},
        },
        {"/x": {"get": {"operationId": "getX", "parameters": [{"$ref": "#/components/nope"}]}}},
    ],
    ids=["missing-operationId", "duplicate-operationId", "dangling-ref"],
)
def test_malformed_specs_raise(paths: dict[str, Any]) -> None:
    with pytest.raises(SpecError):
        build_index(_spec(paths))
