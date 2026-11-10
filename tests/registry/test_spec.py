import time
from typing import Any

import pytest

from okta_mcp.registry.spec import SpecError, SpecIndex, build_index, load_spec


@pytest.fixture(scope="module")
def timed_load() -> tuple[SpecIndex, float]:
    start = time.perf_counter()
    index = load_spec()
    return index, time.perf_counter() - start


@pytest.fixture(scope="module")
def pinned(timed_load: tuple[SpecIndex, float]) -> SpecIndex:
    return timed_load[0]


def test_load_time_within_budget(timed_load: tuple[SpecIndex, float]) -> None:
    # A guard against a load that grows with the square of the spec, not a benchmark: parsing
    # the 3.9 MB YAML alone takes about 1.8 s on Python 3.12 (1.3 s on 3.13), and a shared CI
    # runner is slower still, so a 2 s limit failed there without any change to the load.
    assert timed_load[1] < 5


def test_known_operations_resolve(pinned: SpecIndex) -> None:
    get_user = pinned.operations["getUser"]
    assert get_user.path == "/api/v1/users/{id}"
    assert get_user.params["id"].location == "path"
    assert get_user.params["id"].required
    assert get_user.scope_sets == (frozenset({"okta.users.read"}),)
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


def test_operations_without_oauth2_have_no_scope_sets(pinned: SpecIndex) -> None:
    assert pinned.operations["listSupportedSecurityQuestions"].scope_sets == ()


def test_oauth2_entries_are_alternatives(pinned: SpecIndex) -> None:
    assert pinned.operations["getApplicationsCsvExport"].scope_sets == (
        frozenset({"okta.apps.read"}),
        frozenset({"okta.apps.read", "okta.governance.labels.read"}),
    )


def test_path_params_required_even_when_spec_omits_flag(pinned: SpecIndex) -> None:
    assert pinned.operations["getHookKey"].params["id"].required


def test_single_resource_with_scalar_arrays_has_no_list_keys(pinned: SpecIndex) -> None:
    assert pinned.operations["getGroup"].response.list_keys == ()
    assert pinned.operations["getSession"].response.list_keys == ()


def test_query_param_schema_keeps_enum_and_type(pinned: SpecIndex) -> None:
    zones = pinned.operations["listNetworkZones"]
    assert zones.params["limit"].schema["type"] == "integer"
    assert zones.response.kind == "list"


def test_wrapped_response_reports_list_key_and_next_link(pinned: SpecIndex) -> None:
    response = pinned.operations["listResourceSets"].response
    assert response.kind == "object"
    assert response.list_keys == ("resource-sets",)
    assert response.links_next


def test_response_fields_cover_nested_paths(pinned: SpecIndex) -> None:
    users = pinned.operations["listUsers"].response
    assert {"id", "status", "profile.login", "lastLogin"} <= users.fields
    assert pinned.operations["listResourceSets"].response.item_fields["resource-sets"] >= {
        "id",
        "label",
    }


def test_polymorphic_fields_are_the_base_schema(pinned: SpecIndex) -> None:
    apps = pinned.operations["listApplications"].response.fields
    assert {"id", "label", "signOnMode"} <= apps
    assert "settings" not in apps  # subtype-only (discriminator mapping)
    roles = pinned.operations["listAssignedRolesForUser"].response.fields
    assert {"id", "type", "label", "status"} <= roles  # StandardRole ∩ CustomRole


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


def test_query_explode_follows_the_spec_and_defaults_to_true(pinned: SpecIndex) -> None:
    assert not pinned.operations["getBrand"].params["expand"].explode
    assert pinned.operations["listAuthenticatorEnrollments"].params["discloseIdentifiers"].explode


def test_unsupported_query_style_is_an_error() -> None:
    param = {"name": "a", "in": "query", "style": "pipeDelimited", "schema": {"type": "array"}}
    spec = _spec(
        {"/x": {"get": {"operationId": "getX", "parameters": [param], "responses": _ok({})}}}
    )
    with pytest.raises(SpecError, match="getX: a has unsupported style pipeDelimited"):
        build_index(spec)


def test_scope_sets_one_per_oauth2_entry_and_empty_entries_dropped() -> None:
    security = [
        {"apiToken": []},
        {"oauth2": ["b.read", "a.read"]},
        {"oauth2": ["a.read"]},
        {"oauth2": []},
        {"oauth2": ["a.read"]},
    ]
    spec = _spec({"/x": {"get": {"operationId": "getX", "security": security, "responses": {}}}})
    assert build_index(spec).operations["getX"].scope_sets == (
        frozenset({"a.read"}),
        frozenset({"a.read", "b.read"}),
    )


def test_unflagged_path_param_is_required() -> None:
    params = [{"name": "id", "in": "path", "schema": {"type": "string"}}]
    spec = _spec({"/x/{id}": {"get": {"operationId": "getX", "parameters": params}}})
    assert build_index(spec).operations["getX"].params["id"].required


@pytest.mark.parametrize(
    ("schema", "kind", "list_keys", "links_next"),
    [
        ({"type": "array"}, "list", (), False),
        ({"type": "object", "properties": {"id": {"type": "string"}}}, "object", (), False),
        (
            {
                "allOf": [
                    {"properties": {"items": {"type": "array", "items": {"type": "object"}}}},
                    {"properties": {"_links": {"properties": {"next": {"type": "object"}}}}},
                ]
            },
            "object",
            ("items",),
            True,
        ),
        (
            {
                "type": "object",
                "properties": {
                    "amr": {"type": "array", "items": {"type": "string"}},
                    "odd": True,
                },
            },
            "object",
            (),
            False,
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


def test_response_fields() -> None:
    components = {
        "schemas": {
            "Node": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "parent": {"$ref": "#/components/schemas/Node"},
                    "tags": {"type": "array", "items": {"type": "object", "properties": {"k": {}}}},
                },
            },
            "Base": {
                "type": "object",
                "properties": {"id": {}, "kind": {}},
                "discriminator": {
                    "propertyName": "kind",
                    "mapping": {"a": "#/components/schemas/A"},
                },
            },
            "A": {"allOf": [{"$ref": "#/components/schemas/Base"}, {"properties": {"a": {}}}]},
            "B": {"properties": {"id": {}, "b": {}, "meta": {"properties": {"x": {}, "y": {}}}}},
            "C": {"properties": {"id": {}, "c": {}, "meta": {"properties": {"x": {}}}}},
        }
    }

    def fields(schema: dict[str, Any]) -> frozenset[str]:
        paths = {"/x": {"get": {"operationId": "getX", "responses": _ok(schema)}}}
        return build_index(_spec(paths, components)).operations["getX"].response.fields

    ref = {"$ref": "#/components/schemas/Node"}
    # A schema repeated on its own path is a leaf; so are arrays.
    assert fields(ref) == {"name", "parent", "tags"}
    assert fields({"type": "array", "items": {"$ref": "#/components/schemas/Base"}}) == {
        "id",
        "kind",
    }
    one_of = {"oneOf": [{"$ref": "#/components/schemas/B"}, {"$ref": "#/components/schemas/C"}]}
    assert fields({"type": "array", "items": one_of}) == {"id", "meta", "meta.x"}

    wrapped = {"properties": {"items": {"type": "array", "items": ref}}}
    paths = {"/x": {"get": {"operationId": "getX", "responses": _ok(wrapped)}}}
    response = build_index(_spec(paths, components)).operations["getX"].response
    assert response.item_fields["items"] == fields(ref)
    assert response.list_keys == ("items",)


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
        {"/x/{id}": {"get": {"operationId": "getX"}}},
        {
            "/x": {
                "get": {
                    "operationId": "getX",
                    "parameters": [{"name": "id", "in": "path", "schema": {}}],
                }
            }
        },
        {"/x": {"get": {"operationId": "getX", "parameters": [{"name": "q"}]}}},
        {"/x": {"$ref": "#/components/pathItems/x"}},
        {"/x": {"get": {"operationId": "getX", "responses": _ok({"$ref": "#/components/A"})}}},
    ],
    ids=[
        "missing-operationId",
        "duplicate-operationId",
        "dangling-ref",
        "template-var-without-param",
        "path-param-not-in-template",
        "param-missing-in",
        "path-item-ref",
        "allOf-cycle",
    ],
)
def test_malformed_specs_raise(paths: dict[str, Any]) -> None:
    components = {
        "A": {"allOf": [{"$ref": "#/components/B"}]},
        "B": {"allOf": [{"$ref": "#/components/A"}]},
    }
    with pytest.raises(SpecError):
        build_index(_spec(paths, components))


def test_reserved_path_literals_from_the_pinned_spec(pinned: SpecIndex) -> None:
    # `/api/v1/groups/rules` is listGroupRules; `/api/v1/apps/export` a CSV export.
    assert pinned.operations["getGroup"].reserved == {"groupId": frozenset({"rules"})}
    assert pinned.operations["listGroupUsers"].reserved == {"groupId": frozenset({"rules"})}
    assert {"export", "search", "types"} <= pinned.operations["getApplication"].reserved["appId"]
    assert {"catalog", "questions"} <= pinned.operations["getFactor"].reserved["factorId"]
    assert pinned.operations["getNetworkZone"].reserved == {}
    assert "userId" not in pinned.operations["getFactor"].reserved


def test_reserved_path_literals() -> None:
    def op(op_id: str, *names: str) -> dict[str, Any]:
        params = [{"name": n, "in": "path", "schema": {"type": "string"}} for n in names]
        return {"operationId": op_id, "parameters": params, "responses": {}}

    spec = {
        "info": {"version": "1"},
        "paths": {
            "/things/{id}": {"get": op("getThing", "id")},
            "/things/Export": {"get": op("exportThings")},
            # Non-GET only, and longer than the template: still a name Okta routes elsewhere.
            "/things/me/reset": {"post": op("resetMine")},
            "/things/{id}/parts/{partId}": {"get": op("getPart", "id", "partId")},
            "/things/{id}/parts/catalog": {"get": op("listCatalog", "id")},
            # A literal where the template has a variable earlier on is a compatible prefix.
            "/things/Export/parts/all": {"get": op("exportParts")},
            "/others/{id}/parts/none": {"get": op("otherParts", "id")},
            "/things": {"get": op("listThings")},
        },
    }
    ops = build_index(spec).operations
    assert ops["getThing"].reserved == {"id": frozenset({"export", "me"})}
    assert ops["getPart"].reserved == {
        "id": frozenset({"export", "me"}),
        "partId": frozenset({"catalog", "all"}),
    }
    assert ops["listCatalog"].reserved == {"id": frozenset({"export", "me"})}
    assert ops["listThings"].reserved == {}
