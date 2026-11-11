import copy
from pathlib import Path
from typing import Any

import pytest

from okta_mcp.registry.loader import RegistryError, build_registry, load_registry
from okta_mcp.registry.model import SENSITIVITY
from okta_mcp.registry.spec import SpecIndex, build_index, load_spec


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


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


def _doc(**commands: dict[str, Any]) -> dict[str, Any]:
    return {"domain": "users", "description": "Read users.", "commands": commands}


def _build(spec: SpecIndex, **commands: dict[str, Any]):
    return build_registry({"users.yaml": _doc(**commands)}, spec)


def _with(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    cmd = copy.deepcopy(base)
    for k, v in changes.items():
        if v is None:
            cmd.pop(k, None)
        else:
            cmd[k] = v
    return cmd


def test_valid_registry_loads(spec: SpecIndex) -> None:
    registry = _build(spec, get=GET, **{"get-groups": GET_GROUPS})
    users = registry.domains["users"]
    assert users.description == "Read users."
    get, groups = users.commands["get"], users.commands["get-groups"]
    assert (get.is_list, groups.is_list) == (False, True)
    assert get.operation.path == "/api/v1/users/{id}"
    assert get.sensitivity == "normal"
    assert groups.scope_sets == (frozenset({"okta.users.read"}),)


def test_registry_is_immutable(spec: SpecIndex) -> None:
    registry = _build(spec, get=GET)
    with pytest.raises(TypeError):
        registry.domains["x"] = registry.domains["users"]  # type: ignore[index]
    with pytest.raises(AttributeError):
        registry.domains["users"].commands["get"].sensitivity = "sensitive"  # type: ignore[misc]


def test_resolved_command_adds_get_user_scopes_to_each_alternative() -> None:
    def op(security: list[dict[str, list[str]]]) -> dict[str, Any]:
        return {
            "get": {
                "operationId": "",
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
                "security": security,
                "responses": {},
            }
        }

    paths = {
        "/users/{id}": op([{"oauth2": ["u.read"]}]),
        "/x/{id}": op([{"oauth2": ["a"]}, {"oauth2": ["b"]}]),
    }
    paths["/users/{id}"]["get"]["operationId"] = "getUser"
    paths["/x/{id}"]["get"]["operationId"] = "getX"
    index = build_index({"info": {"version": "1"}, "paths": paths})
    cmd = {"operation": "getX", "summary": "X", "data_classes": ["pii"]}
    plain = _with(cmd, args={"x": {"path_param": "id"}})
    resolved = _with(cmd, args={"x": {"path_param": "id", "resolve": "user_id"}})
    commands = (
        build_registry(
            {
                "users.yaml": _doc(
                    plain=plain, resolved=_with(resolved, data_classes=["org-config"])
                )
            },
            index,
        )
        .domains["users"]
        .commands
    )
    assert commands["plain"].scope_sets == (frozenset({"a"}), frozenset({"b"}))
    assert commands["resolved"].scope_sets == (
        frozenset({"a", "u.read"}),
        frozenset({"b", "u.read"}),
    )


def test_sensitivity_is_derived_from_data_classes(spec: SpecIndex) -> None:
    enrollments = {
        "operation": "listAuthenticatorEnrollments",
        "summary": "Authenticator enrollments",
        "args": {
            "user": {"path_param": "userId", "resolve": "user_id"},
            "disclose_identifiers": {
                "query": "discloseIdentifiers",
                "arg_rule": {"raises_sensitivity_to": "sensitive"},
            },
        },
        "response_override": {"kind": "list", "reason": "spec declares one object (V8)"},
        "view": ["id", "type", "status", "name"],
        "data_classes": ["mfa-state", "pii"],
    }
    cmd = _build(spec, **{"get-enrollments": enrollments}).domains["users"].commands
    assert cmd["get-enrollments"].sensitivity == "sensitive"
    assert cmd["get-enrollments"].is_list


def test_sensitivity_table_covers_known_classes() -> None:
    assert {c for c, s in SENSITIVITY.items() if s == "normal"} == {"pii", "org-config"}


def test_items_key_selects_wrapped_list(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listResourceSets",
        "summary": "Resource sets",
        "paginate": "link_or_body",
        "items_key": "resource-sets",
        "view": ["id", "label"],
        "data_classes": ["admin-roles"],
    }
    registry = build_registry(
        {"iam.yaml": {"domain": "iam", "description": "IAM.", "commands": {"list": cmd}}}, spec
    )
    assert registry.domains["iam"].commands["list"].is_list


def test_items_key_on_paged_value_list(spec: SpecIndex) -> None:
    cmd = {
        "operation": "getIdentitySourceGroupMemberships",
        "summary": "External IDs of a group's members",
        "args": {
            "source": {"path_param": "identitySourceId"},
            "group": {"path_param": "groupOrExternalId"},
        },
        "paginate": "link",
        "items_key": "memberExternalIds",
        "data_classes": ["pii"],
    }
    assert _build(spec, members=cmd).domains["users"].commands["members"].is_list
    with pytest.raises(RegistryError, match="pages with after; set items_key"):
        _build(spec, members=_with(cmd, items_key=None, paginate=None))


def test_links_next_on_single_resource_needs_no_paginate(spec: SpecIndex) -> None:
    cmd = {
        "operation": "getIdentityProviderApplicationUser",
        "summary": "An IdP-linked user",
        "args": {"idp": {"path_param": "idpId"}, "user": {"path_param": "userId"}},
        "data_classes": ["pii"],
    }
    assert not _build(spec, linked=cmd).domains["users"].commands["linked"].is_list


def test_list_without_item_fields_needs_no_view(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listInterclientAllowedApplications",
        "summary": "Allowed interclient apps",
        "args": {"app": {"path_param": "appId"}},
        "paginate": "link",
        "data_classes": ["org-config"],
    }
    assert _build(spec, allowed=cmd).domains["users"].commands["allowed"].is_list


def test_required_limit_needs_page_size() -> None:
    op = {
        "operationId": "listX",
        "parameters": [{"name": "limit", "in": "query", "required": True}],
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x": {"get": op}}})
    cmd = {"operation": "listX", "summary": "X", "data_classes": ["pii"]}
    with pytest.raises(RegistryError, match="required query param limit has no arg"):
        _build(index, x=cmd)
    _build(index, x=_with(cmd, page_size=20))


def test_polymorphic_view_uses_base_schema(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listApplications",
        "summary": "Apps",
        "paginate": "link",
        "view": ["id", "label", "signOnMode", "status"],
        "data_classes": ["org-config"],
    }
    doc = {"domain": "apps", "description": "Apps.", "commands": {"list": cmd}}
    build_registry({"apps.yaml": doc}, spec)
    # `settings` exists only on some application subtypes.
    doc["commands"]["list"]["view"] = ["id", "settings"]
    with pytest.raises(RegistryError, match="view path settings"):
        build_registry({"apps.yaml": doc}, spec)


def test_scopes_override_for_operation_without_oauth2(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listSupportedSecurityQuestions",
        "summary": "Security questions",
        "args": {"user": {"path_param": "userId"}},
        "view": ["question", "questionText"],
        "data_classes": ["mfa-state"],
        "okta_scopes_override": {"scopes": ["okta.users.read"], "reason": "test"},
    }
    commands = _build(spec, questions=cmd).domains["users"].commands
    assert commands["questions"].scope_sets == (frozenset({"okta.users.read"}),)


def test_shared_operation_allowed_when_classification_differs(spec: SpecIndex) -> None:
    other = _with(GET, data_classes=["pii", "org-config"])
    assert len(_build(spec, get=GET, other=other).domains["users"].commands) == 2


def test_load_registry_from_directory(spec: SpecIndex, tmp_path: Path) -> None:
    (tmp_path / "users.yaml").write_text(
        "domain: users\ndescription: Read users.\ncommands:\n"
        "  get:\n    operation: getUser\n    summary: Get a user\n"
        "    args: {user: {path_param: id}}\n    data_classes: [pii]\n"
    )
    (tmp_path / "README.md").write_text("ignored")
    assert list(load_registry(spec, tmp_path).domains) == ["users"]
    assert load_registry(spec, tmp_path / "missing").domains == {}


_GET_YAML = (
    "domain: users\ndescription: Read users.\ncommands:\n"
    "  get:\n    operation: getUser\n    summary: Get a user\n"
    "    args:\n      user: {path_param: id}\n    data_classes: [mfa-state]\n"
)


@pytest.mark.parametrize(
    ("text", "key"),
    [
        (_GET_YAML + "  get:\n    operation: getUser\n", "'get'"),
        (_GET_YAML + "    data_classes: [pii]\n", "'data_classes'"),
        (_GET_YAML.replace("{path_param: id}\n", "{path_param: id}\n      user: {}\n"), "'user'"),
        (
            _GET_YAML.replace(
                "{path_param: id}", "{path_param: id, arg_rule: {forbidden: true}, arg_rule: {}}"
            ),
            "'arg_rule'",
        ),
    ],
    ids=["command", "data-classes", "arg", "arg-rule"],
)
def test_duplicate_yaml_keys_are_errors(
    spec: SpecIndex, tmp_path: Path, text: str, key: str
) -> None:
    (tmp_path / "users.yaml").write_text(text)
    with pytest.raises(RegistryError, match=f"users.yaml: .*duplicate key {key}"):
        load_registry(spec, tmp_path)


def test_yaml_merge_keys_may_be_overridden(spec: SpecIndex, tmp_path: Path) -> None:
    (tmp_path / "users.yaml").write_text(
        _GET_YAML.replace("  get:\n", "  get: &get\n")
        + "  get-again:\n    <<: *get\n    data_classes: [mfa-state, pii]\n"
    )
    commands = load_registry(spec, tmp_path).domains["users"].commands
    assert commands["get-again"].entry.data_classes == ("mfa-state", "pii")


def test_unhashable_yaml_key_is_a_registry_error(spec: SpecIndex, tmp_path: Path) -> None:
    (tmp_path / "users.yaml").write_text(_GET_YAML + "? [1]\n: x\n")
    with pytest.raises(RegistryError, match=r"(?s)users\.yaml: .*unhashable key"):
        load_registry(spec, tmp_path)


def test_errors_from_every_file_are_reported(spec: SpecIndex, tmp_path: Path) -> None:
    (tmp_path / "apps.yml").write_text("")
    (tmp_path / "groups.yaml").write_text("a: 1\na: 2\n")
    (tmp_path / "users.yaml").write_text(_GET_YAML.replace("getUser", "getNope"))
    with pytest.raises(RegistryError) as e:
        load_registry(spec, tmp_path)
    assert [err.split(":")[0] for err in e.value.errors] == [
        "apps.yml",
        "groups.yaml",
        "users.yaml",
    ]


def test_packaged_registry_loads(spec: SpecIndex) -> None:
    load_registry(spec)


def test_all_errors_are_reported(spec: SpecIndex) -> None:
    with pytest.raises(RegistryError) as e:
        _build(spec, a=_with(GET, operation="nope"), b=_with(GET, operation="deleteUser"))
    assert len(e.value.errors) == 2


_FAILURES: dict[str, tuple[dict[str, Any], str]] = {
    # Check 1
    "non-get-operation": (_with(GET, operation="deleteUser"), "is DELETE; only GET"),
    "unknown-operation": (_with(GET, operation="getNope"), "unknown operation getNope"),
    # Check 2
    "missing-path-param": (_with(GET, args={}), "required path param id has no arg"),
    "unknown-query": (
        _with(GET, args={"user": {"path_param": "id"}, "x": {"query": "nope"}}),
        "has no query param nope",
    ),
    "path-param-is-query": (
        _with(GET_GROUPS, args={"user": {"path_param": "id"}, "a": {"path_param": "after"}}),
        "has no path param after",
    ),
    "two-args-one-param": (
        _with(GET, args={"user": {"path_param": "id"}, "u2": {"path_param": "id"}}),
        "both map to id",
    ),
    "reserved-query": (
        _with(GET_GROUPS, args={"user": {"path_param": "id"}, "after": {"query": "after"}}),
        "is set by the server",
    ),
    "page-size-without-limit": (_with(GET, page_size=10), "has no limit param"),
    "unknown-unless-arg": (_with(GET, resumable={"unless_args": ["x"]}), "unknown arg x"),
    # Check 3
    "no-scope-set": (
        {
            "operation": "listSupportedSecurityQuestions",
            "summary": "Questions",
            "args": {"user": {"path_param": "userId"}},
            "view": ["question"],
            "data_classes": ["mfa-state"],
        },
        "declares no oauth2 scopes",
    ),
    "override-on-scoped-operation": (
        _with(GET, okta_scopes_override={"scopes": ["okta.users.manage"], "reason": "x"}),
        "only for operations without oauth2 scopes",
    ),
    # Checks 4, 8
    "missing-data-classes": (_with(GET, data_classes=None), "data_classes: Field required"),
    "empty-data-classes": (_with(GET, data_classes=[]), "data_classes"),
    "unknown-data-class": (_with(GET, data_classes=["secrets"]), "data_classes.0"),
    # Check 6
    "widening-arg-without-rule": (
        {
            "operation": "listAuthenticatorEnrollments",
            "summary": "Enrollments",
            "args": {
                "user": {"path_param": "userId"},
                "disclose": {"query": "discloseIdentifiers"},
            },
            "data_classes": ["mfa-state"],
        },
        "discloseIdentifiers needs an arg_rule or allowed_values",
    ),
    "expand-without-rule": (
        {
            "operation": "listUsers",
            "summary": "Users",
            "args": {"expand": {"query": "expand"}},
            "paginate": "link",
            "view": ["id"],
            "data_classes": ["pii"],
        },
        "expand needs an arg_rule or allowed_values",
    ),
    "free-form-filter-without-rule": (
        {
            "operation": "listUsers",
            "summary": "Users",
            "args": {"search": {"query": "search"}},
            "paginate": "link",
            "view": ["id"],
            "data_classes": ["pii"],
        },
        "search needs an arg_rule",
    ),
    "reviewed-on-expand": (
        {
            "operation": "listUsers",
            "summary": "Users",
            "args": {"expand": {"query": "expand", "arg_rule": {"reviewed": "looked at"}}},
            "paginate": "link",
            "view": ["id"],
            "data_classes": ["pii"],
        },
        "arg expand: arg_rule reviewed is only for free-form filters (filter, q, search)",
    ),
    "reviewed-on-disclose-identifiers": (
        {
            "operation": "listAuthenticatorEnrollments",
            "summary": "Enrollments",
            "args": {
                "user": {"path_param": "userId"},
                "disclose": {"query": "discloseIdentifiers", "arg_rule": {"reviewed": "x"}},
            },
            "data_classes": ["mfa-state"],
        },
        "arg disclose: arg_rule reviewed is only for free-form filters",
    ),
    "reviewed-on-plain-query": (
        {
            "operation": "listUsers",
            "summary": "Users",
            "args": {"sort_by": {"query": "sortBy", "arg_rule": {"reviewed": "x"}}},
            "paginate": "link",
            "view": ["id"],
            "data_classes": ["pii"],
        },
        "arg sort_by: arg_rule reviewed is only for free-form filters",
    ),
    "reviewed-on-path-param": (
        _with(GET, args={"user": {"path_param": "id", "arg_rule": {"reviewed": "x"}}}),
        "arg user: arg_rule reviewed is only for free-form filters",
    ),
    "reviewed-empty": (
        _with(GET, args={"user": {"path_param": "id", "arg_rule": {"reviewed": ""}}}),
        "at least 1 character",
    ),
    "reviewed-not-a-string": (
        _with(GET, args={"user": {"path_param": "id", "arg_rule": {"reviewed": True}}}),
        "valid string",
    ),
    "arg-rule-forbidden-and-raises": (
        _with(
            GET,
            args={
                "user": {
                    "path_param": "id",
                    "arg_rule": {"forbidden": True, "raises_sensitivity_to": "sensitive"},
                }
            },
        ),
        "exactly one of",
    ),
    "arg-rule-raises-and-reviewed": (
        _with(
            GET,
            args={
                "user": {
                    "path_param": "id",
                    "arg_rule": {"raises_sensitivity_to": "sensitive", "reviewed": "x"},
                }
            },
        ),
        "exactly one of",
    ),
    # Check 9
    "items-key-not-object-array": (_with(GET, items_key="profile"), "items_key profile"),
    "items-key-scalar-array": (
        {
            "operation": "getGroup",
            "summary": "Group",
            "args": {"group": {"path_param": "groupId"}},
            "items_key": "objectClass",
            "view": ["id"],
            "data_classes": ["org-config"],
        },
        "items_key objectClass",
    ),
    "pageable-without-paginate": (_with(GET_GROUPS, paginate="none"), "set paginate"),
    "paginate-on-single-resource": (_with(GET, paginate="link"), "single-resource"),
    "response-override-on-list": (
        _with(GET_GROUPS, response_override={"kind": "list", "reason": "x"}),
        "needs an object response",
    ),
    # T1 D5 views
    "list-without-view": (_with(GET_GROUPS, view=None), "list commands need a view"),
    "view-path-not-in-schema": (_with(GET_GROUPS, view=["id", "nope"]), "view path nope"),
    "view-path-in-links": (_with(GET, view=["_links.self"]), "_links are never in a view"),
    "view-duplicate-path": (_with(GET_GROUPS, view=["id", "id"]), "duplicate paths"),
    # Model shape
    "handler": (_with(GET, handler="okta_mcp.handlers.x"), "post-v1"),
    "misspelled-field": (_with(GET, arg_rules={}), "arg_rules: Extra inputs"),
    "arg-path-and-query": (
        _with(GET, args={"user": {"path_param": "id", "query": "id"}}),
        "exactly one of path_param or query",
    ),
    "resolve-on-query": (
        _with(
            GET_GROUPS,
            args={"user": {"path_param": "id"}, "a": {"query": "x", "resolve": "user_id"}},
        ),
        "resolve applies only to a path_param",
    ),
    "empty-path-param": (_with(GET, args={"user": {"path_param": ""}}), "path_param"),
    "bad-pattern": (_with(GET, args={"user": {"path_param": "id", "pattern": "("}}), "pattern"),
    # Python reads `]` first in a class as literal; the `$` → `\Z` translation doesn't.
    "pattern-breaks-ecma-translation": (
        _with(GET, args={"user": {"path_param": "id", "pattern": "^[]$]$"}}),
        r"invalid pattern: bad escape \Z",
    ),
    "empty-arg-rule": (
        _with(GET, args={"user": {"path_param": "id", "arg_rule": {}}}),
        "arg_rule must set",
    ),
    "camel-case-arg": (_with(GET, args={"userId": {"path_param": "id"}}), "snake_case"),
}


@pytest.mark.parametrize(("cmd", "message"), _FAILURES.values(), ids=_FAILURES.keys())
def test_failure_modes(spec: SpecIndex, cmd: dict[str, Any], message: str) -> None:
    with pytest.raises(RegistryError) as e:
        _build(spec, cmd=cmd)
    assert message in str(e.value)


def test_reviewed_filter_loads_and_satisfies_check_6(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listUsers",
        "summary": "Users",
        "args": {
            "search": {"query": "search", "arg_rule": {"reviewed": "matches returned fields"}}
        },
        "paginate": "link",
        "view": ["id"],
        "data_classes": ["pii"],
    }
    rule = _build(spec, list=cmd).domains["users"].commands["list"].entry.args["search"].arg_rule
    assert rule is not None
    assert (rule.reviewed, rule.raises_sensitivity_to, rule.forbidden) == (
        "matches returned fields",
        None,
        False,
    )


def test_same_operation_sensitivity_mismatch(spec: SpecIndex) -> None:
    with pytest.raises(RegistryError, match="differ in base sensitivity"):
        _build(spec, get=GET, factors=_with(GET, data_classes=["mfa-state"]))


def test_same_operation_same_classification_across_domains(spec: SpecIndex) -> None:
    other = {"domain": "people", "description": "People.", "commands": {"get": GET}}
    with pytest.raises(RegistryError, match="share a classification"):
        build_registry({"users.yaml": _doc(get=GET), "people.yaml": other}, spec)


def test_domain_must_match_file_name(spec: SpecIndex) -> None:
    with pytest.raises(RegistryError, match="must match the file name"):
        build_registry({"people.yaml": _doc(get=GET)}, spec)


def test_bad_command_name(spec: SpecIndex) -> None:
    with pytest.raises(RegistryError, match="kebab-case"):
        _build(spec, getGroups=GET)
