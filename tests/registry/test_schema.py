import copy
from typing import Any

import pytest

from okta_mcp.registry.loader import Command, RegistryError, build_registry
from okta_mcp.registry.schema import SYNOPSIS_MAX, InvalidArguments, help_text, validate_args
from okta_mcp.registry.spec import SpecIndex, build_index, load_spec


@pytest.fixture(scope="module")
def spec() -> SpecIndex:
    return load_spec()


GROUP_ID = "^00g[A-Za-z0-9]{17}$"
GET_GROUP = {
    "operation": "getGroup",
    "summary": "Get a group by ID",
    "args": {"group": {"path_param": "groupId", "pattern": GROUP_ID}},
    "data_classes": ["org-config"],
}
LIST_GROUPS = {
    "operation": "listGroups",
    "summary": "List groups",
    "args": {
        "filter": {"query": "filter", "arg_rule": {"raises_sensitivity_to": "sensitive"}},
        "search": {"query": "search", "arg_rule": {"attribute_expression": True}},
        "expand": {"query": "expand", "allowed_values": []},
        "sort_by": {"query": "sortBy", "arg_rule": {"attribute_expression": True}},
        "sort_order": {"query": "sortOrder", "allowed_values": ["asc", "desc"]},
    },
    "paginate": "link",
    "page_size": 200,
    "view": ["id", "type", "profile.name"],
    "data_classes": ["org-config"],
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
LIST_ZONES = {
    "operation": "listNetworkZones",
    "summary": "List network zones",
    "args": {"filter": {"query": "filter", "arg_rule": {"forbidden": True}}},
    "paginate": "link",
    "page_size": 200,
    "view": ["id", "name", "type", "status", "usage"],
    "data_classes": ["org-config"],
}
GET_ENROLLMENTS = {
    "operation": "listAuthenticatorEnrollments",
    "summary": "Authenticator enrollments",
    "args": {
        "user": {"path_param": "userId", "resolve": "user_id"},
        "disclose_identifiers": {
            "query": "discloseIdentifiers",
            "arg_rule": {"raises_sensitivity_to": "sensitive"},
            "maxItems": 1,
        },
    },
    "response_override": {"kind": "list", "reason": "V8"},
    "view": ["id", "type", "status", "name"],
    "data_classes": ["mfa-state", "pii"],
}


def _with(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    cmd = copy.deepcopy(base)
    cmd.update(changes)
    return cmd


def _commands(
    spec: SpecIndex, commands: dict[str, Any], domain: str = "groups"
) -> dict[str, Command]:
    doc = {"domain": domain, "description": "Read.", "commands": commands}
    return dict(build_registry({f"{domain}.yaml": doc}, spec).domains[domain].commands)


def _one(spec: SpecIndex, cmd: dict[str, Any], name: str = "cmd") -> Command:
    return _commands(spec, {name: cmd})[name]


# Schemas


def test_schema_snapshots(spec: SpecIndex) -> None:
    cmds = _commands(
        spec,
        {
            "get": GET_GROUP,
            "list": LIST_GROUPS,
            "get-groups": GET_GROUPS,
            "list-zones": LIST_ZONES,
            "enrollments": GET_ENROLLMENTS,
        },
    )
    assert cmds["get"].schema == {
        "type": "object",
        "properties": {"group": {"type": "string", "pattern": GROUP_ID}},
        "additionalProperties": False,
        "required": ["group"],
    }
    # `expand` is hidden by `allowed_values: []`; spec descriptions, examples and defaults drop.
    assert cmds["list"].schema == {
        "type": "object",
        "properties": {
            "filter": {"type": "string"},
            "search": {"type": "string"},
            "sort_by": {"type": "string"},
            "sort_order": {"type": "string", "enum": ["asc", "desc"]},
        },
        "additionalProperties": False,
    }
    assert cmds["get-groups"].schema == {
        "type": "object",
        "properties": {"user": {"type": "string"}},
        "additionalProperties": False,
        "required": ["user"],
    }
    assert cmds["list-zones"].schema == {
        "type": "object",
        "properties": {"filter": {"type": "string"}},
        "additionalProperties": False,
    }
    assert cmds["enrollments"].schema == {
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "disclose_identifiers": {
                "type": "array",
                "items": {"type": "string", "enum": ["phone"]},
                "maxItems": 1,
            },
        },
        "additionalProperties": False,
        "required": ["user"],
    }


def test_schema_is_read_only(spec: SpecIndex) -> None:
    cmd = _one(spec, GET_GROUP)
    with pytest.raises(TypeError):
        cmd.schema["additionalProperties"] = True  # type: ignore[index]


def test_spec_constraints_are_kept(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listOktaManagedUserAccounts",
        "summary": "Managed accounts",
        "args": {"match": {"query": "match"}},
        "paginate": "link",
        "page_size": 20,
        "view": ["id"],
        "data_classes": ["pii"],
    }
    schema = _one(spec, cmd).schema
    assert schema["properties"]["match"] == {"type": "string", "minLength": 3, "maxLength": 255}


def test_allowed_values_narrow_array_items(spec: SpecIndex) -> None:
    cmd = {
        "operation": "listBrands",
        "summary": "Brands",
        "args": {"expand": {"query": "expand", "allowed_values": ["themes"]}},
        "paginate": "link",
        "page_size": 20,
        "view": ["id", "name"],
        "data_classes": ["org-config"],
    }
    schema = _one(spec, cmd).schema
    assert schema["properties"]["expand"] == {
        "type": "array",
        "items": {"type": "string", "enum": ["themes"]},
    }
    with pytest.raises(RegistryError, match=r"allowed_values \['x'\] are not in the spec enum"):
        _one(spec, _with(cmd, args={"expand": {"query": "expand", "allowed_values": ["x"]}}))


def test_overlay_errors(spec: SpecIndex) -> None:
    def args(**a: Any) -> dict[str, Any]:
        return _with(LIST_GROUPS, args=a)

    cases = [
        (
            args(limit_q={"query": "sortBy", "maxItems": 2, "allowed_values": ["a"]}),
            "maxItems needs an array",
        ),
        (args(f={"query": "sortBy", "type": "integer", "allowed_values": ["a"]}), "string"),
        (
            _with(GET_GROUP, args={"group": {"path_param": "groupId", "type": "integer"}}),
            "path params are strings",
        ),
        (
            _with(GET_GROUP, args={"group": {"path_param": "groupId", "allowed_values": []}}),
            "required, so it can't be hidden",
        ),
    ]
    for cmd, message in cases:
        with pytest.raises(RegistryError, match=message):
            _one(spec, cmd)


def test_registry_pattern_cannot_replace_spec_pattern(spec: SpecIndex) -> None:
    cmd = {
        "operation": "getCertificateAuthority",
        "summary": "A certificate authority",
        "args": {"ca": {"path_param": "authorityInstanceId", "pattern": "^.*$"}},
        "data_classes": ["org-config"],
    }
    with pytest.raises(RegistryError, match="spec already sets pattern"):
        _one(spec, cmd)
    cmd["args"]["ca"].pop("pattern")
    assert _one(spec, cmd).schema["properties"]["ca"]["pattern"] == "^[0-9A-F]+$"


def test_type_overlay() -> None:
    op = {
        "operationId": "getX",
        "parameters": [
            {"name": "id", "in": "path", "schema": {"oneOf": [{"type": "string"}]}},
            {"name": "ids", "in": "query"},
        ],
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x/{id}": {"get": op}}})
    cmd = {
        "operation": "getX",
        "summary": "X",
        "args": {"x": {"path_param": "id"}, "ids": {"query": "ids", "type": "array"}},
        "data_classes": ["pii"],
    }
    props = _one(index, cmd).schema["properties"]
    assert props == {"x": {"type": "string"}, "ids": {"type": "array", "items": {"type": "string"}}}


def test_one_of_required(spec: SpecIndex) -> None:
    cmd = _with(LIST_GROUPS, one_of_required=["filter", "search"])
    schema = _one(spec, cmd).schema
    assert schema["oneOf"] == [{"required": ["filter"]}, {"required": ["search"]}]
    with pytest.raises(RegistryError, match="one_of_required: unknown or hidden arg expand"):
        _one(spec, _with(LIST_GROUPS, one_of_required=["filter", "expand"]))
    with pytest.raises(RegistryError, match="one_of_required: user is always required"):
        _one(spec, _with(GET_GROUPS, one_of_required=["user", "user"]))


# Synopsis


def test_synopsis(spec: SpecIndex) -> None:
    cmds = _commands(
        spec,
        {
            "get": GET_GROUP,
            "list": _with(
                LIST_GROUPS, args={k: LIST_GROUPS["args"][k] for k in ("filter", "search")}
            ),
            "either": _with(
                LIST_GROUPS,
                one_of_required=["search", "filter"],
                summary="List groups, filtered",
                data_classes=["pii"],  # a second command on listGroups needs its own classification
            ),
            "get-groups": GET_GROUPS,
        },
    )
    assert cmds["get"].synopsis == "get <group>"
    assert cmds["get-groups"].synopsis == "get-groups <user>"
    assert cmds["list"].synopsis == "list [filter] [search]"
    # Too long with every optional arg spelled out, so they collapse.
    assert cmds["either"].synopsis == "either <filter|search> [options]"


def test_synopsis_line_is_capped(spec: SpecIndex) -> None:
    summary = "x" * (SYNOPSIS_MAX - len("get <group>  ") + 1)
    with pytest.raises(RegistryError, match=f"synopsis line is over {SYNOPSIS_MAX}"):
        _one(spec, _with(GET_GROUP, summary=summary), name="get")
    _one(spec, _with(GET_GROUP, summary=summary[1:]), name="get")


# Help


def test_help_text_matches_t1_d11(spec: SpecIndex) -> None:
    cmd = _one(spec, GET_GROUPS, name="get-groups")
    assert help_text(cmd) == (
        "okta_groups get-groups <user>\n"
        "Groups the user belongs to. List, paginated.\n"
        "  user  string, required — user ID (00u…) or exact login\n"
        "Default view: id,type,profile.name"
    )


def test_help_text_states_every_constraint(spec: SpecIndex) -> None:
    cmds = _commands(
        spec,
        {
            "get": GET_GROUP,
            "list": _with(LIST_GROUPS, one_of_required=["filter", "search"]),
            "enrollments": GET_ENROLLMENTS,
        },
        "network-zones",
    )
    assert help_text(cmds["get"]) == (
        "okta_network_zones get <group>\n"
        "Get a group by ID.\n"
        f"  group  string, required, pattern {GROUP_ID} — The `id` of the group"
    )
    lst = help_text(cmds["list"])
    assert lst.startswith("okta_network_zones list <filter|search> [sort_by] [sort_order]\n")
    assert "  sort_order  string, one of: asc, desc — Specifies sort order" in lst
    assert "Exactly one of: filter, search" in lst
    # Markdown links and HTML are flattened; long descriptions are cut.
    assert "](" not in lst and "<x-" not in lst
    assert all(len(line) < 200 for line in lst.splitlines())
    enr = help_text(cmds["enrollments"])
    assert "  disclose_identifiers  array of string, one of: phone, at most 1 item" in enr
    assert "Authenticator enrollments. List.\n" in enr


def test_help_text_is_small(spec: SpecIndex) -> None:
    for cmd in _commands(spec, {"get": GET_GROUP, "list": LIST_GROUPS}).values():
        assert len(help_text(cmd).encode()) <= 1024


# Validation


def _invalid(cmd: Command, args: Any) -> str:
    with pytest.raises(InvalidArguments) as e:
        validate_args(cmd, args)
    return str(e.value)


def test_valid_args_pass(spec: SpecIndex) -> None:
    validate_args(_one(spec, GET_GROUP), {"group": "00g1emaKYZTWRYYRRTSK"})
    validate_args(_one(spec, LIST_GROUPS), {})
    validate_args(_one(spec, GET_ENROLLMENTS), {"user": "a@example.com"})


def test_invalid_args_name_valid_options(spec: SpecIndex) -> None:
    lst = _one(spec, LIST_GROUPS)
    assert _invalid(lst, {"usr": "x", "expand": "stats"}) == (
        "unknown args 'expand', 'usr'; valid: filter, search, sort_by, sort_order"
    )
    assert _invalid(lst, {"sort_order": "up"}) == "arg 'sort_order' must be one of: asc, desc"
    assert _invalid(lst, {"filter": 1}) == "arg 'filter' must be a string"
    assert _invalid(lst, []) == "args must be an object"
    get = _one(spec, GET_GROUP)
    assert _invalid(get, {}) == "missing required arg 'group'"
    assert _invalid(get, {"group": "Sales"}) == f"arg 'group' must match {GROUP_ID}"
    enr = _one(spec, GET_ENROLLMENTS)
    assert _invalid(enr, {"user": "u", "disclose_identifiers": ["phone", "phone"]}) == (
        "arg 'disclose_identifiers' takes at most 1 item"
    )
    assert _invalid(enr, {"user": "u", "disclose_identifiers": ["email"]}) == (
        "arg 'disclose_identifiers' must be one of: phone"
    )


def test_invalid_args_reports_every_error(spec: SpecIndex) -> None:
    msg = _invalid(_one(spec, GET_GROUP), {"group": 5, "x": 1})
    assert msg == "arg 'group' must be a string; unknown arg 'x'; valid: group"


def test_one_of_required_validation(spec: SpecIndex) -> None:
    cmd = _one(spec, _with(LIST_GROUPS, one_of_required=["filter", "search"]))
    validate_args(cmd, {"filter": 'type eq "OKTA_GROUP"'})
    for args in ({}, {"filter": "a", "search": "b"}):
        assert _invalid(cmd, args) == "pass exactly one of: filter, search"


def test_error_does_not_echo_values(spec: SpecIndex) -> None:
    msg = _invalid(_one(spec, GET_GROUP), {"group": "A" * 10_000})
    assert "AAAA" not in msg


def test_valid_option_lists_are_capped() -> None:
    params = [{"name": f"p{i:02}", "in": "query", "schema": {"type": "string"}} for i in range(25)]
    op = {
        "operationId": "getX",
        "parameters": params,
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x": {"get": op}}})
    args = {f"p{i:02}": {"query": f"p{i:02}"} for i in range(25)}
    cmd = {"operation": "getX", "summary": "X", "args": args, "data_classes": ["pii"]}
    msg = _invalid(_one(index, cmd), {"nope": "x"})
    assert msg.endswith("p18, p19, … (+5; see okta_help)")


# Review fixes

SEARCH_APPS = {
    "operation": "listApplicationsBySearch",
    "summary": "Search apps",
    "args": {"labels": {"query": "labels"}},
    "paginate": "link",
    "page_size": 100,
    "view": ["id", "label"],
    "data_classes": ["org-config"],
}
LABEL = "^lbc[A-Za-z0-9]{17}$"


def test_pattern_on_array_applies_to_items(spec: SpecIndex) -> None:
    cmd = _one(spec, _with(SEARCH_APPS, args={"labels": {"query": "labels", "pattern": LABEL}}))
    assert cmd.schema["properties"]["labels"]["items"]["pattern"] == LABEL
    assert "pattern" not in cmd.schema["properties"]["labels"]
    assert _invalid(cmd, {"labels": ["x" * 20]}) == f"arg 'labels' must match {LABEL}"
    validate_args(cmd, {"labels": ["lbco3v6xlwdtEX2il1d6"]})


def test_pattern_dollar_ends_the_input(spec: SpecIndex) -> None:
    # ECMA-262 `$`, not Python's, which also matches before a final newline.
    get = _one(spec, GET_GROUP)
    assert (
        _invalid(get, {"group": "00g1emaKYZTWRYYRRTSK\n"}) == f"arg 'group' must match {GROUP_ID}"
    )
    # A `$` escaped or inside a class is literal.
    literal = r"^a[$]\$$"
    op = {
        "operationId": "getX",
        "parameters": [
            {"name": "x", "in": "query", "schema": {"type": "string", "pattern": literal}}
        ],
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x": {"get": op}}})
    cmd = _one(
        index,
        {
            "operation": "getX",
            "summary": "X",
            "args": {"x": {"query": "x"}},
            "data_classes": ["pii"],
        },
    )
    validate_args(cmd, {"x": "a$$"})
    for bad in ("a$$\n", "a$"):
        assert _invalid(cmd, {"x": bad}) == f"arg 'x' must match {literal}"


def test_pattern_on_array_cannot_replace_item_pattern() -> None:
    schema = {"type": "array", "items": {"type": "string", "pattern": "^a$"}}
    op = {
        "operationId": "getX",
        "parameters": [{"name": "ids", "in": "query", "schema": schema}],
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x": {"get": op}}})
    args = {"ids": {"query": "ids", "pattern": "^.*$"}}
    cmd = {"operation": "getX", "summary": "X", "args": args, "data_classes": ["pii"]}
    with pytest.raises(RegistryError, match=r"spec already sets pattern \^a\$"):
        _one(index, cmd)


def test_type_overlay_cannot_replace_spec_type(spec: SpecIndex) -> None:
    for t in ("string", "integer"):
        args = {"labels": {"query": "labels", "type": t}}
        with pytest.raises(RegistryError, match=f"spec type is array, not {t}"):
            _one(spec, _with(SEARCH_APPS, args=args))


def test_one_of_required_rejects_duplicates(spec: SpecIndex) -> None:
    with pytest.raises(RegistryError, match="one_of_required has duplicate args"):
        _one(spec, _with(LIST_GROUPS, one_of_required=["filter", "filter"]))


def test_unknown_arg_names_are_shortened_and_capped(spec: SpecIndex) -> None:
    args = {f"k{i:02}": 1 for i in range(25)} | {"z" * 1000: 1}
    msg = _invalid(_one(spec, GET_GROUP), {"group": "00g1emaKYZTWRYYRRTSK", **args})
    assert "z" * 40 not in msg and "'k19', … (+6; see okta_help)" in msg
    assert len(msg) < 400


def test_help_text_states_item_constraints(spec: SpecIndex) -> None:
    args = {"labels": {"query": "labels", "pattern": LABEL}}
    text = help_text(_one(spec, _with(SEARCH_APPS, args=args)))
    assert (
        f"  labels  array of string, each min length 20, each max length 20, each pattern {LABEL}"
        in text
    )


def test_integer_args_reject_floats_and_booleans() -> None:
    op = {
        "operationId": "getX",
        "parameters": [{"name": "n", "in": "query", "schema": {"type": "integer"}}],
        "security": [{"oauth2": ["x.read"]}],
        "responses": {},
    }
    index = build_index({"info": {"version": "1"}, "paths": {"/x": {"get": op}}})
    cmd = _one(
        index,
        {
            "operation": "getX",
            "summary": "X",
            "args": {"n": {"query": "n"}},
            "data_classes": ["pii"],
        },
    )
    validate_args(cmd, {"n": 5})
    for bad in (5.0, True):
        assert _invalid(cmd, {"n": bad}) == "arg 'n' must be an integer"
