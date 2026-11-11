import copy
import dataclasses
from pathlib import Path
from typing import Any

import pytest
import yaml

from okta_mcp.policy.loader import PolicyError, build_policy, load_policy
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import load_spec

from ._pilot import GROUPS_NORMAL, GROUPS_SENSITIVE, HELPDESK, PILOT, READERS, ZONES

G1, G2 = READERS, HELPDESK


def _doc(**roles: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "roles": copy.deepcopy(roles)}


def _role(**fields: Any) -> dict[str, Any]:
    return {"groups": [G1], "allow": {"groups": ["list"]}, **fields}


def _groups(*names: str) -> set[tuple[str, str]]:
    return {("groups", n) for n in names}


def _errors(doc: Any, registry: Registry) -> list[str]:
    with pytest.raises(PolicyError) as e:
        build_policy(doc, registry)
    assert str(e.value) == "\n".join(e.value.errors)
    return e.value.errors


def _one_error(doc: Any, registry: Registry) -> str:
    (error,) = _errors(doc, registry)
    return error


# --- the pilot fixture ---------------------------------------------------------------------


def test_registry_fixture_matches_the_assumed_sensitivities(registry: Registry) -> None:
    commands = registry.domains["groups"].commands
    assert {n for n, c in commands.items() if c.sensitivity == "normal"} == GROUPS_NORMAL
    assert {n for n, c in commands.items() if c.sensitivity == "sensitive"} == GROUPS_SENSITIVE
    assert {(d, n) for d in ("network-zones",) for n in registry.domains[d].commands} == ZONES


def test_pilot_policy_loads_clean() -> None:
    # Against the shipped registry alone, as the server loads it.
    policy = load_policy(PILOT, load_registry(load_spec()))
    assert policy.warnings == ()
    assert set(policy.roles) == {
        "directory-reader",
        "helpdesk",
        "security-analyst",
        "platform-admin",
    }

    reader = policy.roles["directory-reader"]
    assert reader.name == "directory-reader"
    assert reader.groups == {"00g1readers000000000"}
    assert reader.allow == _groups(*GROUPS_NORMAL)
    assert reader.deny == frozenset()

    assert policy.roles["helpdesk"].allow == (
        _groups(*GROUPS_NORMAL, "list-roles", "get-role") | ZONES
    )
    analyst = policy.roles["security-analyst"]
    assert analyst.allow == _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE) | ZONES
    assert analyst.deny == _groups("get-apps")
    assert policy.roles["platform-admin"].allow == analyst.allow


# --- expansion -----------------------------------------------------------------------------


def test_wildcard_leaves_out_sensitive_commands(registry: Registry) -> None:
    role = build_policy(_doc(r=_role(allow={"groups": ["*"]})), registry).roles["r"]
    assert role.allow == _groups(*GROUPS_NORMAL)


def test_all_domains_wildcard_leaves_out_sensitive_commands(registry: Registry) -> None:
    role = build_policy(_doc(r=_role(allow={"*": ["*"]})), registry).roles["r"]
    assert role.allow == _groups(*GROUPS_NORMAL) | ZONES


def test_named_command_is_granted_whatever_its_sensitivity(registry: Registry) -> None:
    role = build_policy(_doc(r=_role(allow={"groups": ["get-role"]})), registry).roles["r"]
    assert role.allow == _groups("get-role")


def test_include_sensitive_widens_only_the_listed_domain(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, include_sensitive=["groups"]))
    role = build_policy(doc, registry).roles["r"]
    assert role.allow == _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE) | ZONES


def test_include_sensitive_star_widens_every_domain(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, include_sensitive=["*"]))
    role = build_policy(doc, registry).roles["r"]
    assert role.allow == {(d.name, c) for d in registry.domains.values() for c in d.commands}


def test_include_sensitive_does_not_widen_another_role(registry: Registry) -> None:
    doc = _doc(
        a=_role(allow={"groups": ["*"]}, include_sensitive=["groups"]),
        b=_role(groups=[G2], allow={"groups": ["*"]}),
    )
    assert build_policy(doc, registry).roles["b"].allow == _groups(*GROUPS_NORMAL)


def test_include_sensitive_without_a_wildcard_grants_nothing_more(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["list"]}, include_sensitive=["groups"]))
    assert build_policy(doc, registry).roles["r"].allow == _groups("list")


@pytest.mark.parametrize(
    ("allow", "include", "raised"),
    [
        # A plain wildcard: no call raised to sensitive by an argument.
        ({"groups": ["*"]}, [], set()),
        ({"*": ["*"]}, [], set()),
        # Named outright.
        ({"groups": ["*", "list"]}, [], {("groups", "list")}),
        ({"groups": ["list", "get-role"]}, [], {("groups", "list"), ("groups", "get-role")}),
        # A wildcard in an included domain: every command there, and only there.
        ({"groups": ["*"]}, ["groups"], _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE)),
        ({"*": ["*"]}, ["network-zones"], ZONES),
        ({"groups": ["*"], "network-zones": ["list"]}, ["vault"], {("network-zones", "list")}),
        ({"groups": ["list"]}, ["groups"], {("groups", "list")}),
    ],
)
def test_allow_raised(
    registry: Registry, allow: dict[str, list[str]], include: list[str], raised: set[Any]
) -> None:
    role = build_policy(_doc(r=_role(allow=allow, include_sensitive=include)), registry).roles["r"]
    assert role.allow_raised == raised
    assert role.allow_raised <= role.allow


def test_allow_raised_with_include_star_is_all_of_allow(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, include_sensitive=["*"]))
    role = build_policy(doc, registry).roles["r"]
    assert role.allow_raised == role.allow


def test_deny_wildcard_covers_sensitive_commands(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, deny={"groups": ["*"]}))
    role = build_policy(doc, registry).roles["r"]
    assert role.deny == _groups(*GROUPS_NORMAL, *GROUPS_SENSITIVE)


def test_deny_is_kept_apart_from_allow(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["list", "get"]}, deny={"groups": ["get"]}))
    role = build_policy(doc, registry).roles["r"]
    assert (role.allow, role.deny) == (_groups("list", "get"), _groups("get"))


def test_a_role_may_name_several_groups_and_groups_may_repeat_across_roles(
    registry: Registry,
) -> None:
    policy = build_policy(_doc(a=_role(groups=[G1, G2]), b=_role(groups=[G1])), registry)
    assert policy.roles["a"].groups == {G1, G2}
    assert policy.roles["b"].groups == {G1}
    assert policy.warnings == ()


def test_policy_is_immutable(registry: Registry) -> None:
    policy = build_policy(_doc(r=_role()), registry)
    with pytest.raises(TypeError):
        policy.roles["x"] = policy.roles["r"]  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.roles["r"].allow = frozenset()  # type: ignore[misc]


# --- validation failures -------------------------------------------------------------------


@pytest.mark.parametrize(
    "group",
    [
        "mcp-okta-helpdesk",  # a name
        "Everyone",
        "00g1readers00000000",  # 19 characters
        "00g1readers0000000000",  # 21
        "00u1readers000000000",  # a user ID
        "00G1readers000000000",
        "00g1readers00000000-",
        "00g1readers000000000\n",
        " 00g1readers00000000",
        "00g1readers00000000\u0661",  # a non-ASCII digit
        "",
        "*",
    ],
)
def test_group_must_be_an_id(registry: Registry, group: str) -> None:
    error = _one_error(_doc(r=_role(groups=[group])), registry)
    assert error.startswith("roles.r.groups: ")
    assert "not an Okta group ID" in error


@pytest.mark.parametrize("group", [1, True, None, ["00g1readers000000000"]])
def test_group_must_be_a_string(registry: Registry, group: Any) -> None:
    errors = _errors(_doc(r=_role(groups=[group])), registry)
    assert errors[0].startswith("roles.r.groups.0: ")
    assert all(e.startswith("roles.r.groups") for e in errors)


@pytest.mark.parametrize("groups", [[], None, G1, {G1: None}])
def test_role_needs_groups(registry: Registry, groups: Any) -> None:
    assert _one_error(_doc(r=_role(groups=groups)), registry).startswith("roles.r.groups: ")


def test_role_without_groups_key(registry: Registry) -> None:
    doc = _doc(r={"allow": {"groups": ["list"]}})
    assert _one_error(doc, registry) == "roles.r.groups: Field required"


def test_duplicate_group_in_a_role(registry: Registry) -> None:
    error = _one_error(_doc(r=_role(groups=[G1, G1])), registry)
    assert "duplicate group '00g1readers000000000'" in error


@pytest.mark.parametrize("allow", [{}, None, [], "*", ["groups"]])
def test_role_needs_allow(registry: Registry, allow: Any) -> None:
    assert _one_error(_doc(r=_role(allow=allow)), registry).startswith("roles.r.allow: ")


def test_role_without_allow_key(registry: Registry) -> None:
    assert _one_error(_doc(r={"groups": [G1]}), registry) == "roles.r.allow: Field required"


@pytest.mark.parametrize("field", ["allow", "deny"])
def test_domain_with_no_commands(registry: Registry, field: str) -> None:
    error = _one_error(_doc(r=_role(**{field: {"groups": []}})), registry)
    assert error.startswith(f"roles.r.{field}: ")
    assert "'groups' lists no commands" in error


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize("commands", ["*", "list", None, {"list": True}, 1])
def test_commands_must_be_a_list(registry: Registry, field: str, commands: Any) -> None:
    error = _one_error(_doc(r=_role(**{field: {"groups": commands}})), registry)
    assert error.startswith(f"roles.r.{field}.groups: ")


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize("command", [True, 1, None, ["list"]])
def test_command_must_be_a_string(registry: Registry, field: str, command: Any) -> None:
    # YAML reads a bare `on`, `yes` or `1` as a boolean or number.
    error = _one_error(_doc(r=_role(**{field: {"groups": [command]}})), registry)
    assert error.startswith(f"roles.r.{field}.groups.0: ")


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize("commands", [["list", "list"], ["*", "*"]])
def test_duplicate_command(registry: Registry, field: str, commands: list[str]) -> None:
    error = _one_error(_doc(r=_role(**{field: {"groups": commands}})), registry)
    assert f"duplicate command under 'groups' {commands[0]!r}" in error


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize(
    "domain", ["users", "Groups", "groups ", "group*", "", "**", "okta_groups"]
)
def test_unknown_domain(registry: Registry, field: str, domain: str) -> None:
    error = _one_error(_doc(r=_role(**{field: {domain: ["*"]}})), registry)
    assert error == f"roles.r.{field}: unknown domain {domain!r}"


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize("command", ["delete", "List", "get-*", "g*", "", "**", "get "])
def test_unknown_command(registry: Registry, field: str, command: str) -> None:
    error = _one_error(_doc(r=_role(**{field: {"groups": [command]}})), registry)
    assert error == f"roles.r.{field}.groups: unknown command {command!r}"


def test_command_of_another_domain_is_unknown(registry: Registry) -> None:
    error = _one_error(_doc(r=_role(allow={"network-zones": ["get-members"]})), registry)
    assert error == "roles.r.allow.network-zones: unknown command 'get-members'"


@pytest.mark.parametrize("field", ["allow", "deny"])
@pytest.mark.parametrize("commands", [["list"], ["*", "list"], ["get-role"]])
def test_only_star_under_the_all_domains_wildcard(
    registry: Registry, field: str, commands: list[str]
) -> None:
    error = _one_error(_doc(r=_role(**{field: {"*": commands}})), registry)
    assert 'the only entry allowed under domain "*" is ["*"]' in error


@pytest.mark.parametrize("include", [["users"], ["Groups"], ["groups", "nope"], ["list"]])
def test_include_sensitive_unknown_domain(registry: Registry, include: list[str]) -> None:
    error = _one_error(_doc(r=_role(include_sensitive=include)), registry)
    assert error == f"roles.r.include_sensitive: unknown domain {include[-1]!r}"


@pytest.mark.parametrize("include", ["*", "groups", True, {"groups": ["*"]}, [True], [None]])
def test_include_sensitive_must_be_a_list_of_strings(registry: Registry, include: Any) -> None:
    error = _one_error(_doc(r=_role(include_sensitive=include)), registry)
    assert error.startswith("roles.r.include_sensitive")


def test_include_sensitive_duplicate(registry: Registry) -> None:
    error = _one_error(_doc(r=_role(include_sensitive=["groups", "groups"])), registry)
    assert "duplicate domain 'groups'" in error


@pytest.mark.parametrize("roles", [{}, None, [], "helpdesk"])
def test_policy_needs_roles(registry: Registry, roles: Any) -> None:
    assert _one_error({"version": 1, "roles": roles}, registry).startswith("roles: ")


def test_policy_without_roles_key(registry: Registry) -> None:
    assert _one_error({"version": 1}, registry) == "roles: Field required"


@pytest.mark.parametrize("name", ["Helpdesk", "help desk", "help_desk", "-x", "x-", "", "*", "a\n"])
def test_role_name_must_be_kebab_case(registry: Registry, name: str) -> None:
    error = _one_error({"version": 1, "roles": {name: _role()}}, registry)
    assert f"role name {name!r} must be kebab-case" in error


@pytest.mark.parametrize("name", [1, True, None])
def test_role_name_must_be_a_string(registry: Registry, name: Any) -> None:
    assert _errors({"version": 1, "roles": {name: _role()}}, registry)


@pytest.mark.parametrize("role", [None, [], "x", {}])
def test_role_must_be_a_mapping_with_fields(registry: Registry, role: Any) -> None:
    assert all(e.startswith("roles.r") for e in _errors(_doc(r=role), registry))


@pytest.mark.parametrize("version", [2, 0, "1", 1.0, True, None])
def test_version_must_be_1(registry: Registry, version: Any) -> None:
    doc = {"version": version, "roles": {"r": _role()}}
    assert _one_error(doc, registry).startswith("version: ")


def test_version_is_required(registry: Registry) -> None:
    assert _one_error({"roles": {"r": _role()}}, registry) == "version: Field required"


@pytest.mark.parametrize("doc", [None, [], "roles", 1])
def test_document_must_be_a_mapping(registry: Registry, doc: Any) -> None:
    assert _errors(doc, registry)


@pytest.mark.parametrize(
    "key",
    # The last two were in design r4; a file that still has them must not load half-read.
    ["role", "default_role", "groups_claim", "unknown_group_behavior"],
)
def test_unknown_top_level_key(registry: Registry, key: str) -> None:
    doc = {**_doc(r=_role()), key: "x"}
    assert _one_error(doc, registry) == f"{key}: Extra inputs are not permitted"


@pytest.mark.parametrize("key", ["denies", "allowed", "include-sensitive", "group", "name"])
def test_unknown_role_key(registry: Registry, key: str) -> None:
    # A misspelt `deny` that was dropped would widen the role.
    doc = _doc(r=_role(**{key: {"groups": ["get"]}}))
    assert _one_error(doc, registry) == f"roles.r.{key}: Extra inputs are not permitted"


def test_every_error_is_reported_at_once(registry: Registry) -> None:
    doc = _doc(
        a=_role(allow={"users": ["*"], "groups": ["nope", "list"]}, deny={"groups": ["gone"]}),
        b=_role(allow={"network-zones": ["list"]}, include_sensitive=["logs"]),
    )
    assert _errors(doc, registry) == [
        "roles.a.allow: unknown domain 'users'",
        "roles.a.allow.groups: unknown command 'nope'",
        "roles.a.deny.groups: unknown command 'gone'",
        "roles.b.include_sensitive: unknown domain 'logs'",
    ]


def test_shape_errors_in_several_roles_are_reported_at_once(registry: Registry) -> None:
    errors = _errors(_doc(a=_role(groups=["x"]), b=_role(allow={})), registry)
    assert [e.split(": ")[0] for e in errors] == ["roles.a.groups", "roles.b.allow"]


# --- warnings ------------------------------------------------------------------------------


def _warnings(doc: Any, registry: Registry) -> tuple[str, ...]:
    return build_policy(doc, registry).warnings


def test_warns_on_include_sensitive_star(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, include_sensitive=["*"]))
    (warning,) = _warnings(doc, registry)
    assert warning.startswith('roles.r.include_sensitive: "*" lets')


@pytest.mark.parametrize(
    ("allow", "include"),
    [
        ({"groups": ["list"]}, "groups"),  # no wildcard
        ({"groups": ["*"]}, "vault"),  # wildcard elsewhere
        # Every command named already, so the wildcard adds nothing, raised calls included.
        ({"groups": ["*", *sorted(GROUPS_NORMAL | GROUPS_SENSITIVE)]}, "groups"),
    ],
)
def test_warns_on_include_sensitive_without_effect(
    registry: Registry, allow: dict[str, list[str]], include: str
) -> None:
    (warning,) = _warnings(_doc(r=_role(allow=allow, include_sensitive=[include])), registry)
    assert warning.startswith(f"roles.r.include_sensitive: {include!r} has no effect")


@pytest.mark.parametrize(
    "allow",
    [
        # No sensitive command there, but the entry lets the wildcard's commands take
        # arguments that raise a call to sensitive.
        {"network-zones": ["*"]},
        # The sensitive commands are named; the normal ones gain the same.
        {"groups": ["*", *sorted(GROUPS_SENSITIVE)]},
    ],
)
def test_include_sensitive_that_only_widens_raised_calls_has_an_effect(
    registry: Registry, allow: dict[str, list[str]]
) -> None:
    (domain,) = allow
    with_entry = build_policy(_doc(r=_role(allow=allow, include_sensitive=[domain])), registry)
    without = build_policy(_doc(r=_role(allow=allow)), registry)
    assert with_entry.warnings == ()
    assert with_entry.roles["r"].allow == without.roles["r"].allow
    assert with_entry.roles["r"].allow_raised > without.roles["r"].allow_raised


def test_include_sensitive_star_without_effect_gets_both_warnings(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["list"]}, include_sensitive=["*"]))
    assert [w.split(" (")[0] for w in _warnings(doc, registry)] == [
        'roles.r.include_sensitive: "*" lets this role\'s wildcards match sensitive commands '
        "in every domain",
        "roles.r.include_sensitive: '*' has no effect",
    ]


def test_domain_listed_beside_star_has_no_effect(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"*": ["*"]}, include_sensitive=["*", "groups"]))
    assert any("'groups' has no effect" in w for w in _warnings(doc, registry))


def test_warns_on_wildcard_that_grants_nothing(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["list"], "vault": ["*"]}))
    (warning,) = _warnings(doc, registry)
    assert warning.startswith('roles.r.allow.vault: "*" grants nothing')


def test_wildcard_with_include_sensitive_grants_the_sensitive_domain(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"vault": ["*"]}, include_sensitive=["vault"]))
    policy = build_policy(doc, registry)
    assert policy.warnings == ()
    assert policy.roles["r"].allow == {("vault", "list"), ("vault", "get")}


@pytest.mark.parametrize(
    ("deny", "what"),
    [
        ({"groups": ["get-role"]}, "'get-role'"),  # no role allows it
        ({"network-zones": ["*"]}, "'*'"),
        ({"vault": ["get"]}, "'get'"),
    ],
)
def test_warns_on_deny_that_matches_nothing(
    registry: Registry, deny: dict[str, list[str]], what: str
) -> None:
    (domain,) = deny
    (warning,) = _warnings(_doc(r=_role(allow={"groups": ["*"]}, deny=deny)), registry)
    assert warning == f"roles.r.deny.{domain}: {what} matches nothing any role allows"


def test_deny_matching_only_another_roles_allow_is_not_a_warning(registry: Registry) -> None:
    # Deny wins across roles, so this entry does something for a principal holding both.
    doc = _doc(
        a=_role(allow={"groups": ["list"]}, deny={"groups": ["get-role"]}),
        b=_role(groups=[G2], allow={"groups": ["get-role"]}),
    )
    assert _warnings(doc, registry) == ()


def test_deny_everything_in_one_role_is_allowed(registry: Registry) -> None:
    doc = _doc(
        a=_role(allow={"groups": ["list"]}, deny={"*": ["*"]}),
        b=_role(groups=[G2], allow={"network-zones": ["*"]}),
    )
    policy = build_policy(doc, registry)
    assert policy.roles["a"].deny == {
        (d.name, c) for d in registry.domains.values() for c in d.commands
    }
    assert policy.warnings == ("roles.a: grants nothing (its deny covers all of its allow)",)


def test_warns_on_role_whose_deny_covers_its_allow(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["list"]}, deny={"groups": ["list"]}))
    assert _warnings(doc, registry) == (
        "roles.r: grants nothing (its deny covers all of its allow)",
    )


# --- the file ------------------------------------------------------------------------------


def _write(tmp_path: Path, text: str | bytes) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


def _file_errors(path: Path, registry: Registry) -> list[str]:
    with pytest.raises(PolicyError) as e:
        load_policy(path, registry)
    return e.value.errors


def test_load_reads_the_file(tmp_path: Path, registry: Registry) -> None:
    path = _write(tmp_path, yaml.safe_dump(_doc(r=_role())))
    assert load_policy(path, registry).roles["r"].allow == _groups("list")


def test_load_errors_name_the_file(tmp_path: Path, registry: Registry) -> None:
    path = _write(tmp_path, yaml.safe_dump(_doc(r=_role(groups=["Everyone"]))))
    (error,) = _file_errors(path, registry)
    assert error.startswith("policy.yaml: roles.r.groups: ")


def test_missing_file(tmp_path: Path, registry: Registry) -> None:
    (error,) = _file_errors(tmp_path / "policy.yaml", registry)
    assert error.startswith("policy.yaml: ")


def test_directory_instead_of_a_file(tmp_path: Path, registry: Registry) -> None:
    assert _file_errors(tmp_path, registry)


@pytest.mark.parametrize(
    "text",
    [b"", b"# only a comment\n", b"roles: [\n", b"\xff\xfe", b"version: 1\nroles: {}\n"],
)
def test_empty_or_malformed_file(tmp_path: Path, registry: Registry, text: bytes) -> None:
    assert _file_errors(_write(tmp_path, text), registry)


@pytest.mark.parametrize(
    "text",
    [
        # A second `deny` would silently replace the first.
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow: {{groups: ['*']}}\n"
        "    deny: {groups: [get]}\n    deny: {groups: [list]}\n",
        # A second role of the same name would replace the first.
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow: {{groups: [list]}}\n"
        f"  r:\n    groups: [{G2}]\n    allow: {{groups: ['*']}}\n",
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n"
        "    allow: {groups: [list], groups: [get]}\n",
    ],
)
def test_duplicate_keys(tmp_path: Path, registry: Registry, text: str) -> None:
    (error,) = _file_errors(_write(tmp_path, text), registry)
    assert "duplicate key" in error


@pytest.mark.parametrize(
    "text",
    [
        # pydantic's lax mode would decode these into the strings they spell.
        "version: 1\nroles:\n  r:\n    groups: [!!binary MDBnMXJlYWRlcnMwMDAwMDAwMDA=]\n"
        "    allow: {groups: [list]}\n",
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow: {{groups: ['*']}}\n"
        "    deny: {groups: [get]}\n    !!binary ZGVueQ==: {groups: [list]}\n",
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n"
        "    allow: {groups: [!!binary bGlzdA==]}\n",
        # A second `groups` under `deny`, which the duplicate-key check can't see.
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow: {{groups: ['*']}}\n"
        "    deny: {groups: [get], !!binary Z3JvdXBz: [list]}\n",
        f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow: {{groups: [list]}}\n"
        "    include_sensitive: [!!binary Z3JvdXBz]\n",
    ],
)
def test_binary_scalars_are_not_strings(tmp_path: Path, registry: Registry, text: str) -> None:
    assert _file_errors(_write(tmp_path, text), registry)


def test_python_tags_are_not_constructed(tmp_path: Path, registry: Registry) -> None:
    text = "version: 1\nroles: !!python/object/apply:os.getcwd []\n"
    (error,) = _file_errors(_write(tmp_path, text), registry)
    assert "could not determine a constructor" in error


def test_unquoted_star_is_a_yaml_error(tmp_path: Path, registry: Registry) -> None:
    # `*` starts a YAML alias, so the wildcard must be quoted; the file must not load.
    text = f"version: 1\nroles:\n  r:\n    groups: [{G1}]\n    allow:\n      groups: [*]\n"
    assert _file_errors(_write(tmp_path, text), registry)


# --- search_attributes ---------------------------------------------------------------------


def test_search_attributes_compile_to_a_set(registry: Registry) -> None:
    policy = build_policy(
        _doc(
            a=_role(search_attributes=["profile.login", "status"]),
            b=_role(groups=[G2], search_attributes=["*"]),
            c=_role(groups=[G2]),
        ),
        registry,
    )
    assert policy.warnings == ()
    assert policy.roles["a"].search_attributes == {"profile.login", "status"}
    assert policy.roles["b"].search_attributes == {"*"}
    assert policy.roles["c"].search_attributes == frozenset()


def test_pilot_policy_search_attributes() -> None:
    roles = load_policy(PILOT, load_registry(load_spec())).roles
    assert roles["directory-reader"].search_attributes == {"profile.name", "type"}
    assert "profile.login" in roles["helpdesk"].search_attributes
    assert roles["security-analyst"].search_attributes == {"*"}
    assert roles["platform-admin"].search_attributes == {"*"}


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (["profile.login", "profile.login"], "duplicate attribute 'profile.login'"),
        (["*", "status"], '"*" must be the only entry'),
        (["profile.*"], "is not an attribute name"),
        (["profile."], "is not an attribute name"),
        (["profile login"], "is not an attribute name"),
        (["profile.login\n"], "is not an attribute name"),
        (['profile.login eq "x"'], "is not an attribute name"),
        ([""], "is not an attribute name"),
        (["pr\u043efile.login"], "is not an attribute name"),
        ([5], "valid string"),
        (["not", "profile.login"], "'not' is an operator or literal word"),
        (["PR"], "'PR' is an operator or literal word"),
        (["true"], "'true' is an operator or literal word"),
        ("status", "valid tuple"),
        ({"users": ["status"]}, "valid tuple"),
    ],
)
def test_search_attributes_shape_errors(registry: Registry, value: Any, message: str) -> None:
    error = _one_error(_doc(r=_role(search_attributes=value)), registry)
    assert error.startswith("roles.r.search_attributes")
    assert message in error


@pytest.mark.parametrize(
    "attribute",
    ["profile.apiKey", "profile.SECRET", "token", "credentials.password.value"],
)
def test_redacted_attribute_cannot_be_listed(registry: Registry, attribute: str) -> None:
    assert _errors(_doc(r=_role(search_attributes=["status", attribute])), registry) == [
        f"roles.r.search_attributes: {attribute!r} is redacted in results, so no role can "
        "search on it"
    ]


def test_redaction_check_uses_the_rules_passed_in(registry: Registry) -> None:
    from okta_mcp.exec.output import ScrubRules

    doc = _doc(r=_role(search_attributes=["profile.costCenter", "profile.apiKey"]))
    with pytest.raises(PolicyError) as e:
        build_policy(doc, registry, ScrubRules(paths=(("costcenter",),)))
    assert e.value.errors == [
        "roles.r.search_attributes: 'profile.costCenter' is redacted in results, so no role "
        "can search on it"
    ]


def test_policy_carries_the_scrub_rules_it_was_checked_against(registry: Registry) -> None:
    from okta_mcp.exec.output import ScrubRules, load_scrub

    assert build_policy(_doc(r=_role()), registry).scrub == load_scrub()
    rules = ScrubRules(paths=(("costcenter",),))
    assert build_policy(_doc(r=_role()), registry, rules).scrub is rules


def test_an_attribute_that_only_starts_a_redaction_chain_can_be_listed(
    registry: Registry,
) -> None:
    # `channel.config.headers.value` is redacted; a custom `profile.channel` is not.
    doc = _doc(r=_role(search_attributes=["profile.channel", "profile.credentials"]))
    assert build_policy(doc, registry).roles["r"].search_attributes == {
        "profile.channel",
        "profile.credentials",
    }


def test_search_attributes_without_an_expression_command_warn(registry: Registry) -> None:
    doc = _doc(r=_role(allow={"groups": ["get"]}, search_attributes=["status"]))
    assert build_policy(doc, registry).warnings == (
        "roles.r.search_attributes: has no effect (no command this role allows takes a "
        "search, filter or sort expression)",
    )
    # A deny that removes the only such command leaves it without effect too.
    doc = _doc(
        r=_role(
            allow={"groups": ["list", "get"]},
            deny={"groups": ["list"]},
            search_attributes=["status"],
        )
    )
    assert any(
        "search_attributes: has no effect" in w for w in build_policy(doc, registry).warnings
    )
