"""The users and apps registries (plan step 5.1): coverage, classification, argument rules."""

import pytest

from okta_mcp.registry.loader import Registry
from okta_mcp.registry.schema import InvalidArguments, validate_args

DOMAINS = ("users", "apps")
USER = "00u1emaKYZTWRYYRRTSK"
APP = "0oa1emaKYZTWRYYRRTSK"


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.op().operation_id for n, c in registry.domains[domain].commands.items()}


def test_users_commands(registry: Registry) -> None:
    # Catalogue `search` is `list` with `q`/`search` (T1 D3). Left out: `get-factors-questions`
    # (excluded: SSWS only).
    assert set(_commands(registry, "users")) == {
        "list",
        "get",
        "get-groups",
        "get-apps",
        "get-blocks",
        "get-idps",
        "get-linked-objects",
        "get-factors",
        "get-factor",
        "get-factor-transaction",
        "get-factors-catalog",
        "get-enrollments",
        "get-enrollment",
        "get-classification",
        "get-devices",
        "get-risk",
        "get-clients",
        "get-client-grants",
        "get-client-tokens",
        "get-client-token",
        "get-grants",
        "get-grant",
        "list-roles",
        "get-role",
        "list-role-app-targets",
        "list-role-group-targets",
        "list-role-targets",
        "get-role-governance",
        "get-governance-grant",
        "get-governance-resources",
    }


def test_apps_commands(registry: Registry) -> None:
    # Left out: `list-jwks` (Okta wraps the list the spec declares bare) and
    # `get-saml-metadata` (XML; post-v1 composite).
    ops = set(_commands(registry, "apps").values())
    assert "listJwk" not in ops
    assert "previewSAMLmetadataForApplication" not in ops
    assert len(ops) == 29


def _sensitive(registry: Registry, domain: str) -> set[str]:
    return {
        c.name for c in registry.domains[domain].commands.values() if c.sensitivity == "sensitive"
    }


def test_users_sensitivity(registry: Registry) -> None:
    assert _sensitive(registry, "users") == {
        # mfa-state
        "get-factors",
        "get-factor",
        "get-factor-transaction",
        "get-factors-catalog",
        "get-enrollments",
        "get-enrollment",
        # risk
        "get-blocks",
        "get-risk",
        # credential-material: IdP objects carry protocol.credentials
        "get-idps",
        # session
        "get-client-tokens",
        "get-client-token",
        # admin-roles
        "list-roles",
        "get-role",
        "list-role-app-targets",
        "list-role-group-targets",
        "list-role-targets",
        "get-role-governance",
        "get-governance-grant",
        "get-governance-resources",
    }


def test_apps_sensitivity(registry: Registry) -> None:
    assert _sensitive(registry, "apps") == {
        # credential-material, public halves included (design §9.2)
        "get-connection-jwks",
        "list-csrs",
        "get-csr",
        "get-jwk",
        "list-keys",
        "get-key",
        "list-secrets",
        "get-secret",
        # admin-roles: scopes granted to the app
        "list-grants",
        "get-grant",
        # session
        "list-tokens",
        "get-token",
    }


def test_free_form_rules(registry: Registry) -> None:
    rules = {
        (domain, cmd.name, name): arg.arg_rule
        for domain in DOMAINS
        for cmd in registry.domains[domain].commands.values()
        for name, arg in cmd.entry.args.items()
        if arg.param in ("filter", "search", "q", "sortBy")
    }
    reviewed = {k for k, r in rules.items() if r is not None and r.reviewed}
    checked = {k for k, r in rules.items() if r is not None and r.attribute_expression}
    assert reviewed == {
        ("users", "list", "q"),
        ("users", "list", "filter"),
        ("apps", "list", "q"),
        ("apps", "get-users", "q"),
        ("apps", "get-groups", "q"),
    }
    # `apps list` filter takes `user.id eq …`, which selects by assignment, not by a field the
    # list returns, so it is checked like a search.
    assert checked == {
        ("users", "list", "search"),
        ("users", "list", "sort_by"),
        ("apps", "list", "filter"),
    }
    assert reviewed | checked == set(rules)


def test_disclose_identifiers_raises(registry: Registry) -> None:
    for name in ("get-enrollments", "get-enrollment"):
        rule = registry.domains["users"].commands[name].entry.args["disclose_identifiers"].arg_rule
        assert rule is not None and rule.raises_sensitivity_to == "sensitive"


@pytest.mark.parametrize(
    ("domain", "command", "param"),
    [
        ("users", "list", "fields"),
        ("apps", "list", "expand"),
        ("apps", "list", "useOptimization"),
        ("apps", "list", "alwaysIncludeVpnSettings"),
        ("apps", "list", "includeNonDeleted"),
        ("apps", "get", "expand"),
    ],
)
def test_unexposed_params(registry: Registry, domain: str, command: str, param: str) -> None:
    cmd = registry.domains[domain].commands[command]
    assert param in cmd.op().params
    assert param not in {a.param for a in cmd.entry.args.values()}


def test_user_args_resolve_except_get(registry: Registry) -> None:
    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            if "user" in cmd.entry.args:
                expected = None if (domain, cmd.name) == ("users", "get") else "user_id"
                assert cmd.entry.args["user"].resolve == expected, f"{domain} {cmd.name}"


def test_every_path_param_is_constrained(registry: Registry) -> None:
    # A pattern, a spec enum, or a resolved user. `users get` alone takes Okta's ID-or-login.
    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            for name, arg in cmd.entry.args.items():
                if arg.path_param is None or (domain, cmd.name, name) == ("users", "get", "user"):
                    continue
                prop = cmd.schema["properties"][name]
                assert arg.pattern or arg.resolve or "enum" in prop, f"{domain} {cmd.name} {name}"


def test_app_id_shape(registry: Registry) -> None:
    get = registry.domains["apps"].commands["get"]
    validate_args(get, {"app": APP})
    for bad in ("00g1emaKYZTWRYYRRTSK", "export", "types", f"{APP}\n"):
        with pytest.raises(InvalidArguments, match="arg 'app'"):
            validate_args(get, {"app": bad})


def test_expand_values_are_closed(registry: Registry) -> None:
    users = registry.domains["users"].commands
    validate_args(users["list"], {"expand": "classification"})
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(users["list"], {"expand": "classification,foo"})
    validate_args(users["list-roles"], {"user": USER, "expand": "targets/groups"})
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(users["list-roles"], {"user": USER, "expand": "targets"})
    apps = registry.domains["apps"].commands
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(apps["get-users"], {"app": APP, "expand": "user/00u1emaKYZTWRYYRRTSK"})


def test_spec_enum_path_params(registry: Registry) -> None:
    feature = registry.domains["apps"].commands["get-feature"]
    validate_args(feature, {"app": APP, "feature": "USER_PROVISIONING"})


def test_q_lists_are_unpaged(registry: Registry) -> None:
    assert registry.domains["users"].commands["list"].entry.unpaged_args == ("q",)


def test_scope_sets(registry: Registry) -> None:
    users, apps = registry.domains["users"].commands, registry.domains["apps"].commands
    assert users["get-risk"].scope_sets == (frozenset({"okta.userRisk.read", "okta.users.read"}),)
    assert users["list-roles"].scope_sets == (frozenset({"okta.roles.read", "okta.users.read"}),)
    # A resolved user adds getUser's scope.
    assert apps["get-user"].scope_sets == (frozenset({"okta.apps.read", "okta.users.read"}),)
    assert apps["list-grants"].scope_sets == (frozenset({"okta.appGrants.read"}),)


def test_factor_transaction_id_shape(registry: Registry) -> None:
    # The pinned spec's own example has a dot.
    cmd = registry.domains["users"].commands["get-factor-transaction"]
    args = {"user": USER, "factor": "opfh52xcuft3J4uZc0g3"}
    validate_args(cmd, {**args, "txn": "v2mst.GldKV5VxTrifyeZmWSQguA"})
    for bad in (".", "..", ".x", "a/b"):
        with pytest.raises(InvalidArguments, match="arg 'txn'"):
            validate_args(cmd, {**args, "txn": bad})


def test_linked_objects_view_is_the_user_link(registry: Registry) -> None:
    # 5.1: items are only `_links.self` (the spec's `ResponseLinks`), so the view names its href.
    cmd = registry.domains["users"].commands["get-linked-objects"]
    assert cmd.entry.view == ("_links.self.href",)
    assert cmd.op().reserved["userIdOrLogin"] == frozenset({"me"})
    for bad in ("1manager", "manager-x", "a" * 257, "me/x"):
        with pytest.raises(InvalidArguments, match="arg 'relationship'"):
            validate_args(cmd, {"user": "00u1emaKYZTWRYYRRTSK", "relationship": bad})
    validate_args(cmd, {"user": "00u1emaKYZTWRYYRRTSK", "relationship": "manager"})
