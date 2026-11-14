"""The iam, oauth-client-roles, api-tokens and authorization-servers registries (plan 5.4)."""

from typing import Any

import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.output import ScrubRules, load_scrub
from okta_mcp.exec.params import build_request
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.expression import scrubbed
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry
from okta_mcp.registry.schema import InvalidArguments, validate_args

ORG = "https://example.okta.com"
AUS = "aus1emaKYZTWRYYRRTSK"
CLIENT = "0oa1emaKYZTWRYYRRTSK"
G1 = "00g1iamreader0000000"
DOMAINS = ("iam", "oauth-client-roles", "api-tokens", "authorization-servers")


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.op().operation_id for n, c in registry.domains[domain].commands.items()}


def test_commands(registry: Registry) -> None:
    assert _commands(registry, "iam") == {
        "list": "listRoles",
        "get": "getRole",
        "list-permissions": "listRolePermissions",
        "get-permission": "getRolePermission",
        "list-assignees": "listUsersWithRoleAssignments",
        "list-resource-sets": "listResourceSets",
        "get-resource-set": "getResourceSet",
        "list-resources": "listResourceSetResources",
        "get-resource": "getResourceSetResource",
        "list-bindings": "listBindings",
        "get-binding": "getBinding",
        "list-members": "listMembersOfBinding",
        "get-member": "getMemberOfBinding",
        "list-bundles": "listGovernanceBundles",
        "get-bundle": "getGovernanceBundle",
        "list-entitlements": "listBundleEntitlements",
        "list-entitlement-values": "listBundleEntitlementValues",
        "get-opt-in-status": "getOptInStatus",
        "list-subscriptions": "listSubscriptionsRole",
        "get-subscription": "getSubscriptionsNotificationTypeRole",
    }
    assert _commands(registry, "oauth-client-roles") == {
        "list": "listRolesForClient",
        "get": "retrieveClientRole",
        "list-app-targets": "listAppTargetRoleToClient",
        "list-group-targets": "listGroupTargetRoleForClient",
    }
    assert _commands(registry, "api-tokens") == {"list": "listApiTokens", "get": "getApiToken"}
    assert _commands(registry, "authorization-servers") == {
        "list": "listAuthorizationServers",
        "get": "getAuthorizationServer",
        "list-associated": "listAssociatedServersByTrustedType",
        "list-claims": "listOAuth2Claims",
        "get-claim": "getOAuth2Claim",
        "list-clients": "listOAuth2ClientsForAuthorizationServer",
        "list-tokens": "listRefreshTokensForAuthorizationServerAndClient",
        "get-token": "getRefreshTokenForAuthorizationServerAndClient",
        "list-keys": "listAuthorizationServerKeys",
        "get-key": "getAuthorizationServerKey",
        "list-policies": "listAuthorizationServerPolicies",
        "get-policy": "getAuthorizationServerPolicy",
        "list-policy-rules": "listAuthorizationServerPolicyRules",
        "get-policy-rule": "getAuthorizationServerPolicyRule",
        "list-resource-server-keys": "listOAuth2ResourceServerJsonWebKeys",
        "get-resource-server-key": "getOAuth2ResourceServerJsonWebKey",
        "list-scopes": "listOAuth2Scopes",
        "get-scope": "getOAuth2Scope",
    }


IAM_SETTINGS = {"get-opt-in-status", "list-subscriptions", "get-subscription"}
AS_SECRETS = {"list-keys", "get-key", "list-resource-server-keys", "get-resource-server-key"}
AS_TOKENS = {"list-tokens", "get-token"}


def test_classes(registry: Registry) -> None:
    for name, cmd in registry.domains["iam"].commands.items():
        want = ("org-config",) if name in IAM_SETTINGS else ("admin-roles",)
        assert cmd.entry.data_classes == want, name
    for cmd in registry.domains["oauth-client-roles"].commands.values():
        assert cmd.entry.data_classes == ("admin-roles",), cmd.name
    for cmd in registry.domains["api-tokens"].commands.values():
        assert cmd.entry.data_classes == ("credential-material",), cmd.name
    for name, cmd in registry.domains["authorization-servers"].commands.items():
        if name in AS_SECRETS:
            want: tuple[str, ...] = ("credential-material",)
        elif name in AS_TOKENS:
            want = ("session", "pii")
        else:
            want = ("org-config",)
        assert cmd.entry.data_classes == want, name


def test_normal_commands_return_no_scrubbed_field(registry: Registry) -> None:
    # V14 by the spec: no declared field of a normal command is one scrub.yaml redacts.
    # A `strings` rule redacts only a string, so it counts on a field without children that
    # ends in its chain (`actions.token`, the rule's token lifetimes, is an object).
    rules = load_scrub()
    always = ScrubRules(paths=rules.paths)

    def string_hit(field: str, fields: set[str]) -> bool:
        keys = tuple(field.lower().split("."))
        leaf = not any(f.startswith(field + ".") for f in fields)
        return leaf and any(keys[-len(c) :] == c for c in rules.strings)

    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            if cmd.sensitivity != "normal":
                continue
            response = cmd.op().response
            fields = set(response.fields) | {f for v in response.item_fields.values() for f in v}
            hits = sorted(f for f in fields if scrubbed(f, always) or string_hit(f, fields))
            assert not hits, (cmd.domain, cmd.name, hits)


def test_scope_sets(registry: Registry) -> None:
    def scopes(domain: str) -> set[tuple[frozenset[str], ...]]:
        return {c.scope_sets for c in registry.domains[domain].commands.values()}

    assert scopes("iam") == {(frozenset({"okta.roles.read"}),)}
    assert scopes("oauth-client-roles") == {(frozenset({"okta.roles.read"}),)}
    assert scopes("api-tokens") == {(frozenset({"okta.apiTokens.read"}),)}
    assert scopes("authorization-servers") == {(frozenset({"okta.authorizationServers.read"}),)}


WRAPPED = {
    "list": "roles",
    "list-permissions": "permissions",
    "list-assignees": "value",
    "list-resource-sets": "resource-sets",
    "list-resources": "resources",
    "list-bindings": "roles",
    "list-members": "members",
    "list-bundles": "bundles",
    "list-entitlements": "entitlements",
    "list-entitlement-values": "entitlementValues",
}


def test_iam_lists_are_wrapped(registry: Registry) -> None:
    for name, cmd in registry.domains["iam"].commands.items():
        assert cmd.entry.items_key == WRAPPED.get(name), name
        if name in WRAPPED:
            assert cmd.is_list
            # listRolePermissions doesn't page; every other wrapped list pages either way.
            want = "none" if name == "list-permissions" else "link_or_body"
            assert cmd.entry.paginate == want, name


def test_resource_server_keys_are_read_wrapped(registry: Registry) -> None:
    cmd = registry.domains["authorization-servers"].commands["list-resource-server-keys"]
    assert cmd.op().response.kind == "list"
    override = cmd.entry.response_override
    assert override is not None and override.kind == "wrapped"
    assert cmd.entry.items_key == "keys" and cmd.is_list


def test_apps_list_jwks_waits_for_a_recording(registry: Registry) -> None:
    # Spec, spec example and okta-skills disagree on its shape (5.4 rows in docs/decisions-log.md).
    ops = {c.op().operation_id for c in registry.domains["apps"].commands.values()}
    assert "listJwk" not in ops


def test_server_id_shape(registry: Registry) -> None:
    for name, cmd in registry.domains["authorization-servers"].commands.items():
        if "server" not in cmd.entry.args:
            continue
        args: dict[str, object] = {
            n: "abc"
            for n, a in cmd.entry.args.items()
            if a.path_param is not None and n not in ("server", "client")
        }
        if "client" in cmd.entry.args:
            args["client"] = CLIENT
        for n in cmd.schema.get("required", ()):
            if cmd.entry.args[n].query is not None:
                assert cmd.schema["properties"][n]["type"] == "boolean"  # extend if this fails
                args[n] = True
        for good in (AUS, "default"):
            validate_args(cmd, {**args, "server": good})
        for bad in ("DEFAULT", "defaults", "aus1emaKYZTWRYYRRTS", f"{AUS}\n", "..", "org"):
            with pytest.raises(InvalidArguments, match="arg 'server'"):
                validate_args(cmd, {**args, "server": bad})
        assert name != "list" or not args


def test_api_token_id_shape(registry: Registry) -> None:
    cmd = registry.domains["api-tokens"].commands["get"]
    validate_args(cmd, {"token": "00T1emaKYZTWRYYRRTSK"})
    # `current` is the spec's literal for the calling token.
    assert "current" in cmd.op().reserved["apiTokenId"]
    for bad in ("current", "CURRENT", "00u1emaKYZTWRYYRRTSK", "00T1emaKYZTWRYYRRTS", ""):
        with pytest.raises(InvalidArguments, match="arg 'token'"):
            validate_args(cmd, {"token": bad})
    url, _ = build_request(cmd, {"token": "00T1emaKYZTWRYYRRTSK"}, ORG)
    assert url == f"{ORG}/api/v1/api-tokens/00T1emaKYZTWRYYRRTSK"


def test_role_and_resource_set_take_id_or_label(registry: Registry) -> None:
    get = registry.domains["iam"].commands["get"]
    for good in ("cr04cxy6yzSCtNciD0g7", "HelpDeskTier2", "help-desk.tier_2"):
        validate_args(get, {"role": good})
    for bad in ("Help Desk", "-x", ".hidden", "a/b", "x" * 129):
        with pytest.raises(InvalidArguments, match="arg 'role'"):
            validate_args(get, {"role": bad})
    member = registry.domains["iam"].commands["get-member"]
    args = {"set": "iam4cxy6z7hhaZCSk0g7", "role": "cr04cxy6yzSCtNciD0g7"}
    url, _ = build_request(member, {**args, "member": "irb1q92TFAHzySt3x0g4"}, ORG)
    assert url == (
        f"{ORG}/api/v1/iam/resource-sets/iam4cxy6z7hhaZCSk0g7/bindings/"
        "cr04cxy6yzSCtNciD0g7/members/irb1q92TFAHzySt3x0g4"
    )


def test_permission_and_subscription_args(registry: Registry) -> None:
    perm = registry.domains["iam"].commands["get-permission"]
    for good in ("okta.users.read", "okta.users.userprofile.manage"):
        validate_args(perm, {"role": "cr04cxy6yzSCtNciD0g7", "permission": good})
    for bad in ("users.read", "okta.", "okta..read", "okta.a.b.c.d.e.f.g"):
        with pytest.raises(InvalidArguments, match="arg 'permission'"):
            validate_args(perm, {"role": "cr04cxy6yzSCtNciD0g7", "permission": bad})
    sub = registry.domains["iam"].commands["get-subscription"]
    validate_args(sub, {"role": "SUPER_ADMIN", "type": "USER_LOCKED_OUT"})
    validate_args(sub, {"role": "cr04cxy6yzSCtNciD0g7", "type": "OKTA_UPDATE"})
    with pytest.raises(InvalidArguments, match="arg 'type'"):
        validate_args(sub, {"role": "SUPER_ADMIN", "type": "SOMETHING_ELSE"})
    with pytest.raises(InvalidArguments, match="arg 'role'"):
        validate_args(sub, {"role": "SUPER-ADMIN", "type": "OKTA_UPDATE"})


def test_filters_and_expands(registry: Registry) -> None:
    servers = registry.domains["authorization-servers"].commands
    for name in ("list", "list-associated", "list-scopes"):
        q = servers[name].entry.args["q"]
        assert q.arg_rule is not None and q.arg_rule.reviewed, name
    # The scope filter's attributes aren't documented, so only `q` is offered.
    scopes = servers["list-scopes"]
    assert "filter" in scopes.op().params
    assert not any(a.param == "filter" for a in scopes.entry.args.values())
    for name in AS_TOKENS:
        assert servers[name].entry.args["expand"].allowed_values == ("scope",)
    tokens = servers["list-tokens"]
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(tokens, {"server": AUS, "client": CLIENT, "expand": "user"})
    url, params = build_request(
        tokens, {"server": "default", "client": CLIENT, "expand": "scope"}, ORG
    )
    assert url == f"{ORG}/api/v1/authorizationServers/default/clients/{CLIENT}/tokens"
    assert params == {"expand": "scope", "limit": "200"}
    associated = servers["list-associated"]
    _, params = build_request(associated, {"server": AUS, "trusted": True}, ORG)
    assert params == {"trusted": "true", "limit": "200"}
    # Okta 400s without `trusted` (5.4 dev-org smoke); the spec doesn't flag it.
    assert not associated.op().params["trusted"].required
    with pytest.raises(InvalidArguments, match="trusted"):
        validate_args(associated, {"server": AUS, "q": "okta"})


def _engine(registry: Registry, role: dict[str, Any]) -> Engine:
    policy = build_policy({"version": 1, "roles": {"r": {"groups": [G1], **role}}}, registry)
    scopes = frozenset(
        s
        for d in registry.domains.values()
        for c in d.commands.values()
        for ss in c.scope_sets
        for s in ss
    )
    return Engine(policy, registry, scopes)


WHO = Principal(uid="00u1example000000000", sub="user@example.com", groups=frozenset({G1}))


def test_wildcards_reach_only_normal_commands(registry: Registry) -> None:
    e = _engine(registry, {"allow": {d: ["*"] for d in DOMAINS}})
    assert e.check(WHO, "iam", "list", {}) is Verdict.FORBIDDEN
    assert e.check(WHO, "iam", "get-opt-in-status", {}) is Verdict.ALLOWED
    assert e.check(WHO, "api-tokens", "list", {}) is Verdict.FORBIDDEN
    assert e.check(WHO, "oauth-client-roles", "list", {"client": CLIENT}) is Verdict.FORBIDDEN
    assert e.check(WHO, "authorization-servers", "list", {}) is Verdict.ALLOWED
    for name in AS_SECRETS | AS_TOKENS:
        cmd = registry.domains["authorization-servers"].commands[name]
        args = {n: "abc1" for n, a in cmd.entry.args.items() if a.path_param is not None}
        args |= {"server": AUS} | ({"client": CLIENT} if "client" in args else {})
        assert e.check(WHO, "authorization-servers", name, args) is Verdict.FORBIDDEN, name
    named = _engine(registry, {"allow": {"iam": ["list"], "api-tokens": ["list"]}})
    assert named.check(WHO, "iam", "list", {}) is Verdict.ALLOWED
    assert named.check(WHO, "api-tokens", "list", {}) is Verdict.ALLOWED
