"""The identity-providers, org-settings, schemas and realms registries (plan 5.5)."""

import json
from pathlib import Path
from typing import Any

import pytest

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.output import ScrubRules, load_scrub, scrub
from okta_mcp.exec.params import build_request
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.policy.expression import scrubbed
from okta_mcp.policy.loader import build_policy
from okta_mcp.registry.loader import Registry
from okta_mcp.registry.schema import InvalidArguments, validate_args

ORG = "https://example.okta.com"
IDP = "0oa1emaKYZTWRYYRRTSK"
APP = "0oa1emaKYZTWRYYRRTSL"
G1 = "00g1orgreader0000000"
DOMAINS = ("identity-providers", "org-settings", "schemas", "realms")
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.operation.operation_id for n, c in registry.domains[domain].commands.items()}


def test_commands(registry: Registry) -> None:
    assert _commands(registry, "identity-providers") == {
        "list": "listIdentityProviders",
        "get": "getIdentityProvider",
        "list-keys": "listIdentityProviderKeys",
        "get-key": "getIdentityProviderKey",
        "list-csrs": "listCsrsForIdentityProvider",
        "get-csr": "getCsrForIdentityProvider",
        "list-signing-keys": "listIdentityProviderSigningKeys",
        "get-active-signing-key": "listActiveIdentityProviderSigningKey",
        "get-signing-key": "getIdentityProviderSigningKey",
        "list-users": "listIdentityProviderApplicationUsers",
        "get-user": "getIdentityProviderApplicationUser",
        "list-tokens": "listSocialAuthTokens",
    }
    assert _commands(registry, "org-settings") == {
        "get": "getOrgSettings",
        "list-contact-types": "listOrgContactTypes",
        "get-contact": "getOrgContactUser",
        "get-captcha-settings": "getOrgCaptchaSettings",
        "get-third-party-admin-setting": "getThirdPartyAdminSetting",
        "get-preferences": "getOrgPreferences",
        "get-communication-settings": "getOktaCommunicationSettings",
        "get-support-settings": "getOrgOktaSupportSettings",
        "list-support-cases": "listOktaSupportCases",
        "get-admin-app-setting": "getAutoAssignAdminAppSetting",
        "get-client-privileges": "getClientPrivilegesSetting",
        "list-yubikey-tokens": "listYubikeyOtpTokens",
        "get-yubikey-token": "getYubikeyOtpTokenById",
    }
    assert _commands(registry, "schemas") == {
        "list-mappings": "listProfileMappings",
        "get-mapping": "getProfileMapping",
        "get-user-schema": "getUserSchema",
        "get-group-schema": "getGroupSchema",
        "get-app-user-schema": "getApplicationUserSchema",
        "list-log-stream-schemas": "listLogStreamSchemas",
        "get-log-stream-schema": "getLogStreamSchema",
        "list-linked-objects": "listLinkedObjectDefinitions",
        "get-linked-object": "getLinkedObjectDefinition",
        "list-user-types": "listUserTypes",
        "get-user-type": "getUserType",
        "list-ui-schemas": "listUISchemas",
        "get-ui-schema": "getUISchema",
    }
    assert _commands(registry, "realms") == {
        "list": "listRealms",
        "get": "getRealm",
        "list-assignments": "listRealmAssignments",
        "get-assignment": "getRealmAssignment",
        "list-operations": "listRealmAssignmentOperations",
    }
    # Needs okta.orgs.manage; the service app has read scopes only.
    ops = {c.operation.operation_id for c in registry.domains["org-settings"].commands.values()}
    assert "getAerialConsent" not in ops


IDP_CONFIG = {"list", "get"}
IDP_USERS = {"list-users", "get-user"}
ORG_GRANTS = {
    "list-contact-types",
    "get-contact",
    "get-support-settings",
    "list-support-cases",
}
YUBIKEY = {"list-yubikey-tokens", "get-yubikey-token"}


def test_classes(registry: Registry) -> None:
    for name, cmd in registry.domains["identity-providers"].commands.items():
        if name in IDP_CONFIG:
            want: tuple[str, ...] = ("org-config", "credential-material")
        elif name in IDP_USERS:
            want = ("pii",)
        elif name == "list-tokens":
            want = ("credential-material", "pii")
        else:
            want = ("credential-material",)
        assert cmd.entry.data_classes == want, name
    for name, cmd in registry.domains["org-settings"].commands.items():
        if name in ORG_GRANTS:
            want = ("admin-roles",)
        elif name in YUBIKEY:
            want = ("mfa-state", "pii")
        else:
            want = ("org-config",)
        assert cmd.entry.data_classes == want, name
    for domain in ("schemas", "realms"):
        for cmd in registry.domains[domain].commands.values():
            assert cmd.entry.data_classes == ("org-config",), (domain, cmd.name)


def test_normal_commands_return_no_scrubbed_field(registry: Registry) -> None:
    # V14 by the spec, as in plan 5.4: no declared field of a normal command is one scrub.yaml
    # redacts (a `strings` rule counts on a field without children).
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
            response = cmd.operation.response
            fields = set(response.fields) | {f for v in response.item_fields.values() for f in v}
            hits = sorted(f for f in fields if scrubbed(f, always) or string_hit(f, fields))
            assert not hits, (cmd.domain, cmd.name, hits)


def _fixture(domain: str, name: str) -> Any:
    return json.loads((FIXTURES / domain / f"{name}.json").read_text())["body"]


def test_idp_secret_and_social_token_are_redacted() -> None:
    rules = load_scrub()
    idp = scrub(_fixture("identity-providers", "get"), rules)
    client = idp["protocol"]["credentials"]["client"]
    redacted = "[redacted]"
    assert client["client_secret"] == redacted
    assert client["client_id"] == "your-client-id"
    tokens = scrub(_fixture("identity-providers", "list-tokens"), rules)
    assert [t["token"] for t in tokens] == [redacted, redacted]
    assert tokens[0]["tokenType"] == "urn:ietf:params:oauth:token-type:access_token"


def test_scope_sets(registry: Registry) -> None:
    def scopes(domain: str) -> dict[str, set[str]]:
        return {
            n: {s for ss in c.scope_sets for s in ss}
            for n, c in registry.domains[domain].commands.items()
        }

    for name, got in scopes("identity-providers").items():
        # A `user` arg resolves a login first, with okta.users.read.
        want = {"okta.idps.read"} | (
            {"okta.users.read"} if name in ("get-user", "list-tokens") else set()
        )
        assert got == want, name
    for name, got in scopes("org-settings").items():
        if name == "get-captcha-settings":
            assert got == {"okta.captchas.read"}
        elif name in YUBIKEY:
            assert got == {"okta.users.read"}
        else:
            assert got == {"okta.orgs.read"}, name
    schema_scopes = {
        "list-mappings": "okta.profileMappings.read",
        "get-mapping": "okta.profileMappings.read",
        "get-user-schema": "okta.schemas.read",
        "get-group-schema": "okta.schemas.read",
        "get-app-user-schema": "okta.schemas.read",
        "list-log-stream-schemas": "okta.logStreams.read",
        "get-log-stream-schema": "okta.logStreams.read",
        "list-linked-objects": "okta.linkedObjects.read",
        "get-linked-object": "okta.linkedObjects.read",
        "list-user-types": "okta.userTypes.read",
        "get-user-type": "okta.userTypes.read",
        "list-ui-schemas": "okta.uischemas.read",
        "get-ui-schema": "okta.uischemas.read",
    }
    assert scopes("schemas") == {n: {s} for n, s in schema_scopes.items()}
    for name, got in scopes("realms").items():
        want = "okta.realms.read" if name in ("list", "get") else "okta.realmAssignments.read"
        assert got == {want}, name


def test_idp_id_shape_keeps_out_the_credentials_segment(registry: Registry) -> None:
    for name, cmd in registry.domains["identity-providers"].commands.items():
        if "idp" not in cmd.entry.args:
            assert name in ("list", "list-keys", "get-key"), name
            continue
        assert "credentials" in cmd.operation.reserved["idpId"]
        args = {n: "abc1" for n, a in cmd.entry.args.items() if a.path_param is not None}
        validate_args(cmd, {**args, "idp": IDP})
        for bad in ("credentials", "00u1emaKYZTWRYYRRTSK", "0oa1emaKYZTWRYYRRTS", f"{IDP}\n"):
            with pytest.raises(InvalidArguments, match="arg 'idp'"):
                validate_args(cmd, {**args, "idp": bad})


def test_signing_key_refuses_its_sibling_literals(registry: Registry) -> None:
    cmd = registry.domains["identity-providers"].commands["get-signing-key"]
    assert {"active", "generate"} <= cmd.operation.reserved["kid"]
    url, _ = build_request(cmd, {"idp": IDP, "key": "KmMo85SSsU7TZzOShcGb"}, ORG)
    assert url == f"{ORG}/api/v1/idps/{IDP}/credentials/keys/KmMo85SSsU7TZzOShcGb"
    for bad in ("active", "ACTIVE", "generate"):
        with pytest.raises(InvalidArguments, match="arg 'key'"):
            build_request(cmd, {"idp": IDP, "key": bad}, ORG)


def test_idp_args(registry: Registry) -> None:
    idps = registry.domains["identity-providers"].commands
    q = idps["list"].entry.args["q"]
    assert q.arg_rule is not None and q.arg_rule.reviewed
    _, params = build_request(idps["list"], {"q": "Example", "type": "OIDC"}, ORG)
    assert params == {"q": "Example", "type": "OIDC", "limit": "200"}
    with pytest.raises(InvalidArguments, match="arg 'type'"):
        validate_args(idps["list"], {"type": "oidc"})
    # Only the IdP's own records' free-form profiles: no `q` on linked users.
    users = idps["list-users"]
    assert "q" in users.operation.params
    assert not any(a.param == "q" for a in users.entry.args.values())
    assert users.entry.args["expand"].allowed_values == ("user",)
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(users, {"idp": IDP, "expand": "groups"})
    for name in ("get-user", "list-tokens"):
        assert idps[name].entry.args["user"].resolve == "user_id", name


def test_org_settings_args(registry: Registry) -> None:
    org = registry.domains["org-settings"].commands
    contact = org["get-contact"]
    for good in ("BILLING", "TECHNICAL"):
        url, _ = build_request(contact, {"type": good}, ORG)
        assert url == f"{ORG}/api/v1/org/contacts/{good}"
    with pytest.raises(InvalidArguments, match="arg 'type'"):
        validate_args(contact, {"type": "SECURITY"})
    cases = org["list-support-cases"]
    assert cases.is_list and cases.entry.items_key == "supportCases"
    tokens = org["list-yubikey-tokens"]
    exposed = {a.param for a in tokens.entry.args.values()}
    assert exposed == {"sortBy", "sortOrder", "expand"}
    assert {"filter", "forDownload"} <= set(tokens.operation.params)
    assert tokens.entry.args["expand"].allowed_values == ("user",)
    with pytest.raises(InvalidArguments, match="arg 'sort_by'"):
        validate_args(tokens, {"sort_by": "profile.secret"})
    _, params = build_request(tokens, {"sort_by": "lastVerified", "sort_order": "DESC"}, ORG)
    assert params == {"sortBy": "lastVerified", "sortOrder": "DESC", "limit": "200"}


def test_schema_args(registry: Registry) -> None:
    schemas = registry.domains["schemas"].commands
    user_schema = schemas["get-user-schema"]
    assert "linkedobjects" in user_schema.operation.reserved["schemaId"]
    url, _ = build_request(user_schema, {"schema": "default"}, ORG)
    assert url == f"{ORG}/api/v1/meta/schemas/user/default"
    for bad in ("linkedObjects", "LINKEDOBJECTS", "a.b", "a-b"):
        with pytest.raises(InvalidArguments, match="arg 'schema'"):
            build_request(user_schema, {"schema": bad}, ORG)
    app = schemas["get-app-user-schema"]
    url, _ = build_request(app, {"app": APP}, ORG)
    assert url == f"{ORG}/api/v1/meta/schemas/apps/{APP}/default"
    with pytest.raises(InvalidArguments, match="arg 'app'"):
        validate_args(app, {"app": "00g1emaKYZTWRYYRRTSK"})
    log = schemas["get-log-stream-schema"]
    validate_args(log, {"type": "aws_eventbridge"})
    with pytest.raises(InvalidArguments, match="arg 'type'"):
        validate_args(log, {"type": "syslog"})
    _, params = build_request(schemas["list-mappings"], {"source": APP}, ORG)
    assert params == {"sourceId": APP, "limit": "200"}


def test_realm_args(registry: Registry) -> None:
    realms = registry.domains["realms"].commands
    listing = realms["list"]
    for name in ("search", "sort_by"):
        rule = listing.entry.args[name].arg_rule
        assert rule is not None and rule.attribute_expression and not rule.attributes, name
    assert "fields" in listing.operation.params
    assert not any(a.param == "fields" for a in listing.entry.args.values())
    assignment = realms["get-assignment"]
    assert "operations" in assignment.operation.reserved["assignmentId"]
    for bad in ("operations", "Operations"):
        with pytest.raises(InvalidArguments, match="arg 'assignment'"):
            build_request(assignment, {"assignment": bad}, ORG)


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
    assert e.check(WHO, "identity-providers", "list", {}) is Verdict.FORBIDDEN
    assert e.check(WHO, "identity-providers", "get", {"idp": IDP}) is Verdict.FORBIDDEN
    assert e.check(WHO, "identity-providers", "list-users", {"idp": IDP}) is Verdict.ALLOWED
    assert e.check(WHO, "org-settings", "get", {}) is Verdict.ALLOWED
    for name in ORG_GRANTS | YUBIKEY:
        cmd = registry.domains["org-settings"].commands[name]
        args = {n: "abc1" for n, a in cmd.entry.args.items() if a.path_param is not None}
        args |= {"type": "BILLING"} if "type" in args else {}
        assert e.check(WHO, "org-settings", name, args) is Verdict.FORBIDDEN, name
    assert e.check(WHO, "schemas", "get-group-schema", {}) is Verdict.ALLOWED
    assert e.check(WHO, "realms", "list", {}) is Verdict.ALLOWED
    # A realm search needs `search_attributes`, whatever the allow.
    assert e.check(WHO, "realms", "list", {"search": 'profile.name co "x"'}) is Verdict.FORBIDDEN
    searcher = _engine(
        registry, {"allow": {"realms": ["list"]}, "search_attributes": ["profile.name"]}
    )
    assert (
        searcher.check(WHO, "realms", "list", {"search": 'profile.name co "x"'}) is Verdict.ALLOWED
    )
    named = _engine(registry, {"allow": {"identity-providers": ["get"]}})
    assert named.check(WHO, "identity-providers", "get", {"idp": IDP}) is Verdict.ALLOWED
