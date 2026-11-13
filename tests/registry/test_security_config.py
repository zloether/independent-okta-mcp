"""The policies, authenticators, behaviors and attack-protection registries (plan step 5.2)."""

import pytest

from okta_mcp.exec.output import load_scrub, scrub
from okta_mcp.exec.params import build_request
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.schema import InvalidArguments, validate_args
from okta_mcp.registry.spec import load_spec

DOMAINS = ("policies", "authenticators", "behaviors", "attack-protection")
AUT = "aut1emaKYZTWRYYRRTSK"
POLICY = "00plrilJ7jZ66Gn0X0g3"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(load_spec())


def _commands(registry: Registry, domain: str) -> dict[str, str]:
    return {n: c.operation.operation_id for n, c in registry.domains[domain].commands.items()}


def test_commands(registry: Registry) -> None:
    assert _commands(registry, "policies") == {
        "list": "listPolicies",
        "get": "getPolicy",
        "get-rules": "listPolicyRules",
        "get-rule": "getPolicyRule",
        "list-mappings": "listPolicyMappings",
        "get-mapping": "getPolicyMapping",
    }
    assert _commands(registry, "authenticators") == {
        "list": "listAuthenticators",
        "get": "getAuthenticator",
        "list-methods": "listAuthenticatorMethods",
        "get-method": "getAuthenticatorMethod",
        "list-aaguids": "listAllCustomAAGUIDs",
        "get-aaguid": "getCustomAAGUID",
    }
    assert _commands(registry, "behaviors") == {
        "list": "listBehaviorDetectionRules",
        "get": "getBehaviorDetectionRule",
    }
    assert _commands(registry, "attack-protection") == {
        "get-authenticator-settings": "getAuthenticatorSettings",
        "get-user-lockout-settings": "getUserLockoutSettings",
    }


def test_all_org_config_and_normal(registry: Registry) -> None:
    # The security-analyst role in design §9.3 takes policies, behaviors and attack-protection
    # with `["*"]` and no `include_sensitive`: they must stay normal for that to mean anything.
    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            assert cmd.entry.data_classes == ("org-config",), f"{domain} {cmd.name}"
            assert cmd.sensitivity == "normal"


def test_scope_sets(registry: Registry) -> None:
    expected = {
        "policies": "okta.policies.read",
        "authenticators": "okta.authenticators.read",
        "behaviors": "okta.behaviors.read",
        "attack-protection": "okta.orgs.read",
    }
    for domain, scope in expected.items():
        for cmd in registry.domains[domain].commands.values():
            assert cmd.scope_sets == (frozenset({scope}),), f"{domain} {cmd.name}"


def test_every_path_param_is_constrained(registry: Registry) -> None:
    for domain in DOMAINS:
        for cmd in registry.domains[domain].commands.values():
            for name, arg in cmd.entry.args.items():
                if arg.path_param is None:
                    continue
                prop = cmd.schema["properties"][name]
                assert arg.pattern or "enum" in prop, f"{domain} {cmd.name} {name}"


def test_policy_list_args(registry: Registry) -> None:
    cmd = registry.domains["policies"].commands["list"]
    validate_args(cmd, {"type": "OKTA_SIGN_ON"})
    validate_args(
        cmd, {"type": "ACCESS_POLICY", "status": "ACTIVE", "sort_by": "name", "expand": "rules"}
    )
    for bad in (
        {},  # `type` is required by Okta
        {"type": "nope"},
        {"type": "PASSWORD", "status": "DELETED"},
        {"type": "PASSWORD", "sort_by": "created"},
        {"type": "PASSWORD", "expand": "rules,mappings"},
    ):
        with pytest.raises(InvalidArguments):
            validate_args(cmd, bad)
    assert cmd.entry.unpaged_args == ("q",)
    q = cmd.entry.args["q"].arg_rule
    assert q is not None and q.reviewed


def test_policy_get_expand_is_closed(registry: Registry) -> None:
    cmd = registry.domains["policies"].commands["get"]
    validate_args(cmd, {"policy": POLICY, "expand": "rules"})
    with pytest.raises(InvalidArguments, match="arg 'expand'"):
        validate_args(cmd, {"policy": POLICY, "expand": "mappings"})


def test_policy_id_refuses_sibling_endpoint(registry: Registry) -> None:
    # `/api/v1/policies/simulate` is another operation (design §6.4 item 5).
    cmd = registry.domains["policies"].commands["get"]
    assert "simulate" in cmd.operation.reserved["policyId"]
    for bad in ("simulate", "SIMULATE", "simulate.json"):
        with pytest.raises(InvalidArguments, match="arg 'policy'"):
            build_request(cmd, {"policy": bad}, "https://example.okta.com")
    for bad in ("a/b", "..", "00p 1", f"{POLICY}\n"):
        with pytest.raises(InvalidArguments, match="arg 'policy'"):
            validate_args(cmd, {"policy": bad})


def test_unexposed_params(registry: Registry) -> None:
    cmd = registry.domains["policies"].commands["list"]
    assert "resourceId" in cmd.operation.params
    assert "resourceId" not in {a.param for a in cmd.entry.args.values()}
    # No page size is sent, and a next link is followed if Okta sends one.
    rules = registry.domains["policies"].commands["get-rules"]
    assert rules.entry.page_size is None and rules.entry.paginate == "link"


def test_authenticator_id_shape(registry: Registry) -> None:
    cmd = registry.domains["authenticators"].commands["get"]
    validate_args(cmd, {"authenticator": AUT})
    for bad in ("00g1emaKYZTWRYYRRTSK", "aut1", f"{AUT}\n"):
        with pytest.raises(InvalidArguments, match="arg 'authenticator'"):
            validate_args(cmd, {"authenticator": bad})


def test_method_type_is_the_spec_enum(registry: Registry) -> None:
    cmd = registry.domains["authenticators"].commands["get-method"]
    validate_args(cmd, {"authenticator": AUT, "method": "webauthn"})
    with pytest.raises(InvalidArguments, match="arg 'method'"):
        validate_args(cmd, {"authenticator": AUT, "method": "aaguids"})


def test_aaguid_is_a_uuid(registry: Registry) -> None:
    cmd = registry.domains["authenticators"].commands["get-aaguid"]
    validate_args(cmd, {"authenticator": AUT, "aaguid": "cb69481e-8ff7-4039-93ec-0a2729a154a8"})
    for bad in ("cb69481e", "../x", "cb69481e-8ff7-4039-93ec-0a2729a154a8\n"):
        with pytest.raises(InvalidArguments, match="arg 'aaguid'"):
            validate_args(cmd, {"authenticator": AUT, "aaguid": bad})


def test_password_policy_recovery_token_settings_survive_scrub() -> None:
    # `recoveryToken` is a secret string on user lifecycle responses but an object of settings
    # in a password policy: `strings` redacts the first and keeps the second.
    rules = load_scrub()
    policy = {
        "settings": {
            "recovery": {
                "factors": {
                    "okta_email": {"properties": {"recoveryToken": {"tokenLifetimeMinutes": 60}}}
                }
            }
        }
    }
    assert scrub(policy, rules) == policy
    assert scrub({"recoveryToken": "VBQ0gwBhJZsFzHGm"}, rules) == {"recoveryToken": "[redacted]"}


def test_duo_secret_key_is_scrubbed() -> None:
    duo = {"provider": {"configuration": {"host": "api-1.example.com", "secretKey": "s3cr3t"}}}
    out = scrub(duo, load_scrub())
    assert out["provider"]["configuration"] == {
        "host": "api-1.example.com",
        "secretKey": "[redacted]",
    }
