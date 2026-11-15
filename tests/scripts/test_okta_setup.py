import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from _load import SCRIPTS, load_script
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_decode

from okta_mcp.registry.loader import load_registry
from okta_mcp.registry.spec import load_spec

setup = load_script("okta-setup")

ORG = "https://example.okta.com"
MCP_URL = "https://mcp.example.com/mcp"


class FakeOkta:
    """In-memory Management API: collections keyed by path; GET lists, POST adds, PUT replaces."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        self.writes: list[tuple[str, str]] = []
        self.next_id = 0
        self.page_size: int | None = None

    def client(self) -> httpx2.Client:
        return httpx2.Client(base_url=ORG, transport=httpx2.MockTransport(self.handle))

    def items(self, *parts: str) -> list[dict[str, Any]]:
        return self.store.setdefault(parts, [])

    def find(self, *parts: str, **match: Any) -> dict[str, Any]:
        return next(i for i in self.items(*parts) if all(i.get(k) == v for k, v in match.items()))

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        parts = tuple(request.url.path.strip("/").split("/"))
        if request.method == "GET":
            q = request.url.params.get("q")
            items = [
                i
                for i in self.items(*parts)
                if not q
                or any(
                    str(v).startswith(q)
                    for v in (i.get("name"), i.get("label"), i.get("profile", {}).get("name"))
                )
            ]
            if not self.page_size:
                limit = request.url.params.get("limit")
                return httpx2.Response(200, json=items[: int(limit)] if limit else items)
            start = int(request.url.params.get("after", 0))
            end = start + self.page_size
            headers = {}
            if end < len(items):
                headers["Link"] = f'<{ORG}{request.url.path}?after={end}>; rel="next"'
            return httpx2.Response(200, json=items[start:end], headers=headers)
        self.writes.append((request.method, request.url.path))
        body = json.loads(request.content)
        if request.method == "POST":
            item = self.create(parts, body)
            self.items(*parts).append(item)
        else:
            item = {**body, "id": parts[-1]}
            siblings = self.items(*parts[:-1])
            siblings[:] = [i for i in siblings if i.get("id") != parts[-1]] + [item]
        return httpx2.Response(200, json=item)

    def create(self, parts: tuple[str, ...], body: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        item: dict[str, Any] = copy.deepcopy(body) | {"id": f"{parts[-1][:3]}{self.next_id:017d}"}
        if parts[-1] == "groups":
            item["type"] = "OKTA_GROUP"
        elif parts[-1] == "apps":
            creds = item["credentials"]["oauthClient"]
            creds["client_id"] = item["id"]
            creds["pkce_required"] = creds["token_endpoint_auth_method"] == "none"  # noqa: S105
            item["settings"]["oauthClient"].setdefault("dpop_bound_access_tokens", False)
            item["status"] = "ACTIVE"
        elif parts[-1] == "authorizationServers":
            item |= {"status": "ACTIVE", "issuer": f"{ORG}/oauth2/{item['id']}"}
        return item


def public_pem(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture
def config(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "service.pub.pem").write_bytes(public_pem(key.public_key()))
    path = tmp_path / "okta-setup.yaml"
    path.write_text(
        f"""
mcp_public_url: {MCP_URL}
groups: [mcp-okta-helpdesk, mcp-okta-readers]
clients:
  - name: Example Client
    redirect_uris: ["http://127.0.0.1:8765/callback"]
service_app:
  public_key_file: service.pub.pem
  scopes: [okta.users.read, okta.groups.read]
"""
    )
    return path


def refresh_tokens(idle: int, lifetime: int) -> str:
    return f"refresh_tokens:\n  idle_minutes: {idle}\n  lifetime_minutes: {lifetime}\n"


def use_refresh_tokens(config: Path) -> None:
    config.write_text(
        config.read_text().replace("service_app:", f"{refresh_tokens(60, 480)}service_app:")
    )


def run(okta: FakeOkta, command: str, config: Path, *extra: str, confirm: bool = True) -> int:
    return setup.run(
        [command, "--config", str(config), *extra], http=okta.client(), confirm=lambda: confirm
    )


def test_public_jwk_kid_is_rfc7638_thumbprint() -> None:
    # RFC 7638 §3.1 example key and thumbprint.
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
        "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz"
        "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6We"
        "Zu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    )
    numbers = rsa.RSAPublicNumbers(65537, int.from_bytes(base64url_decode(n), "big"))
    jwk = setup.public_jwk(public_pem(numbers.public_key()))
    assert jwk["kid"] == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert jwk | {"n": "", "kid": ""} == {
        "kty": "RSA",
        "kid": "",
        "use": "sig",
        "alg": "RS256",
        "n": "",
        "e": "AQAB",
    }


def test_public_jwk_rejects_private_key() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(setup.SetupError, match="public key"):
        setup.public_jwk(pem)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("okta.groups.read]", "okta.groups.manage]"),
        ("okta.groups.read]", "okta.realms.read]"),  # no admin role recorded for it
        ("mcp-okta-readers", "readers"),
        (MCP_URL, "http://mcp.example.com/mcp"),
        (MCP_URL, "https://mcp.example.com"),
        (MCP_URL, "https://mcp.example.com/okta/mcp"),
        (MCP_URL, "https://mcp.example.com/mcp?x=1"),
        (MCP_URL, "https://mcp.example.com/mcp?"),
        (MCP_URL, "https://mcp.example.com/mcp#"),
        (MCP_URL, "https://user@mcp.example.com/mcp"),
        (MCP_URL, "https://MCP.example.com/mcp"),
        (MCP_URL, "https://mcp.example.com:443/mcp"),
        (MCP_URL, "https://mcp.example.com./mcp"),
        (MCP_URL, "https://mcp.example.com:0/mcp"),
        (MCP_URL, "https://mcp.example.com:99999/mcp"),
        (MCP_URL, "https://mcp%2eexample.com/mcp"),
        (MCP_URL, "https://127.1/mcp"),
        ("service_app:", "access_token_minutes: 120\nservice_app:"),
        ("service_app:", "unknown_key: 1\nservice_app:"),
        ("service_app:", f"{refresh_tokens(60, 30)}service_app:"),
        ("service_app:", f"{refresh_tokens(10, 480)}service_app:"),
        ("service_app:", f"{refresh_tokens(60, 10080)}service_app:"),
    ],
)
def test_config_fails_closed(config: Path, old: str, new: str) -> None:
    config.write_text(config.read_text().replace(old, new))
    with pytest.raises(setup.SetupError, match="invalid config"):
        setup.load_config(config)


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://MCP.example.com:443/mcp", "must be https://mcp.example.com/mcp: path /mcp"),
        ("https://mcp%2eexample.com/mcp", setup.ENCODED_HOST),
        ("https://127.1/mcp", setup.ENCODED_HOST),
        # Refused by pydantic outright: the same fixed message, not pydantic's text.
        ("https://mcp%zz.example.com/mcp", setup.ENCODED_HOST),
    ],
)
def test_public_url_messages(config: Path, url: str, message: str) -> None:
    config.write_text(config.read_text().replace(MCP_URL, url))
    with pytest.raises(setup.SetupError) as e:
        setup.load_config(config)
    assert message in str(e.value)
    assert "invalid international domain name" not in str(e.value).lower()
    assert "input is not a valid url" not in str(e.value).lower()


def test_example_config_is_valid() -> None:
    cfg = setup.load_config(SCRIPTS / "okta-setup.example.yaml")
    assert cfg.service_app.scopes == ["okta.users.read", "okta.groups.read"]


# The expression verified live in 0.5 (V1, V13); the default prefix must still produce it.
DEFAULT_EXPRESSION = (
    "user.getGroups({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': {'mcp-okta-'}}).![id]"
)
TERRAFORM = SCRIPTS.parent / "terraform" / "okta"


def use_prefix(config: Path, prefix: str, groups: list[str]) -> None:
    text = config.read_text().replace(
        "groups: [mcp-okta-helpdesk, mcp-okta-readers]",
        f"group_prefix: {json.dumps(prefix)}\ngroups: {json.dumps(groups)}",
    )
    config.write_text(text)


def test_default_prefix_keeps_the_verified_expression(config: Path) -> None:
    cfg = setup.load_config(config)
    assert cfg.group_prefix == setup.GROUP_PREFIX == "mcp-okta-"
    assert cfg.groups_expression == DEFAULT_EXPRESSION


@pytest.mark.parametrize("prefix", ["APP-OktaMCP-", "MCP Okta ", "corp:mcp.", "okta_mcp_", "1234"])
def test_custom_prefix(config: Path, prefix: str) -> None:
    use_prefix(config, prefix, [f"{prefix}helpdesk"])
    cfg = setup.load_config(config)
    assert cfg.groups_expression == DEFAULT_EXPRESSION.replace("mcp-okta-", prefix)


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "abc",  # too short: the claim would carry most of a user's groups
        "x" * 65,
        " mcp-",
        "-mcp-",
        "mcp'}).![id] + {'",  # would close the expression's string literal
        "mcp\\-x",
        "mcp{x}",
        "mcp${x}",
        'mcp"x',
        "mcp-é-",
        "mcp-\n",
        "mcp*",
    ],
)
def test_bad_prefix_fails_closed(config: Path, prefix: str) -> None:
    use_prefix(config, prefix, [f"{prefix}helpdesk"])
    with pytest.raises(setup.SetupError, match="invalid config"):
        setup.load_config(config)
    with pytest.raises(ValueError, match="invalid group prefix"):
        setup.groups_expression(prefix)


@pytest.mark.parametrize(
    "groups",
    [
        ["mcp-okta-helpdesk"],  # the default prefix no longer applies
        ["APP-OktaMCP-"],  # the prefix alone
        ["app-oktamcp-helpdesk"],  # case differs
        ["APP-OktaMCP-helpdesk", "helpdesk"],
    ],
)
def test_groups_must_use_the_configured_prefix(config: Path, groups: list[str]) -> None:
    use_prefix(config, "APP-OktaMCP-", groups)
    with pytest.raises(setup.SetupError, match="must start with 'APP-OktaMCP-'"):
        setup.load_config(config)


def test_apply_with_custom_prefix_then_check_is_clean(config: Path, capsys) -> None:
    use_prefix(config, "APP-OktaMCP-", ["APP-OktaMCP-helpdesk"])
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    assert run(okta, "check", config) == 0
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    claim = okta.find("api", "v1", "authorizationServers", server["id"], "claims", name="groups")
    assert claim["value"] == DEFAULT_EXPRESSION.replace("mcp-okta-", "APP-OktaMCP-")
    assert {g["profile"]["name"] for g in okta.items("api", "v1", "groups")} == {
        "APP-OktaMCP-helpdesk"
    }


def test_changed_prefix_reports_the_old_claim_as_manual(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    use_prefix(config, "APP-OktaMCP-", ["APP-OktaMCP-helpdesk"])
    capsys.readouterr()
    writes = len(okta.writes)
    assert run(okta, "apply", config) == 1
    out = capsys.readouterr().out
    assert "[manual] claim 'groups': value is" in out
    claims = [w for w in okta.writes[writes:] if "/claims" in w[1]]
    assert claims == []  # never rewrites a claim expression


def test_terraform_prefix_matches_the_script() -> None:
    variables = (TERRAFORM / "variables.tf").read_text()
    block = re.search(r'variable "group_prefix" \{(.*?)\n\}', variables, re.DOTALL)
    assert block
    assert re.search(r'default\s*=\s*"mcp-okta-"', block[1])
    pattern = re.search(r'regex\("(.*?)", var\.group_prefix\)', block[1])
    assert pattern
    assert pattern[1] == setup.GROUP_PREFIX_PATTERN
    main = (TERRAFORM / "main.tf").read_text()
    expression = re.search(r'groups_expression = "(.*)"', main)
    assert expression
    assert expression[1].replace("${var.group_prefix}", "X-prefix") == setup.groups_expression(
        "X-prefix"
    )
    assert "startswith(each.value, var.group_prefix)" in main
    assert "mcp-okta-" not in main


# Scopes the registry uses whose narrowest admin role hasn't been checked against an org yet
# (plans 5.1 to 5.6). The setup script refuses them, so their commands stay unavailable
# until a live check adds each to SCOPE_ROLES and is removed from here.
UNVERIFIED_SCOPES = {
    # Not offered by the trial org used for the 2026-11-13 checks.
    "okta.userRisk.read",
    "okta.botProtection.read",
    "okta.realms.read",
    "okta.realmAssignments.read",
    "okta.deviceIntegrations.read",
}


def test_scope_roles_cover_the_registry() -> None:
    registry = load_registry(load_spec())
    used = {
        s
        for d in registry.domains.values()
        for c in d.commands.values()
        for ss in c.scope_sets
        for s in ss
    }
    assert used - UNVERIFIED_SCOPES <= set(setup.SCOPE_ROLES)
    # Each pending scope is still used, and not already verified.
    assert used >= UNVERIFIED_SCOPES
    assert not UNVERIFIED_SCOPES & set(setup.SCOPE_ROLES)


def test_docs_table_matches_scope_roles() -> None:
    text = (SCRIPTS.parent / "docs" / "okta-setup.md").read_text()
    rows = re.findall(r"^\| `(okta\.[A-Za-z.]+\.read)` \| `([A-Z_]+)` \|", text, re.MULTILINE)
    assert dict(rows) == setup.SCOPE_ROLES
    assert len(rows) == len(setup.SCOPE_ROLES)


def test_terraform_scope_roles_match() -> None:
    text = (SCRIPTS.parent / "terraform" / "okta" / "main.tf").read_text()
    block = re.search(r"scope_roles = \{(.*?)\}", text, re.DOTALL)
    assert block
    found = re.findall(r'"(okta\.[\w.]+\.read)"\s*=\s*"([A-Z_]+)"', block[1])
    assert dict(found) == setup.SCOPE_ROLES


def test_scope_roles_are_ordered_as_terraform_assumes() -> None:
    # main.tf picks SUPER_ADMIN, then ORG_ADMIN, if any scope needs it, else READ_ONLY_ADMIN:
    # another role must change both derivations.
    assert setup.ROLE_ORDER == [setup.READ_ONLY_ADMIN, setup.ORG_ADMIN, setup.SUPER_ADMIN]
    assert set(setup.SCOPE_ROLES.values()) <= set(setup.ROLE_ORDER)


def use_scopes(config: Path, scopes: str) -> None:
    config.write_text(config.read_text().replace("okta.users.read, okta.groups.read", scopes))


def test_roles_scope_needs_super_admin_which_apply_never_assigns(config: Path, capsys) -> None:
    use_scopes(config, "okta.users.read, okta.groups.read, okta.roles.read")
    okta = FakeOkta()
    assert run(okta, "apply", config) == 1
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    grants = okta.items("api", "v1", "apps", service["id"], "grants")
    assert {g["scopeId"] for g in grants} == {
        "okta.users.read",
        "okta.groups.read",
        "okta.roles.read",
    }
    roles = okta.items("oauth2", "v1", "clients", service["id"], "roles")
    assert [r["type"] for r in roles] == ["READ_ONLY_ADMIN"]
    assert "[manual] role SUPER_ADMIN: okta.roles.read needs SUPER_ADMIN; assign it by hand" in (
        capsys.readouterr().out
    )

    roles.append({"type": "SUPER_ADMIN"})
    assert run(okta, "check", config) == 0
    assert "OKTA_SCOPES=okta.users.read okta.groups.read okta.roles.read" in capsys.readouterr().out


def test_schemas_scope_needs_org_admin_which_apply_never_assigns(config: Path, capsys) -> None:
    use_scopes(config, "okta.users.read, okta.schemas.read")
    okta = FakeOkta()
    assert run(okta, "apply", config) == 1
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    roles = okta.items("oauth2", "v1", "clients", service["id"], "roles")
    assert [r["type"] for r in roles] == ["READ_ONLY_ADMIN"]
    assert "[manual] role ORG_ADMIN: okta.schemas.read needs ORG_ADMIN; assign it by hand" in (
        capsys.readouterr().out
    )

    roles.append({"type": "ORG_ADMIN"})
    assert run(okta, "check", config) == 0
    # Super Admin is broader than these scopes need.
    roles.append({"type": "SUPER_ADMIN"})
    assert run(okta, "check", config) == 1
    assert "remove ['SUPER_ADMIN']" in capsys.readouterr().out


def test_super_admin_scope_outranks_org_admin_scope(config: Path, capsys) -> None:
    use_scopes(config, "okta.users.read, okta.schemas.read, okta.orgs.read")
    assert run(FakeOkta(), "check", config) == 1
    assert "assign READ_ONLY_ADMIN (SUPER_ADMIN by hand)" in capsys.readouterr().out
    # Until then the Org Admin scope's commands fail too, so the message names it.
    assert run(FakeOkta(), "apply", config) == 1
    out = capsys.readouterr().out
    assert (
        "role SUPER_ADMIN: okta.schemas.read needs ORG_ADMIN, okta.orgs.read needs SUPER_ADMIN;"
        in out
    )


def test_narrower_role_than_the_scopes_need_is_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    use_scopes(config, "okta.users.read, okta.groups.read, okta.roles.read")
    capsys.readouterr()
    okta.writes.clear()

    # READ_ONLY_ADMIN stays (narrower than required, so not a widening); SUPER_ADMIN is manual.
    assert run(okta, "apply", config, "--yes") == 1
    assert [m for m, p in okta.writes if p.endswith("/roles")] == []
    assert "[manual] role SUPER_ADMIN" in capsys.readouterr().out


def test_check_on_empty_org_reports_todo_and_only_reads(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "check", config) == 1
    assert okta.writes == []
    out = capsys.readouterr().out
    assert "[todo  ] authorization server 'okta-mcp'" in out
    assert "[manual" not in out


def test_apply_declined_changes_nothing(config: Path) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config, confirm=False) == 1
    assert okta.writes == []


def test_apply_creates_everything_then_check_is_clean(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    writes = len(okta.writes)
    assert run(okta, "check", config) == 0
    assert len(okta.writes) == writes

    groups = {g["profile"]["name"]: g["id"] for g in okta.items("api", "v1", "groups")}
    assert set(groups) == {"mcp-okta-helpdesk", "mcp-okta-readers"}

    client = okta.find("api", "v1", "apps", label="Example Client")
    assert client["settings"]["oauthClient"]["application_type"] == "native"
    assert {g["id"] for g in okta.items("api", "v1", "apps", client["id"], "groups")} == set(
        groups.values()
    )

    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    assert server["audiences"] == [MCP_URL]
    base = ("api", "v1", "authorizationServers", server["id"])
    assert okta.find(*base, "claims", name="groups")["value"] == DEFAULT_EXPRESSION
    policy = okta.find(*base, "policies", name=setup.POLICY_NAME)
    assert policy["conditions"]["clients"]["include"] == [client["id"]]
    rule = okta.find(*base, "policies", policy["id"], "rules", name=setup.RULE_NAME)
    assert rule["conditions"]["people"]["groups"]["include"] == list(groups.values())
    assert rule["conditions"]["grantTypes"]["include"] == ["authorization_code"]
    assert "offline_access" in rule["conditions"]["scopes"]["include"]
    assert rule["actions"]["token"] == {
        "accessTokenLifetimeMinutes": 30,
        "refreshTokenLifetimeMinutes": 30,
        "refreshTokenWindowMinutes": 30,
    }
    assert client["settings"]["oauthClient"]["grant_types"] == ["authorization_code"]
    assert "refresh_token" not in client["settings"]["oauthClient"]

    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    oauth = service["settings"]["oauthClient"]
    assert oauth["dpop_bound_access_tokens"] is True
    kid = oauth["jwks"]["keys"][0]["kid"]
    assert {g["scopeId"] for g in okta.items("api", "v1", "apps", service["id"], "grants")} == {
        "okta.users.read",
        "okta.groups.read",
    }
    roles = okta.items("oauth2", "v1", "clients", service["id"], "roles")
    assert [r["type"] for r in roles] == ["READ_ONLY_ADMIN"]

    out = capsys.readouterr().out
    assert f"MCP_ISSUER={ORG}/oauth2/{server['id']}" in out
    assert f"OKTA_CLIENT_ID={service['id']}" in out
    assert f"MCP_ALLOWED_CLIENT_IDS={client['id']}" in out
    assert f"OKTA_KEY_ID={kid}" in out
    assert f"{groups['mcp-okta-helpdesk']}  # mcp-okta-helpdesk" in out


def test_apply_adds_links_and_turns_on_dpop(config: Path) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    service["settings"]["oauthClient"]["dpop_bound_access_tokens"] = False
    config.write_text(
        config.read_text().replace("mcp-okta-readers]", "mcp-okta-readers, mcp-okta-new]")
    )

    assert run(okta, "check", config) == 1
    okta.writes.clear()
    assert run(okta, "apply", config) == 0
    methods = [m for m, _ in okta.writes]
    assert methods.count("POST") == 1  # the new group; nothing else is recreated
    assert run(okta, "check", config) == 0
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    assert service["settings"]["oauthClient"]["dpop_bound_access_tokens"] is True


def test_key_uploaded_in_console_is_matched_by_material(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    service["settings"]["oauthClient"]["jwks"]["keys"][0]["kid"] = "console-kid"
    capsys.readouterr()
    assert run(okta, "check", config) == 0
    assert "OKTA_KEY_ID=console-kid" in capsys.readouterr().out

    service["settings"]["oauthClient"]["jwks"]["keys"][0]["n"] = "other"
    assert run(okta, "check", config) == 1
    assert "the configured public key is not registered" in capsys.readouterr().out


def test_drift_is_reported_not_changed(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    server["audiences"] = ["api://default"]
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    okta.items("oauth2", "v1", "clients", service["id"], "roles").append({"type": "SUPER_ADMIN"})
    okta.items("api", "v1", "apps", service["id"], "grants").append(
        {"scopeId": "okta.users.manage"}
    )
    capsys.readouterr()
    okta.writes.clear()

    assert run(okta, "apply", config) == 1
    assert okta.writes == []
    out = capsys.readouterr().out
    assert "[manual] authorization server 'okta-mcp': audiences are ['api://default']" in out
    assert "remove ['SUPER_ADMIN']" in out
    assert "revoke them: ['okta.users.manage']" in out


@pytest.mark.parametrize(
    "widen",
    [
        lambda okta, app_id: okta.items("oauth2", "v1", "clients", app_id, "roles").append(
            {"type": "ORG_ADMIN"}
        ),
        lambda okta, app_id: okta.items("api", "v1", "apps", app_id, "grants").append(
            {"scopeId": "okta.apps.read"}
        ),
    ],
)
def test_service_app_with_extra_access_gets_nothing_more(config: Path, widen, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    okta.items("api", "v1", "apps", service["id"], "grants")[:1] = []
    okta.items("oauth2", "v1", "clients", service["id"], "roles").clear()
    widen(okta, service["id"])
    capsys.readouterr()
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 1
    assert okta.writes == []
    out = capsys.readouterr().out
    assert "[manual] service app " in out
    assert "OKTA_CLIENT_ID" not in out


def test_existing_service_app_gets_no_new_access(config: Path, capsys) -> None:
    okta = FakeOkta()
    jwk = setup.public_jwk((config.parent / "service.pub.pem").read_bytes())
    oauth = {
        "application_type": "service",
        "grant_types": ["client_credentials"],
        "jwks": {"keys": [jwk]},
        "dpop_bound_access_tokens": True,
    }
    app = plant_app(okta, "okta-mcp service", "private_key_jwt", oauth)

    assert run(okta, "apply", config, "--yes") == 1
    assert [p for _, p in okta.writes if app["id"] in p] == []
    out = capsys.readouterr().out
    assert f"[manual] grant okta.users.read: existing app {app['id']}" in out
    assert "[manual] role READ_ONLY_ADMIN: existing app" in out


def test_existing_service_app_needing_super_admin_still_asks_to_confirm(
    config: Path, capsys
) -> None:
    use_scopes(config, "okta.users.read, okta.groups.read, okta.roles.read")
    okta = FakeOkta()
    jwk = setup.public_jwk((config.parent / "service.pub.pem").read_bytes())
    oauth = {
        "application_type": "service",
        "grant_types": ["client_credentials"],
        "jwks": {"keys": [jwk]},
        "dpop_bound_access_tokens": True,
    }
    app = plant_app(okta, "okta-mcp service", "private_key_jwt", oauth)

    assert run(okta, "apply", config, "--yes") == 1
    assert [p for _, p in okta.writes if app["id"] in p] == []
    assert f"[manual] role SUPER_ADMIN: existing app {app['id']}" in capsys.readouterr().out


def test_check_on_empty_org_says_super_admin_is_by_hand(config: Path, capsys) -> None:
    use_scopes(config, "okta.users.read, okta.groups.read, okta.roles.read")
    assert run(FakeOkta(), "check", config) == 1
    assert "assign READ_ONLY_ADMIN (SUPER_ADMIN by hand)" in capsys.readouterr().out


def plant_app(okta: FakeOkta, label: str, auth: str, oauth: dict[str, Any]) -> dict[str, Any]:
    """An app someone else created before setup ran."""
    body = {
        "label": label,
        "credentials": {"oauthClient": {"token_endpoint_auth_method": auth}},
        "settings": {"oauthClient": oauth},
    }
    app = okta.create(("api", "v1", "apps"), body)
    okta.items("api", "v1", "apps").append(app)
    return app


@pytest.mark.parametrize(
    "tamper",
    [
        lambda auth, oauth: oauth["jwks"]["keys"].append({"kty": "RSA", "n": "other", "e": "AQAB"}),
        lambda auth, oauth: oauth.update(application_type="web"),
        lambda auth, oauth: oauth.update(grant_types=["client_credentials", "authorization_code"]),
        lambda auth, oauth: auth.update(token_endpoint_auth_method="client_secret_basic"),  # noqa: S106
    ],
)
def test_unverified_service_app_gets_no_access(config: Path, tamper, capsys) -> None:
    okta = FakeOkta()
    jwk = setup.public_jwk((config.parent / "service.pub.pem").read_bytes())
    oauth = {
        "application_type": "service",
        "grant_types": ["client_credentials"],
        "jwks": {"keys": [jwk]},
    }
    app = plant_app(okta, "okta-mcp service", "private_key_jwt", oauth)
    tamper(app["credentials"]["oauthClient"], app["settings"]["oauthClient"])

    assert run(okta, "apply", config, "--yes") == 1
    touched = [p for _, p in okta.writes if app["id"] in p]
    assert touched == []
    out = capsys.readouterr().out
    assert "[manual] service app 'okta-mcp service'" in out
    assert "OKTA_CLIENT_ID" not in out


@pytest.mark.parametrize(
    "tamper",
    [
        lambda oauth: oauth["redirect_uris"].append("https://attacker.example.com/cb"),
        lambda oauth: oauth.update(application_type="web"),
        lambda oauth: oauth["grant_types"].append("refresh_token"),
    ],
)
def test_unverified_client_is_not_trusted(config: Path, tamper, capsys) -> None:
    okta = FakeOkta()
    oauth = {
        "application_type": "native",
        "grant_types": ["authorization_code"],
        "redirect_uris": ["http://127.0.0.1:8765/callback"],
    }
    app = plant_app(okta, "Example Client", "none", oauth)
    tamper(app["settings"]["oauthClient"])

    assert run(okta, "apply", config, "--yes") == 1
    assert [p for _, p in okta.writes if app["id"] in p] == []
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    assert okta.items("api", "v1", "authorizationServers", server["id"], "policies") == []
    out = capsys.readouterr().out
    assert "[manual] client 'Example Client'" in out
    assert "no configured client passed its checks" in out
    assert f"MCP_ALLOWED_CLIENT_IDS={app['id']}" not in out


def test_duplicate_labels_are_an_error(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    plant_app(okta, "okta-mcp service", "private_key_jwt", {"application_type": "service"})
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 2
    assert okta.writes == []
    assert "2 objects" in capsys.readouterr().err


def test_imported_group_is_not_used(config: Path, capsys) -> None:
    okta = FakeOkta()
    imported = {"id": "00gimported", "type": "APP_GROUP", "profile": {"name": "mcp-okta-readers"}}
    okta.items("api", "v1", "groups").append(imported)

    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if "00gimported" in p]
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert "00gimported" not in rule["conditions"]["people"]["groups"]["include"]
    out = capsys.readouterr().out
    assert "[manual] group mcp-okta-readers: type is APP_GROUP" in out
    assert "00gimported  #" not in out


def plant_group(okta: FakeOkta, name: str, members: int) -> dict[str, Any]:
    """A group someone made before the tool ran, with `members` users in it."""
    group = {
        "id": "00gplanted0000000000",
        "type": "OKTA_GROUP",
        "created": "2026-01-02T03:04:05.000Z",
        "profile": {"name": name},
    }
    okta.items("api", "v1", "groups").append(group)
    okta.items("api", "v1", "groups", group["id"], "users").extend(
        {"id": f"00u{i:017d}"} for i in range(members)
    )
    return group


def test_existing_group_with_members_is_not_used(config: Path, capsys) -> None:
    okta = FakeOkta()
    planted = plant_group(okta, "mcp-okta-readers", 2)

    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if planted["id"] in p]
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert planted["id"] not in rule["conditions"]["people"]["groups"]["include"]
    out = capsys.readouterr().out
    assert (
        f"[manual] group mcp-okta-readers: existing group {planted['id']} created "
        "2026-01-02T03:04:05.000Z has 2 member(s)"
    ) in out
    assert "reviewed_groups" in out
    assert f"{planted['id']}  #" not in out
    # The other group is still set up.
    assert len(rule["conditions"]["people"]["groups"]["include"]) == 1


def test_a_full_page_of_members_is_reported_as_a_minimum(config: Path, capsys) -> None:
    okta = FakeOkta()
    plant_group(okta, "mcp-okta-readers", setup.MEMBERS_SHOWN + 5)

    assert run(okta, "check", config) == 1
    assert f"has {setup.MEMBERS_SHOWN} or more member(s)" in capsys.readouterr().out


def test_reviewed_existing_group_is_used(config: Path, capsys) -> None:
    okta = FakeOkta()
    planted = plant_group(okta, "mcp-okta-readers", 2)
    config.write_text(config.read_text() + f"reviewed_groups: [{planted['id']}]\n")

    assert run(okta, "apply", config, "--yes") == 0
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert planted["id"] in rule["conditions"]["people"]["groups"]["include"]
    assert f"{planted['id']}  # mcp-okta-readers" in capsys.readouterr().out


def test_empty_existing_group_is_used(config: Path) -> None:
    okta = FakeOkta()
    planted = plant_group(okta, "mcp-okta-readers", 0)

    assert run(okta, "apply", config, "--yes") == 0
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert planted["id"] in rule["conditions"]["people"]["groups"]["include"]


def test_group_already_in_the_rule_stays_trusted_once_it_has_members(config: Path) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config, "--yes") == 0
    for group in okta.items("api", "v1", "groups"):
        okta.items("api", "v1", "groups", group["id"], "users").append({"id": "00u1member"})

    assert run(okta, "check", config) == 0


def test_group_with_members_added_to_the_config_later_is_not_used(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config, "--yes") == 0
    planted = plant_group(okta, "mcp-okta-new", 1)
    add_group(config)
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 1
    assert not okta.writes
    assert "[manual] group mcp-okta-new: existing group" in capsys.readouterr().out
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert planted["id"] not in rule["conditions"]["people"]["groups"]["include"]


def test_reviewed_groups_are_ids_not_names(config: Path, capsys) -> None:
    """The review was of one group's members: another group given its name is not covered."""
    config.write_text(config.read_text() + "reviewed_groups: [mcp-okta-readers]\n")

    assert run(FakeOkta(), "check", config) == 2
    assert "reviewed_groups" in capsys.readouterr().err


def test_a_review_does_not_carry_over_to_another_group_of_the_same_name(
    config: Path, capsys
) -> None:
    okta = FakeOkta()
    plant_group(okta, "mcp-okta-readers", 2)
    config.write_text(config.read_text() + "reviewed_groups: [00gother000000000000]\n")

    assert run(okta, "check", config) == 1
    assert "[manual] group mcp-okta-readers: existing group" in capsys.readouterr().out


@pytest.mark.parametrize("level", ["server", "policy", "rule"])
def test_a_group_in_an_inactive_rule_is_not_trusted_for_it(
    config: Path, level: str, capsys
) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config, "--yes") == 0
    for group in okta.items("api", "v1", "groups"):
        okta.items("api", "v1", "groups", group["id"], "users").append({"id": "00u1member"})
    path = rules_path(okta)
    target = {
        "server": okta.find("api", "v1", "authorizationServers", name="okta-mcp"),
        "policy": okta.find(*path[:-2], name=setup.POLICY_NAME),
        "rule": okta.find(*path, name=setup.RULE_NAME),
    }[level]
    target["status"] = "INACTIVE"

    assert run(okta, "check", config) == 1
    assert "[manual] group mcp-okta-readers: existing group" in capsys.readouterr().out


def test_duplicate_groups_are_an_error(config: Path, capsys) -> None:
    okta = FakeOkta()
    for gid in ("00gone", "00gtwo"):
        okta.items("api", "v1", "groups").append(
            {"id": gid, "type": "OKTA_GROUP", "profile": {"name": "mcp-okta-readers"}}
        )
    assert run(okta, "apply", config, "--yes") == 2
    assert okta.writes == []
    assert "2 objects" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "value"), [("audiences", ["api://default"]), ("status", "INACTIVE")]
)
def test_untrusted_authorization_server_is_left_alone(
    config: Path, field: str, value: Any, capsys
) -> None:
    okta = FakeOkta()
    server = okta.create(("api", "v1", "authorizationServers"), {"name": "okta-mcp"})
    okta.items("api", "v1", "authorizationServers").append(server | {field: value})

    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if server["id"] in p]
    out = capsys.readouterr().out
    assert "[manual] authorization server 'okta-mcp'" in out
    assert "MCP_ISSUER" not in out


def rules_path(okta: FakeOkta) -> tuple[str, ...]:
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    base = ("api", "v1", "authorizationServers", server["id"], "policies")
    return (*base, okta.find(*base, name=setup.POLICY_NAME)["id"], "rules")


def add_group(config: Path) -> None:
    config.write_text(
        config.read_text().replace("mcp-okta-readers]", "mcp-okta-readers, mcp-okta-new]")
    )


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        (
            lambda policy, rule: policy["conditions"]["clients"].update(include=["ALL_CLIENTS"]),
            "applies to ALL_CLIENTS",
        ),
        (
            lambda policy, rule: rule["conditions"]["grantTypes"]["include"].append("password"),
            "grant types are ['authorization_code', 'password']",
        ),
        (
            lambda policy, rule: rule["conditions"]["grantTypes"]["include"].append(
                "refresh_token"
            ),
            "refresh tokens are turned on per client app",
        ),
        (
            lambda policy, rule: rule["actions"]["token"].update(accessTokenLifetimeMinutes=1440),
            "access tokens last 1440 min",
        ),
        (
            lambda policy, rule: rule["conditions"]["people"]["groups"].update(
                include=["EVERYONE"]
            ),
            "applies to EVERYONE; limit it to the mcp-okta-* groups",
        ),
    ],
)
def test_rule_with_problems_gets_no_new_groups(config: Path, tamper, message: str, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    path = rules_path(okta)
    policy = okta.find(*path[:-2], name=setup.POLICY_NAME)
    tamper(policy, okta.find(*path, name=setup.RULE_NAME))
    add_group(config)
    capsys.readouterr()
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if "/rules" in p]
    assert message in capsys.readouterr().out


def test_rule_with_a_token_inline_hook_gets_no_new_groups(config: Path, capsys) -> None:
    # 8.1 sweep: a token inline hook can rewrite custom claims, `groups` included, after the
    # claim expression ran, so its owner could put any role group in any token.
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    rule["actions"]["token"]["inlineHook"] = {"id": "cal1emaKYZTWRYYRRTSK"}
    add_group(config)
    capsys.readouterr()
    okta.writes.clear()

    assert run(okta, "check", config) == 1
    assert "runs token inline hook 'cal1emaKYZTWRYYRRTSK'" in capsys.readouterr().out
    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if "/rules" in p]


def _other_rule(status: str = "ACTIVE") -> dict[str, Any]:
    return {
        "id": "0pr1emaKYZTWRYYRRTSK",
        "name": "other",
        "priority": 1,
        "status": status,
        "type": "RESOURCE_ACCESS",
        "conditions": {
            "grantTypes": {"include": ["authorization_code"]},
            "people": {"groups": {"include": ["EVERYONE"]}},
            "scopes": {"include": ["*"]},
        },
        "actions": {"token": {"accessTokenLifetimeMinutes": 1440}},
    }


def test_another_active_rule_in_the_policy_is_reported(config: Path, capsys) -> None:
    # Okta applies the first matching rule by priority: a sibling bypasses every bound the
    # managed rule sets (lifetimes, refresh, groups).
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    okta.items(*rules_path(okta)).insert(0, _other_rule())
    capsys.readouterr()
    assert run(okta, "check", config) == 1
    out = capsys.readouterr().out
    assert "policy rule 'other'" in out and "remove it" in out


def test_a_sibling_rule_blocks_new_groups(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    okta.items(*rules_path(okta)).insert(0, _other_rule())
    add_group(config)
    okta.writes.clear()
    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if "/rules" in p or "/policies" in p]


def test_a_second_rule_with_the_managed_name_is_reported(config: Path, capsys) -> None:
    # Name reuse doesn't hide a sibling: only the first rule with the name is the managed one.
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    rules = okta.items(*rules_path(okta))
    rules.append({**_other_rule(), "name": setup.RULE_NAME})
    capsys.readouterr()
    assert run(okta, "check", config) == 1
    assert "a second one with this name" in capsys.readouterr().out


def test_an_inline_hook_without_an_id_is_still_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    rule["actions"]["token"]["inlineHook"] = {"name": "x\x1b[2J"}
    capsys.readouterr()
    assert run(okta, "check", config) == 1
    out = capsys.readouterr().out
    assert "runs a token inline hook" in out and "\x1b" not in out


def test_an_inactive_other_rule_is_not_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    okta.items(*rules_path(okta)).insert(0, _other_rule("INACTIVE"))
    capsys.readouterr()
    assert run(okta, "check", config) == 0
    assert "'other'" not in capsys.readouterr().out


def test_another_active_policy_on_the_server_is_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    policies = rules_path(okta)[:-2]
    okta.items(*policies).insert(
        0,
        {
            "id": "00p1emaKYZTWRYYRRTSK",
            "name": "other",
            "priority": 1,
            "status": "ACTIVE",
            "conditions": {"clients": {"include": ["ALL_CLIENTS"]}},
        },
    )
    capsys.readouterr()
    assert run(okta, "check", config) == 1
    out = capsys.readouterr().out
    assert "access policy 'other'" in out and "remove it" in out


def test_service_app_with_a_jwks_uri_is_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    svc = okta.find("api", "v1", "apps", label="okta-mcp service")
    svc["settings"]["oauthClient"]["jwks_uri"] = "https://keys.example.com/jwks"
    capsys.readouterr()
    assert run(okta, "check", config) == 1
    assert "jwks_uri" in capsys.readouterr().out


def test_rule_without_offline_access_is_reported_but_trusted(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    rule["conditions"]["scopes"]["include"].remove("offline_access")
    add_group(config)
    capsys.readouterr()

    assert run(okta, "apply", config, "--yes") == 1
    assert "scope offline_access is not included" in capsys.readouterr().out
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert len(rule["conditions"]["people"]["groups"]["include"]) == 3


def test_refresh_tokens_apply_then_check_is_clean(config: Path) -> None:
    use_refresh_tokens(config)
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    writes = len(okta.writes)
    assert run(okta, "check", config) == 0
    assert len(okta.writes) == writes

    oauth = okta.find("api", "v1", "apps", label="Example Client")["settings"]["oauthClient"]
    assert oauth["grant_types"] == ["authorization_code", "refresh_token"]
    assert oauth["refresh_token"]["rotation_type"] == "ROTATE"
    rule = okta.find(*rules_path(okta), name=setup.RULE_NAME)
    assert rule["conditions"]["grantTypes"]["include"] == ["authorization_code"]
    assert rule["actions"]["token"] | {"accessTokenLifetimeMinutes": 0} == {
        "accessTokenLifetimeMinutes": 0,
        "refreshTokenLifetimeMinutes": 480,
        "refreshTokenWindowMinutes": 60,
    }


@pytest.mark.parametrize(
    "tamper",
    [
        lambda oauth: oauth.update(grant_types=["authorization_code"]),
        lambda oauth: oauth.update(refresh_token={"rotation_type": "STATIC", "leeway": 0}),
        lambda oauth: oauth.pop("refresh_token"),
        lambda oauth: oauth.update(refresh_token={"rotation_type": "ROTATE", "leeway": 60}),
        lambda oauth: oauth.update(refresh_token={"rotation_type": "ROTATE"}),
    ],
)
def test_refresh_client_with_wrong_rotation_is_not_trusted(config: Path, tamper, capsys) -> None:
    use_refresh_tokens(config)
    okta = FakeOkta()
    oauth = {
        "application_type": "native",
        "grant_types": ["refresh_token", "authorization_code"],
        "redirect_uris": ["http://127.0.0.1:8765/callback"],
        "refresh_token": dict(setup.ROTATION),
    }
    app = plant_app(okta, "Example Client", "none", oauth)
    tamper(app["settings"]["oauthClient"])

    assert run(okta, "apply", config, "--yes") == 1
    assert [p for _, p in okta.writes if app["id"] in p] == []
    assert "[manual] client 'Example Client'" in capsys.readouterr().out


@pytest.mark.parametrize("option_b", [False, True], ids=["A", "B"])
@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        (lambda t: t.update(refreshTokenLifetimeMinutes=0), "refresh tokens last unlimited min"),
        (lambda t: t.update(refreshTokenLifetimeMinutes=1440), "refresh tokens last 1440 min"),
        (lambda t: t.update(refreshTokenWindowMinutes=10080), "idle window is 10080 min"),
        (lambda t: t.pop("refreshTokenWindowMinutes"), "idle window is unlimited min"),
    ],
)
def test_rule_with_long_refresh_lifetimes_gets_no_new_groups(
    config: Path, option_b: bool, tamper, message: str, capsys
) -> None:
    if option_b:
        use_refresh_tokens(config)
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    tamper(okta.find(*rules_path(okta), name=setup.RULE_NAME)["actions"]["token"])
    add_group(config)
    capsys.readouterr()
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 1
    assert not [p for _, p in okta.writes if "/rules" in p]
    assert message in capsys.readouterr().out


def test_custom_admin_role_is_accepted(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    service = okta.find("api", "v1", "apps", label="okta-mcp service")
    okta.items("oauth2", "v1", "clients", service["id"], "roles")[:] = [{"type": "CUSTOM"}]
    okta.writes.clear()

    assert run(okta, "apply", config, "--yes") == 0
    assert okta.writes == []
    assert "[ok    ] role CUSTOM" in capsys.readouterr().out


def test_app_group_assignments_are_paged(config: Path) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    client = okta.find("api", "v1", "apps", label="Example Client")
    assigned = okta.items("api", "v1", "apps", client["id"], "groups")
    assigned[:0] = [{"id": f"00gother{i}"} for i in range(25)]
    okta.page_size = 20
    okta.writes.clear()

    assert run(okta, "check", config) == 0


def paged_okta(next_url: str) -> Any:
    def handle(request: httpx2.Request) -> httpx2.Response:
        if request.url.params.get("after"):
            return httpx2.Response(200, json=[{"id": 2}])
        return httpx2.Response(200, json=[{"id": 1}], headers={"Link": f'<{next_url}>; rel="next"'})

    return setup.Okta(httpx2.Client(base_url=ORG, transport=httpx2.MockTransport(handle)))


def test_get_all_follows_next_links() -> None:
    okta = paged_okta(f"{ORG}/api/v1/things?after=1")
    assert okta.get_all("/api/v1/things") == [{"id": 1}, {"id": 2}]


def test_get_all_refuses_next_link_to_another_host() -> None:
    okta = paged_okta("https://attacker.example.com/api/v1/things?after=1")
    with pytest.raises(setup.SetupError, match="another host"):
        okta.get_all("/api/v1/things")


def test_claim_limited_to_other_scopes_is_reported(config: Path, capsys) -> None:
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    claim = okta.find("api", "v1", "authorizationServers", server["id"], "claims", name="groups")
    claim["conditions"]["scopes"] = ["openid"]
    capsys.readouterr()

    assert run(okta, "check", config) == 1
    assert "only included for scopes ['openid']" in capsys.readouterr().out


def test_malformed_config_is_an_error(config: Path, capsys) -> None:
    config.write_text("groups: [")
    assert run(FakeOkta(), "check", config) == 2
    assert "invalid config" in capsys.readouterr().err


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(200, text="<html>maintenance</html>"),
        httpx2.Response(200, json=[{"id": "00g1", "profile": {"name": "mcp-okta-helpdesk"}}]),
    ],
)
def test_unexpected_okta_response_is_an_error(
    config: Path, response: httpx2.Response, capsys
) -> None:
    http = httpx2.Client(base_url=ORG, transport=httpx2.MockTransport(lambda _: response))
    assert setup.run(["check", "--config", str(config)], http=http) == 2
    err = capsys.readouterr().err
    assert "unexpected response from Okta" in err
    assert "maintenance" not in err


def test_missing_credentials_is_an_error(config: Path, monkeypatch, capsys) -> None:
    monkeypatch.delenv("OKTA_SETUP_API_TOKEN", raising=False)
    assert setup.run(["check", "--config", str(config)]) == 2
    assert "OKTA_SETUP_API_TOKEN" in capsys.readouterr().err


def failing(
    status: int,
    match: Callable[[httpx2.Request], bool],
    body: Any = None,
    okta: FakeOkta | None = None,
    content: bytes | None = None,
) -> tuple[FakeOkta, httpx2.Client]:
    """A FakeOkta whose requests that `match` answer `status` with `body` (or raw `content`)."""
    okta = okta or FakeOkta()
    fake = okta

    def handle(request: httpx2.Request) -> httpx2.Response:
        if match(request):
            if content is not None:
                return httpx2.Response(status, content=content)
            return httpx2.Response(status, json=body)
        return fake.handle(request)

    return okta, httpx2.Client(base_url=ORG, transport=httpx2.MockTransport(handle))


def at(path: str, method: str | None = None) -> Callable[[httpx2.Request], bool]:
    return lambda r: r.url.path.startswith(path) and method in (None, r.method)


FEATURE_OFF_BODY = {
    "errorCode": "E0000015",
    "errorSummary": "You do not have permission to access the feature you are requesting",
}
AS_PATH = "/api/v1/authorizationServers"


@pytest.mark.parametrize(("status", "method"), [(401, "GET"), (403, "GET"), (401, "POST")])
def test_no_api_access_management_names_the_add_on(
    config: Path, status: int, method: str, capsys
) -> None:
    okta, http = failing(status, at(AS_PATH, method), FEATURE_OFF_BODY)
    assert setup.run(["apply", "--config", str(config)], http=http, confirm=lambda: True) == 2
    err = capsys.readouterr().err
    assert f"HTTP {status} E0000015 You do not have permission" in err
    assert setup.NO_API_AM in err
    assert okta.items("api", "v1", "authorizationServers") == []


@pytest.mark.parametrize(
    ("status", "path", "code"),
    [
        (401, "/api/v1/groups", "E0000015"),  # another endpoint
        (403, "/api/v1/authorizationServers", "E0000006"),  # a plain permission error
        (500, "/api/v1/authorizationServers", "E0000015"),
    ],
)
def test_other_errors_get_no_add_on_hint(
    config: Path, status: int, path: str, code: str, capsys
) -> None:
    _, http = failing(status, at(path), {"errorCode": code, "errorSummary": "x"})
    assert setup.run(["check", "--config", str(config)], http=http) == 2
    err = capsys.readouterr().err
    assert f"HTTP {status} {code} x" in err
    assert "API Access Management" not in err


def test_sub_resource_feature_off_gets_the_softer_note(config: Path, capsys) -> None:
    # Under an existing server (`authorization_server: default`, or one made before the add-on
    # lapsed) E0000015 may be the add-on or another feature.
    okta = FakeOkta()
    assert run(okta, "apply", config) == 0
    server = okta.find("api", "v1", "authorizationServers", name="okta-mcp")
    claims = f"{server['id']}/claims"
    _, http = failing(403, lambda r: r.url.path.endswith(claims), FEATURE_OFF_BODY, okta)
    assert setup.run(["check", "--config", str(config)], http=http) == 2
    err = capsys.readouterr().err
    assert "HTTP 403 E0000015" in err
    assert setup.MAYBE_NO_API_AM in err
    assert setup.NO_API_AM not in err


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (["x"], ""),
        ("text", ""),
        ({"errorCode": "E0000015", "errorCauses": None}, "E0000015"),
        ({"errorCode": "E0000015", "errorCauses": "x"}, "E0000015"),
        ({"errorCode": "E0000015", "errorCauses": ["x", 1]}, "E0000015"),
        ({"errorCode": "E0000015", "errorCauses": [{"errorSummary": "cause"}]}, "E0000015 cause"),
        (
            {
                "errorCode": "E0000001",
                "errorCauses": [{"errorSummary": None}, {}, {"errorSummary": "taken"}],
            },
            "E0000001 taken",
        ),
        ({"errorCode": 15, "errorSummary": ["x"]}, ""),
        # control characters (newlines, ANSI escapes) collapse to one space
        (
            {"errorCode": "E0000001", "errorSummary": "bad\nline\x1b[31m red"},
            "E0000001 bad line [31m red",
        ),
    ],
)
def test_malformed_error_bodies(config: Path, body: Any, detail: str, capsys) -> None:
    _, http = failing(403, at(AS_PATH), body)
    assert setup.run(["check", "--config", str(config)], http=http) == 2
    err = capsys.readouterr().err
    first = err.splitlines()[0]
    assert first.endswith(f"HTTP 403 {detail}".rstrip())
    # The note needs the code: it never appears without E0000015 in the message.
    assert ("API Access Management" in err) == ("E0000015" in first)


@pytest.mark.parametrize("content", [b"", b"null", b"not json"])
def test_error_bodies_that_are_not_objects(config: Path, content: bytes, capsys) -> None:
    _, http = failing(403, at(AS_PATH), content=content)
    assert setup.run(["check", "--config", str(config)], http=http) == 2
    assert capsys.readouterr().err.splitlines()[0].endswith("HTTP 403")
