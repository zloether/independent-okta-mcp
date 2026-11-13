#!/usr/bin/env python3
"""Check and set up the Okta side of okta-mcp.

    uv run python scripts/okta-setup.py check --config okta-setup.yaml
    uv run python scripts/okta-setup.py apply --config okta-setup.yaml [--yes]

Environment: OKTA_ORG_URL and OKTA_SETUP_API_TOKEN (an SSWS token of a Super Administrator,
used only by this tool and never given to the server).

`check` only reads. `apply` shows what it will do, asks, then creates missing objects, adds
missing links (group assignments, scope grants, the admin role, policy clients and groups) and
turns on DPoP. It never deletes or loosens anything; other differences are reported for an
admin to fix by hand. Exit status: 0 when everything matches, 1 when work remains, 2 on errors.
See docs/okta-setup.md.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

import httpx2
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

GROUP_PREFIX = "mcp-okta-"
"""Default `group_prefix`."""
# The prefix goes inside a single-quoted Okta Expression Language literal, so the character set
# leaves out quotes, backslashes, braces and `$`. At least 4 characters: a short prefix ("a")
# would put most of a user's groups in every token, past Okta's cap on the claim. Mirrored in
# terraform/okta/variables.tf (tested).
GROUP_PREFIX_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 _.:-]{3,63}$"


def groups_expression(prefix: str) -> str:
    """Emits IDs of Okta-mastered groups whose name starts with `prefix` (design §8.2, V13)."""
    if not re.fullmatch(GROUP_PREFIX_PATTERN, prefix):
        raise ValueError(f"invalid group prefix {prefix!r}")
    return (
        "user.getGroups({'group.type': {'OKTA_GROUP'}}, "
        f"{{'group.profile.name': {{'{prefix}'}}}}).![id]"
    )


GROUPS_CLAIM = "groups"
POLICY_NAME = "okta-mcp clients"
RULE_NAME = "okta-mcp groups"
READ_ONLY_ADMIN = "READ_ONLY_ADMIN"
SUPER_ADMIN = "SUPER_ADMIN"
CUSTOM_ROLE = "CUSTOM"
# The narrowest standard admin role under which each scope's GET endpoints answer: Okta checks
# the token's scopes and the app's admin role together. Mirrored in docs/okta-setup.md (tested)
# and terraform/okta/main.tf. A scope missing here is refused, so add each new one after
# checking it against an org.
SCOPE_ROLES = {
    "okta.users.read": READ_ONLY_ADMIN,
    "okta.groups.read": READ_ONLY_ADMIN,
    "okta.networkZones.read": READ_ONLY_ADMIN,
    "okta.roles.read": SUPER_ADMIN,  # role assignments are visible to Super Admins only
}
ROLE_ORDER = [READ_ONLY_ADMIN, SUPER_ADMIN]
DESCRIPTION = "Managed by okta-mcp scripts/okta-setup.py"
# Claude Code requests offline_access; a rule without it fails sign-in with no_matching_policy.
# Okta issues a refresh token only when the client app also has the refresh_token grant.
RULE_SCOPES = ["openid", "profile", "email", "offline_access"]
ROTATION = {"rotation_type": "ROTATE", "leeway": 30}

T = TypeVar("T")


class SetupError(Exception):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Client(_Model):
    name: str = Field(min_length=1)
    redirect_uris: list[str] = Field(min_length=1)


class ServiceApp(_Model):
    name: str = "okta-mcp service"
    public_key_file: Path
    scopes: list[str] = Field(min_length=1)

    @field_validator("scopes")
    @classmethod
    def _read_only(cls, scopes: list[str]) -> list[str]:
        bad = [s for s in scopes if not (s.startswith("okta.") and s.endswith(".read"))]
        if bad:
            raise ValueError(f"only okta.*.read scopes are allowed, got {bad}")
        unknown = [s for s in scopes if s not in SCOPE_ROLES]
        if unknown:
            raise ValueError(f"no admin role is recorded for {unknown}; see SCOPE_ROLES")
        return scopes

    @property
    def role(self) -> str:
        """The admin role the scopes need: the broadest of their `SCOPE_ROLES`."""
        return max((SCOPE_ROLES[s] for s in self.scopes), key=ROLE_ORDER.index)

    @property
    def accepted_roles(self) -> set[str]:
        """Roles the app may hold without widening what the scopes need."""
        return set(ROLE_ORDER[: ROLE_ORDER.index(self.role) + 1]) | {CUSTOM_ROLE}


class RefreshTokens(_Model):
    """Option B (docs/okta-setup.md): rotating refresh tokens for the MCP clients."""

    idle_minutes: int = Field(ge=5, le=1440)
    lifetime_minutes: int = Field(ge=5, le=1440)

    @model_validator(mode="after")
    def _idle_within_lifetime(self) -> "RefreshTokens":
        if self.idle_minutes > self.lifetime_minutes:
            raise ValueError("idle_minutes must not exceed lifetime_minutes")
        return self


ENCODED_HOST = "must not use an encoded or shorthand host (e.g. %2e, 127.1)"


class Config(_Model):
    mcp_public_url: str
    authorization_server: str = "okta-mcp"
    scope: str = "okta-mcp"
    access_token_minutes: int = Field(default=30, ge=5, le=30)
    refresh_tokens: RefreshTokens | None = None
    group_prefix: str = Field(default=GROUP_PREFIX, pattern=GROUP_PREFIX_PATTERN)
    """Role group names start with this; the groups claim emits only such groups' IDs."""
    groups: list[str] = Field(min_length=1)
    clients: list[Client] = Field(min_length=1)
    service_app: ServiceApp

    @model_validator(mode="after")
    def _refresh_outlives_access(self) -> "Config":
        if self.refresh_tokens and self.refresh_tokens.idle_minutes < self.access_token_minutes:
            raise ValueError("refresh_tokens.idle_minutes must be at least access_token_minutes")
        return self

    @model_validator(mode="after")
    def _prefix(self) -> "Config":
        prefix = self.group_prefix
        bad = [g for g in self.groups if not g.startswith(prefix) or g == prefix]
        if bad:
            raise ValueError(f"group names must start with {prefix!r}, got {bad}")
        return self

    @property
    def groups_expression(self) -> str:
        return groups_expression(self.group_prefix)

    @property
    def client_grants(self) -> list[str]:
        return ["authorization_code"] + (["refresh_token"] if self.refresh_tokens else [])

    @field_validator("mcp_public_url")
    @classmethod
    def _url(cls, url: str) -> str:
        parts = urlsplit(url)
        loopback = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")
        if not (parts.scheme == "https" or loopback) or not parts.netloc:
            raise ValueError("must be an https URL (http only for 127.0.0.1/localhost)")
        # The server's MCP_PUBLIC_URL check refuses anything but this canonical form, so an
        # audience in any other would never match.
        if any(c.isspace() or not c.isprintable() for c in url) or "@" in parts.netloc:
            raise ValueError("must not contain whitespace, control characters or credentials")
        host = parts.hostname or ""
        if not host.isascii() or host.endswith(".") or ":" in host:
            raise ValueError("host must be an ASCII (punycode) name with no trailing dot")
        port = parts.port  # raises ValueError out of range
        if port == 0 or parts.netloc.endswith(":"):
            raise ValueError("must not have an empty or zero port")
        default = {"https": 443, "http": 80}[parts.scheme]
        suffix = f":{port}" if port not in (None, default) else ""
        canonical = f"{parts.scheme}://{host}{suffix}/mcp"
        if url != canonical:
            raise ValueError(f"must be {canonical}: path /mcp, lowercase host, no default port")
        # Pydantic's normalization, which the server's PRM uses (it decodes `%2e`, expands
        # `127.1`, ...), must leave it unchanged. A URL it refuses outright gets the same fixed
        # message, not pydantic's own text.
        try:
            normalized = str(AnyHttpUrl(url))
        except ValidationError:
            normalized = None
        if normalized != url:
            raise ValueError(ENCODED_HOST)
        return url


def load_config(path: Path) -> Config:
    try:
        return Config.model_validate(yaml.safe_load(path.read_text()))
    except (ValidationError, yaml.YAMLError) as e:
        raise SetupError(f"{path}: invalid config\n{e}") from e


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_jwk(pem: bytes) -> dict[str, str]:
    """RS256 signing JWK for an RSA public key, `kid` = RFC 7638 thumbprint."""
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError as e:
        raise SetupError("expected a PEM public key (`openssl pkey -pubout`)") from e
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise SetupError("expected an RSA public key of at least 2048 bits")
    jwk = RSAAlgorithm.to_jwk(key, as_dict=True)
    members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    thumbprint = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    kid = b64url(hashlib.sha256(thumbprint).digest())
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": jwk["n"], "e": jwk["e"]}


class Okta:
    def __init__(self, http: httpx2.Client) -> None:
        self.http = http

    def _send(
        self, method: str, path: str, body: Any = None, params: dict[str, Any] | None = None
    ) -> httpx2.Response:
        response = self.http.request(method, path, json=body, params=params)
        if response.status_code >= 400:
            try:
                error = response.json()
                causes = "; ".join(c.get("errorSummary", "") for c in error.get("errorCauses", []))
                detail = f"{error.get('errorCode')} {error.get('errorSummary')} {causes}".strip()
            except ValueError:
                detail = ""
            raise SetupError(f"{method} {path} -> HTTP {response.status_code} {detail}")
        return response

    def request(self, method: str, path: str, body: Any = None, **params: Any) -> Any:
        response = self._send(method, path, body, params or None)
        return response.json() if response.content else None

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, **params)

    def get_all(self, path: str, **params: Any) -> list[Any]:
        """Every page of a list, following `Link: rel="next"` only within this org."""
        org = self.http.base_url
        items: list[Any] = []
        url: str | None = path
        while url:
            response = self._send("GET", url, params=params or None)
            items += response.json()
            url, params = response.links.get("next", {}).get("url"), {}
            if url:
                next_url = httpx2.URL(url)
                if (next_url.scheme, next_url.host, next_url.port) != (
                    org.scheme,
                    org.host,
                    org.port,
                ):
                    raise SetupError(f"{path}: next page is on another host; not following it")
        return items

    def find(self, path: str, field: str, value: str) -> dict[str, Any] | None:
        """Exact match on a field (dotted for nested) among `q` search results; duplicates are an
        error."""

        def at(obj: Any) -> Any:
            for key in field.split("."):
                obj = (obj or {}).get(key)
            return obj

        matches = [o for o in self.get(path, q=value, limit=200) if at(o) == value]
        if len(matches) > 1:
            raise SetupError(f"{len(matches)} objects at {path} have {field} {value!r}; keep one")
        return matches[0] if matches else None


class Setup:
    def __init__(self, okta: Okta, cfg: Config, jwk: dict[str, str], *, apply: bool) -> None:
        self.okta, self.cfg, self.jwk, self.apply = okta, cfg, jwk, apply
        self.kid = jwk["kid"]  # replaced by the registered kid when the key is already uploaded
        self.todo = self.manual = 0
        self.values: dict[str, str] = {}
        self.group_ids: dict[str, str] = {}

    def _line(self, status: str, what: str, detail: str = "") -> None:
        print(f"  [{status:6}] {what}" + (f": {detail}" if detail else ""))

    def ok(self, what: str, detail: str = "") -> None:
        self._line("ok", what, detail)

    def problem(self, what: str, detail: str) -> None:
        self.manual += 1
        self._line("manual", what, detail)

    def pending(self, what: str, detail: str) -> None:
        self.todo += 1
        self._line("todo", what, detail)

    def fix(self, what: str, detail: str, action: Callable[[], T]) -> T | None:
        if not self.apply:
            self.pending(what, detail)
            return None
        result = action()
        self._line("done", what, detail)
        return result

    def run(self) -> None:
        self.groups()
        client_ids = self.clients()
        self.values["MCP_ALLOWED_CLIENT_IDS"] = ",".join(client_ids)
        self.authorization_server(client_ids)
        self.service_app()

    def groups(self) -> None:
        for name in self.cfg.groups:
            group = self.okta.find("/api/v1/groups", "profile.name", name)
            if group is None:
                body = {"profile": {"name": name, "description": DESCRIPTION}}
                group = self.fix(
                    f"group {name}",
                    "create",
                    lambda body=body: self.okta.request("POST", "/api/v1/groups", body),
                )
            elif group["type"] != "OKTA_GROUP":
                self.problem(
                    f"group {name}",
                    f"type is {group['type']}; must be an Okta group "
                    "(the groups claim ignores imported groups)",
                )
                continue  # not trusted: no app assignment, rule entry or policy.yaml ID
            else:
                self.ok(f"group {name}", group["id"])
            if group:
                self.group_ids[name] = group["id"]

    def clients(self) -> list[str]:
        client_ids: list[str] = []
        for client in self.cfg.clients:
            what = f"client {client.name!r}"
            app = self.okta.find("/api/v1/apps", "label", client.name)
            if app is None:
                app = self.fix(
                    what,
                    "create native OIDC app (PKCE, no secret)",
                    lambda client=client: self._create_client(client),
                )
            elif not self._check_client(what, app, client):
                continue  # not trusted: no group assignment, policy entry or allowlist entry
            if app is None:
                continue
            client_ids.append(app["credentials"]["oauthClient"]["client_id"])
            assigned = {g["id"] for g in self.okta.get_all(f"/api/v1/apps/{app['id']}/groups")}
            for name, gid in self.group_ids.items():
                if gid in assigned:
                    continue
                path = f"/api/v1/apps/{app['id']}/groups/{gid}"
                self.fix(
                    f"{what} assignment",
                    f"assign group {name}",
                    lambda path=path: self.okta.request("PUT", path, {}),
                )
        return client_ids

    def _create_client(self, client: Client) -> Any:
        oauth: dict[str, Any] = {
            "application_type": "native",
            "grant_types": self.cfg.client_grants,
            "response_types": ["code"],
            "redirect_uris": client.redirect_uris,
            "consent_method": "TRUSTED",
        }
        if self.cfg.refresh_tokens:
            oauth["refresh_token"] = ROTATION
        return self.okta.request(
            "POST",
            "/api/v1/apps",
            {
                "name": "oidc_client",
                "label": client.name,
                "signOnMode": "OPENID_CONNECT",
                "credentials": {"oauthClient": {"token_endpoint_auth_method": "none"}},
                "settings": {"oauthClient": oauth},
            },
        )

    def _check_client(self, what: str, app: dict[str, Any], client: Client) -> bool:
        creds = app["credentials"]["oauthClient"]
        settings = app["settings"]["oauthClient"]
        issues = []
        if settings.get("application_type") != "native":
            issues.append("must be a native app")
        if creds.get("token_endpoint_auth_method") != "none":
            issues.append("must be a public client (token_endpoint_auth_method none)")
        if not creds.get("pkce_required"):
            issues.append("PKCE is not required")
        grants = self.cfg.client_grants
        if sorted(settings.get("grant_types") or []) != grants:
            issues.append(f"grant types are {settings.get('grant_types')}, expected {grants}")
        rotation = settings.get("refresh_token") or {}
        if self.cfg.refresh_tokens and (
            rotation.get("rotation_type") != "ROTATE"
            or rotation.get("leeway", ROTATION["leeway"] + 1) > ROTATION["leeway"]
        ):
            issues.append(f"refresh token rotation is {rotation}, expected {ROTATION}")
        registered = set(settings.get("redirect_uris", []))
        if missing := sorted(set(client.redirect_uris) - registered):
            issues.append(f"redirect URIs missing: {missing}")
        if extra := sorted(registered - set(client.redirect_uris)):
            issues.append(f"redirect URIs not in config, remove them: {extra}")
        if app["status"] != "ACTIVE":
            issues.append(f"status is {app['status']}")
        for issue in issues:
            self.problem(what, issue)
        if not issues:
            self.ok(what, creds["client_id"])
        return not issues

    def authorization_server(self, client_ids: list[str]) -> None:
        cfg = self.cfg
        what = f"authorization server {cfg.authorization_server!r}"
        server = self.okta.find("/api/v1/authorizationServers", "name", cfg.authorization_server)
        if server is None:
            body = {
                "name": cfg.authorization_server,
                "description": DESCRIPTION,
                "audiences": [cfg.mcp_public_url],
            }
            server = self.fix(
                what,
                f"create with audience {cfg.mcp_public_url}",
                lambda: self.okta.request("POST", "/api/v1/authorizationServers", body),
            )
            if server is None:
                self.pending(
                    f"{what} contents", f"scope {cfg.scope}, groups claim, access policy and rule"
                )
                return
        elif server["status"] != "ACTIVE":
            self.problem(what, f"status is {server['status']}")
            return  # not trusted: no scope, claim, policy or MCP_ISSUER
        elif server["audiences"] != [cfg.mcp_public_url]:
            self.problem(
                what, f"audiences are {server['audiences']}, expected [{cfg.mcp_public_url!r}]"
            )
            return
        else:
            self.ok(what, server["issuer"])
        self.values["MCP_ISSUER"] = server["issuer"]
        base = f"/api/v1/authorizationServers/{server['id']}"
        self._scope(base)
        self._claim(base)
        self._policy(base, client_ids)

    def _scope(self, base: str) -> None:
        name = self.cfg.scope
        if any(s["name"] == name for s in self.okta.get(f"{base}/scopes", q=name)):
            self.ok(f"scope {name}")
            return
        body = {
            "name": name,
            "displayName": "Okta MCP",
            "description": "Use the okta-mcp server",
            "consent": "IMPLICIT",
            "metadataPublish": "ALL_CLIENTS",
        }
        self.fix(
            f"scope {name}", "create", lambda: self.okta.request("POST", f"{base}/scopes", body)
        )

    def _claim(self, base: str) -> None:
        what = f"claim {GROUPS_CLAIM!r}"
        expression = self.cfg.groups_expression
        claim = next(
            (
                c
                for c in self.okta.get(f"{base}/claims")
                if c["name"] == GROUPS_CLAIM and c["claimType"] == "RESOURCE"
            ),
            None,
        )
        if claim is None:
            body = {
                "name": GROUPS_CLAIM,
                "status": "ACTIVE",
                "claimType": "RESOURCE",
                "valueType": "EXPRESSION",
                "value": expression,
                "alwaysIncludeInToken": True,
                "conditions": {"scopes": []},
            }
            self.fix(
                what,
                "create on access token",
                lambda: self.okta.request("POST", f"{base}/claims", body),
            )
        elif claim["valueType"] != "EXPRESSION" or claim["value"] != expression:
            self.problem(what, f"value is {claim['value']!r}, expected {expression!r}")
        elif claim["status"] != "ACTIVE" or not claim["alwaysIncludeInToken"]:
            self.problem(what, "must be ACTIVE and always included in the token")
        elif scopes := (claim.get("conditions") or {}).get("scopes"):
            self.problem(what, f"only included for scopes {scopes}; clear the scope condition")
        else:
            self.ok(what)

    def _policy(self, base: str, client_ids: list[str]) -> None:
        what = f"access policy {POLICY_NAME!r}"
        policy = next(
            (p for p in self.okta.get(f"{base}/policies") if p["name"] == POLICY_NAME), None
        )
        if policy is None:
            if not client_ids:
                if self.apply:
                    self.problem(what, "not created: no configured client passed its checks")
                else:
                    self.pending(what, "create for the configured clients")
                return
            body = {
                "type": "OAUTH_AUTHORIZATION_POLICY",
                "name": POLICY_NAME,
                "description": DESCRIPTION,
                "priority": 1,
                "status": "ACTIVE",
                "conditions": {"clients": {"include": client_ids}},
            }
            policy = self.fix(
                what,
                "create for the configured clients",
                lambda: self.okta.request("POST", f"{base}/policies", body),
            )
            if policy is None:
                self.pending(f"policy rule {RULE_NAME!r}", "create with the policy")
                return
        else:
            include = policy["conditions"]["clients"]["include"]
            missing = [c for c in client_ids if c not in include]
            if "ALL_CLIENTS" in include:
                self.problem(what, "applies to ALL_CLIENTS; limit it to approved MCP clients")
                return  # not trusted: its rule gets no groups
            elif missing:
                policy["conditions"]["clients"]["include"] = include + missing
                self.fix(
                    what,
                    f"add clients {missing}",
                    lambda: self.okta.request("PUT", f"{base}/policies/{policy['id']}", policy),
                )
            else:
                self.ok(what)
        self._rule(f"{base}/policies/{policy['id']}/rules")

    def _rule(self, path: str) -> None:
        cfg = self.cfg
        refresh = cfg.refresh_tokens
        # Under option A no client should hold the refresh_token grant; if one does anyway, its
        # refresh tokens last no longer than an access token.
        rt_max, idle_max = (
            (refresh.lifetime_minutes, refresh.idle_minutes)
            if refresh
            else (cfg.access_token_minutes, cfg.access_token_minutes)
        )
        what = f"policy rule {RULE_NAME!r}"
        group_ids = list(self.group_ids.values())
        rule = next((r for r in self.okta.get(path) if r["name"] == RULE_NAME), None)
        if rule is None:
            if not group_ids:
                if self.apply:
                    self.problem(what, "not created: no configured group passed its checks")
                else:
                    self.pending(what, "create for the configured groups")
                return
            body = {
                "type": "RESOURCE_ACCESS",
                "name": RULE_NAME,
                "priority": 1,
                "status": "ACTIVE",
                "conditions": {
                    "grantTypes": {"include": ["authorization_code"]},
                    "people": {"groups": {"include": group_ids}},
                    "scopes": {"include": [*RULE_SCOPES, cfg.scope]},
                },
                "actions": {
                    "token": {
                        "accessTokenLifetimeMinutes": cfg.access_token_minutes,
                        "refreshTokenLifetimeMinutes": rt_max,
                        "refreshTokenWindowMinutes": idle_max,
                    }
                },
            }
            self.fix(
                what,
                f"create (authorization code, {cfg.access_token_minutes}-min tokens)",
                lambda: self.okta.request("POST", path, body),
            )
            return
        conditions = rule["conditions"]
        issues = []
        grants = conditions["grantTypes"]["include"]
        if grants != ["authorization_code"]:
            issues.append(
                f"grant types are {grants}, expected authorization_code only "
                "(refresh tokens are turned on per client app)"
            )
        scopes = conditions["scopes"]["include"]
        if cfg.scope not in scopes and "*" not in scopes:
            issues.append(f"scope {cfg.scope} is not included")
        token = rule["actions"]["token"]
        lifetime = token["accessTokenLifetimeMinutes"]
        if lifetime > cfg.access_token_minutes:
            issues.append(
                f"access tokens last {lifetime} min, expected ≤{cfg.access_token_minutes}"
            )
        # Missing or 0 means unlimited.
        rt_lifetime = token.get("refreshTokenLifetimeMinutes") or 0
        if not rt_lifetime or rt_lifetime > rt_max:
            issues.append(
                f"refresh tokens last {rt_lifetime or 'unlimited'} min, expected ≤{rt_max}"
            )
        window = token.get("refreshTokenWindowMinutes") or 0
        if not window or window > idle_max:
            issues.append(
                f"refresh token idle window is {window or 'unlimited'} min, expected ≤{idle_max}"
            )
        offline = "offline_access" in scopes or "*" in scopes
        if not offline:
            # Narrower, not wider: reported, but the rule is still trusted.
            self.problem(what, "scope offline_access is not included; Claude Code can't sign in")
        people = conditions.get("people") or {}
        if (people.get("users") or {}).get("include"):
            issues.append("includes individual users; grant access through groups only")
        include = (people.get("groups") or {}).get("include", [])
        if "EVERYONE" in include:
            issues.append(f"applies to EVERYONE; limit it to the {cfg.group_prefix}* groups")
        for issue in issues:
            self.problem(what, issue)
        if issues:
            return  # not trusted: no groups added
        missing = [g for g in group_ids if g not in include]
        if missing:
            conditions["people"] = {**people, "groups": {"include": include + missing}}
            self.fix(
                what,
                f"add groups {missing}",
                lambda: self.okta.request("PUT", f"{path}/{rule['id']}", rule),
            )
        elif offline:
            self.ok(what)

    def service_app(self) -> None:
        svc = self.cfg.service_app
        what = f"service app {svc.name!r}"
        app = self.okta.find("/api/v1/apps", "label", svc.name)
        if app is None:
            app = self.fix(
                what,
                f"create (private_key_jwt, DPoP, kid {self.jwk['kid']})",
                self._create_service_app,
            )
            if app is None:
                role = svc.role
                if role == SUPER_ADMIN:
                    role = f"{READ_ONLY_ADMIN} ({SUPER_ADMIN} by hand)"
                self.pending(f"{what} access", f"grant {' '.join(svc.scopes)}; assign {role}")
                return
            existing = None
        elif not self._check_service_app(what, app):
            return  # not trusted: no grants, role or server settings
        else:
            # Its public key is public, so anyone who can create apps could have planted it:
            # never give an app this run didn't create new access (admin confirms by hand).
            existing = f"existing app {app['id']} created {app.get('created')}"
        client_id = app["credentials"]["oauthClient"]["client_id"]
        granted = {g["scopeId"] for g in self.okta.get(f"/api/v1/apps/{app['id']}/grants")}
        roles_path = f"/oauth2/v1/clients/{client_id}/roles"
        roles = {r["type"] for r in self.okta.get(roles_path)}
        extra_grants = sorted(granted - set(svc.scopes))
        extra_roles = sorted(roles - svc.accepted_roles)
        if extra_grants:
            self.problem("service app grants", f"not in config, revoke them: {extra_grants}")
        if extra_roles:
            self.problem(
                "service app roles",
                f"remove {extra_roles}; with these scopes only {sorted(svc.accepted_roles)} "
                "are accepted",
            )
        if extra_grants or extra_roles:
            return  # not trusted: no grants, role or server settings
        self.values |= {
            "OKTA_CLIENT_ID": client_id,
            "OKTA_KEY_ID": self.kid,
            "OKTA_SCOPES": " ".join(svc.scopes),
        }
        self._grants(app["id"], granted, existing)
        self._roles(roles_path, roles, existing)

    def _create_service_app(self) -> Any:
        return self.okta.request(
            "POST",
            "/api/v1/apps",
            {
                "name": "oidc_client",
                "label": self.cfg.service_app.name,
                "signOnMode": "OPENID_CONNECT",
                "credentials": {"oauthClient": {"token_endpoint_auth_method": "private_key_jwt"}},
                "settings": {
                    "oauthClient": {
                        "application_type": "service",
                        "grant_types": ["client_credentials"],
                        "response_types": ["token"],
                        "redirect_uris": [],
                        "dpop_bound_access_tokens": True,
                        "jwks": {"keys": [self.jwk]},
                    }
                },
            },
        )

    def _check_service_app(self, what: str, app: dict[str, Any]) -> bool:
        settings = app["settings"]["oauthClient"]
        issues = []
        if settings.get("application_type") != "service":
            issues.append("must be an API Services app")
        if app["credentials"]["oauthClient"].get("token_endpoint_auth_method") != "private_key_jwt":
            issues.append(
                "client authentication must be public key / private key (private_key_jwt)"
            )
        if settings.get("grant_types") != ["client_credentials"]:
            issues.append(
                f"grant types are {settings.get('grant_types')}, expected client_credentials only"
            )
        keys = (settings.get("jwks") or {}).get("keys", [])
        ours = [k for k in keys if (k.get("n"), k.get("e")) == (self.jwk["n"], self.jwk["e"])]
        if not ours:
            issues.append(
                "the configured public key is not registered "
                "(add it under Client Credentials > Public Keys)"
            )
        else:
            self.kid = ours[0].get("kid", self.kid)
        if len(keys) > len(ours):
            issues.append("has public keys other than the configured one; remove them")
        if app["status"] != "ACTIVE":
            issues.append(f"status is {app['status']}")
        for issue in issues:
            self.problem(what, issue)
        if issues:
            return False
        if not settings.get("dpop_bound_access_tokens"):
            settings["dpop_bound_access_tokens"] = True
            self.fix(
                what,
                "turn on Require DPoP",
                lambda: self.okta.request("PUT", f"/api/v1/apps/{app['id']}", app),
            )
        else:
            self.ok(what, app["credentials"]["oauthClient"]["client_id"])
        return True

    def _grants(self, app_id: str, granted: set[str], existing: str | None) -> None:
        for scope in self.cfg.service_app.scopes:
            if scope in granted:
                self.ok(f"grant {scope}")
            elif existing:
                self.problem(f"grant {scope}", f"{existing}; confirm it is yours, then grant it")
            else:
                body = {"scopeId": scope, "issuer": str(self.okta.http.base_url).rstrip("/")}
                self.fix(
                    f"grant {scope}",
                    "grant to service app",
                    lambda body=body: self.okta.request(
                        "POST", f"/api/v1/apps/{app_id}/grants", body
                    ),
                )

    def _roles(self, path: str, roles: set[str], existing: str | None) -> None:
        role = self.cfg.service_app.role
        if role in roles:
            self.ok(f"role {role}")
        elif CUSTOM_ROLE in roles:
            # Design Appendix C allows a narrower custom role instead; don't add the broad one.
            self.ok(f"role {CUSTOM_ROLE}", f"in place of {role}; review its permissions")
        elif existing:
            self.problem(f"role {role}", f"{existing}; confirm it is yours, then assign it")
        else:
            if role == SUPER_ADMIN:
                needs = [s for s in self.cfg.service_app.scopes if SCOPE_ROLES[s] == SUPER_ADMIN]
                self.problem(
                    f"role {role}",
                    f"{', '.join(needs)} needs it; assign it by hand (this tool never assigns it)",
                )
                role = READ_ONLY_ADMIN  # enough for the other scopes until then
            if role not in roles:
                self.fix(
                    f"role {role}",
                    "assign to service app",
                    lambda: self.okta.request("POST", path, {"type": role}),
                )

    def summary(self) -> None:
        print("\nServer settings:")
        values = {
            "MCP_PUBLIC_URL": self.cfg.mcp_public_url,
            "OKTA_ORG_URL": str(self.okta.http.base_url).rstrip("/"),
            **self.values,
        }
        for key, value in values.items():
            print(f"  {key}={value}")
        print("Group IDs for policy.yaml:")
        for name, gid in self.group_ids.items():
            print(f"  {gid}  # {name}")


def _ask() -> bool:
    return input("Apply these changes? [y/N] ").strip().lower() == "y"


def run(
    argv: list[str], http: httpx2.Client | None = None, confirm: Callable[[], bool] = _ask
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["check", "apply"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--yes", action="store_true", help="apply without asking")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        key_file = args.config.parent / cfg.service_app.public_key_file
        jwk = public_jwk(key_file.read_bytes())
        if http is None:
            org = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
            token = os.environ.get("OKTA_SETUP_API_TOKEN", "")
            if not org.startswith("https://") or not token:
                raise SetupError("set OKTA_ORG_URL (https://…) and OKTA_SETUP_API_TOKEN")
            http = httpx2.Client(
                base_url=org,
                timeout=30,
                headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
            )
        okta = Okta(http)
        print(f"Checking {http.base_url} …")
        setup = Setup(okta, cfg, jwk, apply=False)
        setup.run()
        if args.command == "apply" and setup.todo:
            if not args.yes and not confirm():
                print("Nothing changed.")
                return 1
            print("Applying …")
            setup = Setup(okta, cfg, jwk, apply=True)
            setup.run()
    except (SetupError, OSError, httpx2.HTTPError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (KeyError, ValueError) as e:
        # A missing field or a non-JSON body; the message names the field, never the body.
        print(f"error: unexpected response from Okta ({type(e).__name__}: {e})", file=sys.stderr)
        return 2
    if not setup.todo:
        setup.summary()
    if setup.manual:
        print(f"\n{setup.manual} item(s) need manual changes in the Okta admin console.")
    if setup.todo:
        print(f"\n{setup.todo} item(s) missing; run `apply` to create them.")
    return 1 if setup.manual or setup.todo else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
