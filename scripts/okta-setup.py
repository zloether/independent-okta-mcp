#!/usr/bin/env python3
"""Check and set up the Okta side of independent-okta-mcp.

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
from typing import Annotated, Any, TypeVar, cast
from urllib.parse import urlsplit

import httpx2
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
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
# pydantic's regex engine (Rust): `$` is the end of the text, never before a final newline.
GROUP_ID_PATTERN = r"^00g[A-Za-z0-9]{17}$"


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
ORG_ADMIN = "ORG_ADMIN"
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
    "okta.apps.read": READ_ONLY_ADMIN,
    "okta.apps.interclientTrust.read": READ_ONLY_ADMIN,
    "okta.policies.read": READ_ONLY_ADMIN,
    "okta.authenticators.read": READ_ONLY_ADMIN,
    "okta.behaviors.read": READ_ONLY_ADMIN,
    "okta.logs.read": READ_ONLY_ADMIN,
    "okta.threatInsights.read": READ_ONLY_ADMIN,
    "okta.apiTokens.read": READ_ONLY_ADMIN,
    "okta.authorizationServers.read": READ_ONLY_ADMIN,
    "okta.idps.read": READ_ONLY_ADMIN,
    "okta.captchas.read": READ_ONLY_ADMIN,
    "okta.userTypes.read": READ_ONLY_ADMIN,
    "okta.uischemas.read": READ_ONLY_ADMIN,
    "okta.devices.read": READ_ONLY_ADMIN,
    "okta.deviceAssurance.read": READ_ONLY_ADMIN,
    "okta.devicePostureChecks.read": READ_ONLY_ADMIN,
    "okta.sessions.read": READ_ONLY_ADMIN,  # `sessions get` works only without DPoP
    "okta.schemas.read": ORG_ADMIN,  # user and group schemas; app user schemas need less
    "okta.profileMappings.read": ORG_ADMIN,  # get-mapping (run 27); list-mappings needs less
    "okta.linkedObjects.read": ORG_ADMIN,
    "okta.orgs.read": SUPER_ADMIN,  # four org-settings commands; the rest need less
    "okta.logStreams.read": SUPER_ADMIN,
    "okta.appGrants.read": SUPER_ADMIN,
    "okta.securityEventsProviders.read": SUPER_ADMIN,
    "okta.roles.read": SUPER_ADMIN,  # role assignments are visible to Super Admins only
}
ROLE_ORDER = [READ_ONLY_ADMIN, ORG_ADMIN, SUPER_ADMIN]
DESCRIPTION = "Managed by okta-mcp scripts/okta-setup.py"
# Claude Code requests offline_access; a rule without it fails sign-in with no_matching_policy.
# Okta issues a refresh token only when the client app also has the refresh_token grant.
RULE_SCOPES = ["openid", "profile", "email", "offline_access"]
ROTATION = {"rotation_type": "ROTATE", "leeway": 30}
MEMBERS_SHOWN = 200
"""Members counted in an existing group (one page); more are reported as "200 or more"."""

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
    # `reviewed_groups:` with its entries removed is YAML null: an empty list.
    reviewed_groups: Annotated[
        list[Annotated[str, Field(pattern=GROUP_ID_PATTERN)]],
        BeforeValidator(lambda v: [] if v is None else v),
    ] = []
    """IDs of groups that had members before they reached the policy rule, and whose members
    an admin has checked (`Setup.groups`). IDs, not names: the check was of one group, and a
    name can be given to another. Not needed once the group is in the policy rule."""
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


# Okta's "feature not available" code. On the authorization-server list/create endpoint it
# most likely means the org lacks API Access Management, which creating a custom authorization
# server needs (docs/okta-setup.md#prerequisites). Under an existing server (its claims,
# policies) it could be that or another feature, so the note says so. Not seen live: matched on
# the code at 401 or 403 (Okta sends E0000015 with 401 elsewhere, e.g. group owners).
FEATURE_OFF = "E0000015"
AUTHORIZATION_SERVERS = "/api/v1/authorizationServers"
NO_API_AM = (
    "this org can't create or use custom authorization servers. They need Okta's "
    "API Access Management add-on (Enterprise and One-App subscriptions include only the "
    "built-in 'default' server); see Prerequisites in docs/okta-setup.md"
)
MAYBE_NO_API_AM = (
    "a feature this server needs is off for the org. If the org lacks Okta's API Access "
    "Management add-on, that is the likely cause; see Prerequisites in docs/okta-setup.md"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def _one_line(text: str) -> str:
    """Okta's text with control characters (newlines, ANSI escapes) collapsed to a space."""
    return " ".join(_CONTROL.sub(" ", text).split())


def _error_detail(response: httpx2.Response) -> tuple[str | None, str]:
    """Okta's error code and a one-line summary, from whatever shape the body has."""
    try:
        error = response.json()
    except ValueError:
        return None, ""
    if not isinstance(error, dict):
        return None, ""
    fields = cast(dict[str, Any], error)
    code = fields.get("errorCode")
    code = code if isinstance(code, str) else None
    summary = fields.get("errorSummary")
    causes = fields.get("errorCauses")
    cause_summaries = [
        c.get("errorSummary")
        for c in (causes if isinstance(causes, list) else [])
        if isinstance(c, dict)
    ]
    cause_text = "; ".join(
        _one_line(s) for s in cause_summaries if isinstance(s, str) and s.strip()
    )
    parts = [
        _one_line(code) if code else None,
        _one_line(summary) if isinstance(summary, str) else None,
        cause_text,
    ]
    return code, " ".join(p for p in parts if p)


class Okta:
    def __init__(self, http: httpx2.Client) -> None:
        self.http = http

    def _send(
        self, method: str, path: str, body: Any = None, params: dict[str, Any] | None = None
    ) -> httpx2.Response:
        response = self.http.request(method, path, json=body, params=params)
        if response.status_code >= 400:
            code, detail = _error_detail(response)
            message = f"{method} {path} -> HTTP {response.status_code} {detail}".rstrip()
            target = httpx2.URL(path).path.rstrip("/")
            if code == FEATURE_OFF and response.status_code in (401, 403):
                if target == AUTHORIZATION_SERVERS:
                    message += f"\n{NO_API_AM}"
                elif target.startswith(f"{AUTHORIZATION_SERVERS}/"):
                    message += f"\n{MAYBE_NO_API_AM}"
            raise SetupError(message)
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

    def _rule_groups(self) -> tuple[set[str], str]:
        """IDs of the groups already in the managed policy rule: put there by this tool or by
        an admin who can edit the authorization server (who decides who gets tokens anyway),
        so already accepted as role groups. Only from the one ACTIVE server, policy and rule
        of the managed names; whether that rule is otherwise sound is `_rule`'s to say. With
        the IDs, a note for the report when a server, policy or rule is there but can't
        vouch for any group: the report then gives that as a remedy beside the review."""
        cfg = self.cfg
        server = self.okta.find("/api/v1/authorizationServers", "name", cfg.authorization_server)
        if server is None:
            return set(), ""
        if server.get("status") != "ACTIVE":
            return set(), f"authorization server {cfg.authorization_server!r} is not ACTIVE"
        base = f"/api/v1/authorizationServers/{server['id']}/policies"
        policies = [p for p in self.okta.get(base) if p["name"] == POLICY_NAME]
        if not policies:
            return set(), ""
        if len(policies) != 1 or policies[0].get("status") != "ACTIVE":
            return set(), f"access policy {POLICY_NAME!r} is not ACTIVE, or there are two"
        rules = self.okta.get(f"{base}/{policies[0]['id']}/rules")
        rules = [r for r in rules if r["name"] == RULE_NAME]
        if not rules:
            return set(), ""
        if len(rules) != 1 or rules[0].get("status") != "ACTIVE":
            return set(), f"policy rule {RULE_NAME!r} is not ACTIVE, or there are two"
        people = (rules[0].get("conditions") or {}).get("people") or {}
        return set((people.get("groups") or {}).get("include") or []), ""

    def _unreviewed(self, group: dict[str, Any], accepted: set[str], note: str) -> str | None:
        """Why an existing group isn't used yet, or None. Group names are not reserved, so
        anyone who can create a group could have made this one, with themselves in it, for a
        Super Admin to turn into a role (as for an existing service app). A group is used when
        this run created it, it is already in the policy rule, it has no members, or the
        config lists its ID under `reviewed_groups`. Who joins a group later is outside this
        tool's view (design R7)."""
        if group["id"] in accepted or group["id"] in self.cfg.reviewed_groups:
            return None
        members = self.okta.get(f"/api/v1/groups/{group['id']}/users", limit=MEMBERS_SHOWN)
        if not members:
            return None
        count = f"{len(members)}{' or more' if len(members) >= MEMBERS_SHOWN else ''}"
        if note:
            # Perhaps a group this tool set up: the rule that would say so can't be relied on
            # as it is. Both remedies, since which applies is the admin's to know.
            return (
                f"existing group {group['id']} created {group.get('created')} has {count} "
                f"member(s), and {note}, so the policy rule can't show whether this group "
                "was already accepted: anyone in it gets the role. If this tool set the group "
                "up, fix that and run again; otherwise check its members, then add this ID to "
                "reviewed_groups in the config (or empty the group) and run again"
            )
        return (
            f"existing group {group['id']} created {group.get('created')} has {count} "
            "member(s) and is not in the policy rule yet: anyone in it gets the role. Check "
            "its members, then add this ID to reviewed_groups in the config (or empty the "
            "group) and run again"
        )

    def groups(self) -> None:
        accepted, note = self._rule_groups()
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
            elif reason := self._unreviewed(group, accepted, note):
                self.problem(f"group {name}", reason)
                continue  # not trusted, as above
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

    def _others(
        self, kind: str, items: list[dict[str, Any]], ours: str
    ) -> tuple[dict[str, Any] | None, bool]:
        """The first item named `ours`, and whether any other ACTIVE one was reported, a second
        one named `ours` included. Okta applies the first that matches, by priority, so another
        one can issue tokens on this server that ours doesn't bound. While one is there, ours
        isn't trusted: nothing is created in or added to it."""
        mine = next((i for i in items if i["name"] == ours), None)
        found = False
        for item in items:
            if item is not mine and item.get("status") == "ACTIVE":
                found = True
                self.problem(
                    f"{kind} {item['name']!r}",
                    ("a second one with this name" if item["name"] == ours else "not managed")
                    + " on the authorization server this tool dedicates to independent-okta-mcp: "
                    f"it can issue tokens {ours!r} doesn't bound; remove it",
                )
        return mine, found

    def _policy(self, base: str, client_ids: list[str]) -> None:
        what = f"access policy {POLICY_NAME!r}"
        policy, others = self._others(
            "access policy", self.okta.get(f"{base}/policies"), POLICY_NAME
        )
        if others:
            return  # not trusted: nothing created, no clients or groups added
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
        rule, others = self._others("policy rule", self.okta.get(path), RULE_NAME)
        if others:
            return  # not trusted: nothing created, no groups added
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
        # A token inline hook can rewrite custom claims, `groups` included, after the claim
        # expression has run: whoever runs the hook could give any user any role.
        if hook := token.get("inlineHook"):
            hook_id = hook.get("id") if isinstance(hook, dict) else None
            issues.append(
                f"runs token inline hook {hook_id!r}; a hook can rewrite the groups claim, so "
                "remove it (Security > API > the authorization server > Access Policies > the rule)"
                if isinstance(hook_id, str)
                else "runs a token inline hook; a hook can rewrite the groups claim, so remove it"
            )
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
                if role != READ_ONLY_ADMIN:
                    role = f"{READ_ONLY_ADMIN} ({role} by hand)"
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
        if settings.get("jwks_uri"):
            issues.append("has a jwks_uri: Okta could take keys from it; remove it")
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
            if role != READ_ONLY_ADMIN:
                needs = [
                    f"{s} needs {SCOPE_ROLES[s]}"
                    for s in self.cfg.service_app.scopes
                    if SCOPE_ROLES[s] != READ_ONLY_ADMIN
                ]
                self.problem(
                    f"role {role}",
                    f"{', '.join(needs)}; assign it by hand (this tool never assigns it)",
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
