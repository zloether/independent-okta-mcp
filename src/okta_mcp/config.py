"""Server configuration from environment variables (design §11.3).

`load_config` returns a frozen `Config` or raises `ConfigError` listing every problem with
single variables. Unreadable `_FILE` secrets are reported first, on their own; rules that span
variables run once single variables pass. Values are stripped, and an empty one counts as
unset. Secrets may be read from `<NAME>_FILE` instead and are held as pydantic secrets, so they
never appear in a repr or an error message.
"""

import base64
import binascii
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretBytes,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import ErrorDetails

log = logging.getLogger(__name__)

_SECRETS = ("MCP_CURSOR_KEY", "OKTA_API_TOKEN")
_LOOPBACK = frozenset({"127.0.0.1", "localhost"})  # as in scripts/okta-setup.py
_DEFAULT_PORT = {"https": 443, "http": 80}
MCP_PATH = "/mcp"


class ConfigError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


def _comma_list(v: str) -> tuple[str, ...]:
    return tuple(s.strip() for s in v.split(",") if s.strip())


def _space_set(v: str) -> frozenset[str]:
    return frozenset(v.split())


CommaList = Annotated[tuple[str, ...], BeforeValidator(_comma_list)]
SpaceSet = Annotated[frozenset[str], BeforeValidator(_space_set), Field(min_length=1)]


def _url(value: str, *, origin_only: bool = False, http_loopback: bool = False) -> str:
    if any(c.isspace() or not c.isprintable() for c in value):
        raise ValueError("must not contain whitespace or control characters")
    parts = urlsplit(value)
    if not parts.hostname:
        raise ValueError("must be an absolute URL with a host")
    # Okta and browsers use ASCII (punycode) hosts with no trailing dot; anything else never
    # matches an `Origin`, `iss` or `Link` they send.
    if not parts.hostname.isascii() or parts.hostname.endswith("."):
        raise ValueError("host must be ASCII (punycode) with no trailing dot")
    port = parts.port  # raises ValueError on a bad port
    if parts.netloc.endswith(":") or port == 0:
        raise ValueError("must not have an empty or zero port")
    if not (
        parts.scheme == "https"
        or (http_loopback and parts.scheme == "http" and parts.hostname in _LOOPBACK)
    ):
        raise ValueError(
            "must use https" + (" (http only on a loopback host)" if http_loopback else "")
        )
    if "@" in parts.netloc or "?" in value or "#" in value:
        raise ValueError("must not contain credentials, a query or a fragment")
    if origin_only:
        if parts.path not in ("", "/"):
            raise ValueError("must be an origin with no path, e.g. https://example.okta.com")
        # Canonical form (lowercase host, no default port), as browsers send `Origin` and as
        # request URLs and DPoP `htu` are built from it.
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        suffix = f":{port}" if port is not None and port != _DEFAULT_PORT[parts.scheme] else ""
        return f"{parts.scheme}://{host}{suffix}"
    return value


def _cursor_key(v: str) -> bytes:
    # Accept wrapped lines (`openssl rand -base64`) and unpadded URL-safe base64
    # (`secrets.token_urlsafe`).
    s = "".join(v.split()).replace("-", "+").replace("_", "/")
    try:
        key = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except binascii.Error:
        raise ValueError("must be base64") from None
    if len(key) < 32:
        raise ValueError("must decode to at least 32 bytes")
    return key


def _readable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError:  # stat refused (EPERM/EACCES): Python 3.12's is_file raises those
        return False


class Config(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    env: Literal["development", "production"] = Field("development", alias="MCP_ENV")
    public_url: str | None = Field(None, alias="MCP_PUBLIC_URL")
    issuer: str | None = Field(None, alias="MCP_ISSUER")
    audience: str | None = Field(None, alias="MCP_AUDIENCE")
    """Defaults to `public_url`."""
    required_scope: str = Field("okta-mcp", alias="MCP_REQUIRED_SCOPE")
    allowed_client_ids: CommaList = Field((), alias="MCP_ALLOWED_CLIENT_IDS")
    groups_claim: str = Field("groups", alias="MCP_GROUPS_CLAIM")
    max_token_age: int = Field(86400, ge=60, alias="MCP_MAX_TOKEN_AGE")
    """Oldest `iat` accepted (s). Okta's longest access-token lifetime is one day."""
    policy_file: Path = Field(alias="MCP_POLICY_FILE")
    cursor_key: Annotated[SecretBytes, BeforeValidator(_cursor_key)] = Field(alias="MCP_CURSOR_KEY")
    allowed_origins: CommaList = Field((), alias="MCP_ALLOWED_ORIGINS")
    """Canonical origins, as `_url(origin_only=True)` returns them."""
    host: str = Field("127.0.0.1", alias="MCP_HOST")
    port: int = Field(8080, ge=1, le=65535, alias="MCP_PORT")
    trust_proxy: bool = Field(False, alias="MCP_TRUST_PROXY")
    dev_mode: bool = Field(False, alias="MCP_DEV_MODE")
    dev_principal_file: Path | None = Field(None, alias="MCP_DEV_PRINCIPAL_FILE")
    default_limit: int = Field(50, gt=0, alias="MCP_DEFAULT_LIMIT")
    max_items: int = Field(1000, gt=0, alias="MCP_MAX_ITEMS")
    max_bytes: int = Field(65536, ge=1024, alias="MCP_MAX_BYTES")
    max_batch: int = Field(50, gt=0, alias="MCP_MAX_BATCH")
    # At least twice the list's 1 s deadline headroom (`exec.envelope.DEADLINE_HEADROOM`); the
    # executor checks it too.
    call_timeout: float = Field(60, ge=2, alias="MCP_CALL_TIMEOUT")
    okta_max_inflight: int = Field(10, gt=0, alias="MCP_OKTA_MAX_INFLIGHT")
    requests_per_minute: int = Field(600, gt=0, alias="MCP_REQUESTS_PER_MINUTE")
    audit_log: str = Field("stdout", alias="MCP_AUDIT_LOG")
    audit_args: Literal["full", "hash"] = Field("full", alias="MCP_AUDIT_ARGS")
    log_level: Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], BeforeValidator(str.upper)
    ] = Field("INFO", alias="MCP_LOG_LEVEL")
    okta_org_url: str = Field(alias="OKTA_ORG_URL")
    """Canonical origin, no trailing slash."""
    okta_client_id: str | None = Field(None, alias="OKTA_CLIENT_ID")
    okta_private_key_file: Path | None = Field(None, alias="OKTA_PRIVATE_KEY_FILE")
    okta_key_id: str | None = Field(None, alias="OKTA_KEY_ID")
    okta_scopes: SpaceSet = Field(alias="OKTA_SCOPES")
    okta_dpop: bool = Field(True, alias="OKTA_DPOP")
    okta_rate_limit_max_wait: float = Field(10, ge=0, alias="OKTA_RATE_LIMIT_MAX_WAIT")
    okta_api_token: SecretStr | None = Field(None, alias="OKTA_API_TOKEN")

    @model_validator(mode="before")
    @classmethod
    def _default_audience(cls, data: dict[str, str]) -> dict[str, str]:
        if "MCP_AUDIENCE" not in data and "MCP_PUBLIC_URL" in data:
            return {**data, "MCP_AUDIENCE": data["MCP_PUBLIC_URL"]}
        return data

    @field_validator("public_url")
    @classmethod
    def _public_url(cls, v: str) -> str:
        v = _url(v, http_loopback=True)
        # The one path the HTTP app serves; PRM `resource`, its URL in a 401, and the expected
        # `aud` are all this value (design §8.1), so it must be canonical too: the SDK
        # canonicalizes it for PRM, while `aud` is compared as written.
        parts = urlsplit(v)
        if parts.path != MCP_PATH:
            raise ValueError(f"path must be {MCP_PATH}, the endpoint the server serves")
        canonical = _url(f"{parts.scheme}://{parts.netloc}", origin_only=True, http_loopback=True)
        if v != canonical + MCP_PATH:
            raise ValueError(f"must be in canonical form: {canonical}{MCP_PATH}")
        # And unchanged by the SDK's own normalization (`AnyHttpUrl`, as PRM is built), which
        # also decodes `%2e`, expands `127.1` and the like.
        if str(AnyHttpUrl(v)) != v:
            raise ValueError("must be in canonical form (no encoded or shorthand host)")
        return v

    @field_validator("issuer")
    @classmethod
    def _issuer(cls, v: str) -> str:
        return _url(v)

    @field_validator("okta_org_url")
    @classmethod
    def _org_url(cls, v: str) -> str:
        return _url(v, origin_only=True)

    @field_validator("allowed_origins")
    @classmethod
    def _origins(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_url(o, origin_only=True, http_loopback=True) for o in v)

    @field_validator("required_scope", "groups_claim")
    @classmethod
    def _one_word(cls, v: str) -> str:
        # Compared with one `scp` entry or claim name; a space can never match.
        if any(c.isspace() for c in v):
            raise ValueError("must be a single name with no whitespace")
        return v

    @field_validator("allowed_client_ids")
    @classmethod
    def _client_ids(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if "*" in v and len(v) > 1:
            raise ValueError("'*' must be the only entry")
        return v

    @field_validator("okta_scopes")
    @classmethod
    def _read_scopes(cls, v: frozenset[str]) -> frozenset[str]:
        # Read-only invariant: the service token never carries a write scope (design §10).
        if bad := sorted(s for s in v if not s.endswith(".read")):
            raise ValueError(f"only read scopes are allowed, got {', '.join(bad)}")
        return v

    @model_validator(mode="after")
    def _cross_variable(self) -> Self:
        """Rules that span variables (design §8.2, §8.6, §11.3), on every validated instance so
        none holds dev mode or SSWS in production. `model_copy(update=…)` and `model_construct`
        skip validation: don't use them on a `Config`. One "NAME: problem" per line."""
        errors: list[str] = []
        if self.env == "production":
            if self.public_url and self.public_url.startswith("http:"):
                errors.append("MCP_PUBLIC_URL: http refused when MCP_ENV=production")
            if any(o.startswith("http:") for o in self.allowed_origins):
                errors.append("MCP_ALLOWED_ORIGINS: http refused when MCP_ENV=production")
        if self.dev_mode:
            if self.env == "production":
                errors.append("MCP_DEV_MODE: refused when MCP_ENV=production")
            if self.dev_principal_file is None:
                errors.append("MCP_DEV_PRINCIPAL_FILE: required when MCP_DEV_MODE is on")
        else:
            # Dev mode has no HTTP auth, so these are needed only outside it.
            for name, value in [
                ("MCP_PUBLIC_URL", self.public_url),
                ("MCP_ISSUER", self.issuer),
                ("MCP_ALLOWED_CLIENT_IDS", self.allowed_client_ids),
            ]:
                if not value:
                    errors.append(f"{name}: required")

        if self.okta_api_token is not None:
            if self.env == "production":
                errors.append("OKTA_API_TOKEN: refused when MCP_ENV=production")
            if not self.dev_mode:
                errors.append("OKTA_API_TOKEN: accepted only in dev mode (MCP_DEV_MODE)")
            if self.okta_client_id or self.okta_private_key_file:
                errors.append(
                    "OKTA_API_TOKEN: set it or OKTA_CLIENT_ID/OKTA_PRIVATE_KEY_FILE, not both"
                )
        else:
            if not self.okta_client_id:
                errors.append("OKTA_CLIENT_ID: required")
            if self.okta_private_key_file is None:
                errors.append("OKTA_PRIVATE_KEY_FILE: required")

        for name, path in [
            ("MCP_POLICY_FILE", self.policy_file),
            ("MCP_DEV_PRINCIPAL_FILE", self.dev_principal_file if self.dev_mode else None),
            ("OKTA_PRIVATE_KEY_FILE", self.okta_private_key_file),
        ]:
            if path is not None and not _readable(path):
                errors.append(f"{name}: cannot read {path}")
        if self.default_limit > self.max_items:
            errors.append("MCP_DEFAULT_LIMIT: must not exceed MCP_MAX_ITEMS")
        if errors:
            raise ValueError("\n".join(errors))
        return self


_NAMES = tuple(f.alias for f in Config.model_fields.values() if f.alias)


def _messages(e: ErrorDetails) -> list[str]:
    msg = "required" if e["type"] == "missing" else e["msg"].removeprefix("Value error, ")
    if not e["loc"]:  # `_cross_variable`: already one "NAME: problem" per line
        return msg.split("\n")
    return [f"{e['loc'][0]}: {msg}"]


def _secrets_from_files(env: Mapping[str, str], raw: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for name in _SECRETS:
        if not (path := env.get(f"{name}_FILE", "").strip()):
            continue
        if name in raw:
            errors.append(f"{name}: set {name} or {name}_FILE, not both")
            continue
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            errors.append(f"{name}_FILE: cannot read {path}")
            continue
        if not value:
            errors.append(f"{name}_FILE: {path} is empty")
            continue
        raw[name] = value
    return errors


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    """Build the config from `environ` (default `os.environ`); raise `ConfigError` listing
    every problem."""
    env = os.environ if environ is None else environ
    raw = {name: v for name in _NAMES if (v := env.get(name, "").strip())}
    # Reported alone: validating without the secret would add misleading "required" errors.
    if errors := _secrets_from_files(env, raw):
        raise ConfigError(errors)
    try:
        config = Config.model_validate(raw)
    except ValidationError as e:
        errors = [m for d in e.errors(include_url=False, include_input=False) for m in _messages(d)]
    else:
        if config.allowed_client_ids == ("*",):
            log.warning("MCP_ALLOWED_CLIENT_IDS is '*': tokens from any client of the issuer pass")
        return config
    # Raised outside `except`, so the ValidationError, whose text includes input values (i.e.
    # secrets), isn't attached as `__context__`.
    raise ConfigError(errors)
