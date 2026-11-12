import base64
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from okta_mcp.config import _NAMES, _SECRETS, Config, ConfigError, load_config

KEY = base64.b64encode(b"k" * 32).decode()
SSWS = "00ssws-secret-token"


@pytest.fixture
def files(tmp_path: Path) -> Path:
    for name in ("policy.yaml", "okta.pem", "principal.yaml"):
        (tmp_path / name).write_text("x\n")
    return tmp_path


@pytest.fixture
def env(files: Path) -> dict[str, str]:
    return {
        "MCP_PUBLIC_URL": "https://mcp.example.com/mcp",
        "MCP_ISSUER": "https://example.okta.com/oauth2/aus1abc",
        "MCP_ALLOWED_CLIENT_IDS": "0oa1client",
        "MCP_POLICY_FILE": str(files / "policy.yaml"),
        "MCP_CURSOR_KEY": KEY,
        "OKTA_ORG_URL": "https://example.okta.com",
        "OKTA_CLIENT_ID": "0oa1service",
        "OKTA_PRIVATE_KEY_FILE": str(files / "okta.pem"),
        "OKTA_SCOPES": "okta.users.read okta.groups.read",
    }


@pytest.fixture
def dev_env(env: dict[str, str], files: Path) -> dict[str, str]:
    for name in ("MCP_PUBLIC_URL", "MCP_ISSUER", "MCP_ALLOWED_CLIENT_IDS"):
        del env[name]
    env["MCP_DEV_MODE"] = "1"
    env["MCP_DEV_PRINCIPAL_FILE"] = str(files / "principal.yaml")
    return env


def _errors(env: dict[str, str]) -> list[str]:
    with pytest.raises(ConfigError) as e:
        load_config(env)
    return e.value.errors


def test_defaults(env: dict[str, str]) -> None:
    c = load_config(env)
    assert c.env == "development"
    assert c.audience == "https://mcp.example.com/mcp"
    assert c.required_scope == "okta-mcp"
    assert c.groups_claim == "groups"
    assert c.cursor_key.get_secret_value() == b"k" * 32
    assert c.allowed_origins == ()
    assert (c.host, c.port, c.trust_proxy) == ("127.0.0.1", 8080, False)
    assert (c.default_limit, c.max_items, c.max_bytes, c.max_batch) == (50, 1000, 65536, 50)
    assert (c.call_timeout, c.okta_max_inflight, c.requests_per_minute) == (60, 10, 600)
    assert (c.audit_log, c.audit_args, c.log_level) == ("stdout", "full", "INFO")
    assert c.okta_scopes == {"okta.users.read", "okta.groups.read"}
    assert c.okta_dpop is True
    assert c.okta_rate_limit_max_wait == 10
    assert c.okta_api_token is None
    assert not c.dev_mode


def test_reads_os_environ(env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    # The developer's shell may export any of these (e.g. OKTA_API_TOKEN).
    for name in (*_NAMES, *(f"{s}_FILE" for s in _SECRETS)):
        monkeypatch.delenv(name, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert load_config().okta_client_id == "0oa1service"


def test_overrides(env: dict[str, str]) -> None:
    env |= {
        "MCP_AUDIENCE": "api://okta-mcp",
        "MCP_ALLOWED_CLIENT_IDS": " 0oa1a , 0oa1b,, ",
        "MCP_ALLOWED_ORIGINS": "https://a.example.com,https://b.example.com",
        "MCP_PORT": "9000",
        "MCP_TRUST_PROXY": "true",
        "MCP_ENV": "production",
        "MCP_AUDIT_ARGS": "hash",
        "OKTA_DPOP": "false",
        "OKTA_ORG_URL": "https://example.okta.com/",
    }
    c = load_config(env)
    assert c.audience == "api://okta-mcp"
    assert c.allowed_client_ids == ("0oa1a", "0oa1b")
    assert c.allowed_origins == ("https://a.example.com", "https://b.example.com")
    assert (c.port, c.trust_proxy, c.env, c.audit_args) == (9000, True, "production", "hash")
    assert c.okta_dpop is False
    assert c.okta_org_url == "https://example.okta.com"


@pytest.mark.parametrize(
    "name",
    [
        "MCP_PUBLIC_URL",
        "MCP_ISSUER",
        "MCP_ALLOWED_CLIENT_IDS",
        "MCP_POLICY_FILE",
        "MCP_CURSOR_KEY",
        "OKTA_ORG_URL",
        "OKTA_CLIENT_ID",
        "OKTA_PRIVATE_KEY_FILE",
        "OKTA_SCOPES",
    ],
)
def test_missing_required(env: dict[str, str], name: str) -> None:
    del env[name]
    assert _errors(env) == [f"{name}: required"]


@pytest.mark.parametrize("value", ["", " , ", "  "])
def test_empty_counts_as_unset(env: dict[str, str], value: str) -> None:
    env["MCP_ALLOWED_CLIENT_IDS"] = value
    assert _errors(env) == ["MCP_ALLOWED_CLIENT_IDS: required"]


@pytest.mark.parametrize("name", ["OKTA_CLIENT_ID", "MCP_ISSUER", "OKTA_SCOPES"])
def test_whitespace_counts_as_unset(env: dict[str, str], name: str) -> None:
    env[name] = " \t "
    assert _errors(env) == [f"{name}: required"]


def test_values_are_stripped(env: dict[str, str]) -> None:
    env["MCP_REQUIRED_SCOPE"] = "okta-mcp \n"
    env["OKTA_CLIENT_ID"] = " 0oa1service"
    env["MCP_ISSUER"] += "\n"
    c = load_config(env)
    assert (c.required_scope, c.okta_client_id) == ("okta-mcp", "0oa1service")
    assert c.issuer == "https://example.okta.com/oauth2/aus1abc"


def test_all_errors_reported_together(env: dict[str, str]) -> None:
    env["MCP_ISSUER"] = "http://example.okta.com/oauth2/aus1abc"
    del env["OKTA_SCOPES"]
    env["MCP_PORT"] = "0"
    errors = _errors(env)
    assert len(errors) == 3
    assert {e.split(":")[0] for e in errors} == {"MCP_ISSUER", "OKTA_SCOPES", "MCP_PORT"}


def test_cross_variable_errors_reported_together(env: dict[str, str]) -> None:
    del env["MCP_ISSUER"]
    del env["OKTA_CLIENT_ID"]
    env["MCP_DEFAULT_LIMIT"] = "2000"
    assert _errors(env) == [
        "MCP_ISSUER: required",
        "OKTA_CLIENT_ID: required",
        "MCP_DEFAULT_LIMIT: must not exceed MCP_MAX_ITEMS",
    ]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MCP_ISSUER", "http://example.okta.com/oauth2/aus1abc"),
        ("MCP_ISSUER", "example.okta.com/oauth2/aus1abc"),
        ("MCP_ISSUER", "https://example.okta.com/oauth2/aus1abc?x=1"),
        ("MCP_ISSUER", "https://example.okta.com/oauth2/aus1abc?"),
        ("MCP_ISSUER", "https://example.okta.com/oauth2/aus1abc#f"),
        ("MCP_ISSUER", "https://example.okta.com/oauth2/aus1 abc"),
        ("MCP_ISSUER", "https://example.okta.com/oauth2/\taus1abc"),
        ("MCP_ISSUER", "https://example.okta.com:99999/oauth2/aus1abc"),
        ("MCP_PUBLIC_URL", "http://mcp.example.com/mcp"),
        ("MCP_PUBLIC_URL", "https://user:pw@mcp.example.com/mcp"),
        ("MCP_PUBLIC_URL", "https:///mcp"),
        ("MCP_PUBLIC_URL", "https://mcp.example.com"),
        ("MCP_PUBLIC_URL", "https://mcp.example.com/"),
        ("MCP_PUBLIC_URL", "https://mcp.example.com/okta/mcp"),
        ("MCP_PUBLIC_URL", "https://mcp.example.com/mcp/"),
        ("MCP_PUBLIC_URL", "https://MCP.example.com/mcp"),
        ("MCP_PUBLIC_URL", "https://mcp.example.com:443/mcp"),
        ("MCP_PUBLIC_URL", "http://127.0.0.1:80/mcp"),
        ("MCP_PUBLIC_URL", "HTTPS://mcp.example.com/mcp"),
        ("OKTA_ORG_URL", "https://example.okta.com/api/v1"),
        ("OKTA_ORG_URL", "http://example.okta.com"),
        ("OKTA_ORG_URL", "https://evil.example.com@example.okta.com"),
        ("OKTA_ORG_URL", "https://example.okta.com:/"),
        ("MCP_ALLOWED_ORIGINS", "https://app.example.com/path"),
        ("MCP_ALLOWED_ORIGINS", "*"),
        ("MCP_ALLOWED_ORIGINS", "https://app.example.com,http://app.example.com"),
        ("MCP_ALLOWED_ORIGINS", "http://[::1]:3000"),
        ("OKTA_ORG_URL", "https://example.okta.com."),
        ("OKTA_ORG_URL", "https://exämple.okta.com"),
        ("OKTA_ORG_URL", "https://example.okta.com:0"),
        ("MCP_ISSUER", "https://example.okta.com./oauth2/aus1abc"),
        ("MCP_REQUIRED_SCOPE", "okta-mcp openid"),
        ("MCP_GROUPS_CLAIM", "groups\tx"),
    ],
)
def test_bad_urls(env: dict[str, str], name: str, value: str) -> None:
    env[name] = value
    errors = _errors(env)
    assert len(errors) == 1
    assert errors[0].startswith(f"{name}: ")


@pytest.mark.parametrize(
    ("value", "origin"),
    [
        ("https://Example.OKTA.com", "https://example.okta.com"),
        ("https://example.okta.com:443/", "https://example.okta.com"),
        ("HTTPS://example.okta.com", "https://example.okta.com"),
        ("https://example.okta.com:8443", "https://example.okta.com:8443"),
        ("https://[2001:DB8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_org_url_is_canonical(env: dict[str, str], value: str, origin: str) -> None:
    env["OKTA_ORG_URL"] = value
    assert load_config(env).okta_org_url == origin


def test_allowed_origins_are_canonical(env: dict[str, str]) -> None:
    env["MCP_ALLOWED_ORIGINS"] = (
        "https://App.example.com/, http://localhost:80, http://127.0.0.1:3000"
    )
    assert load_config(env).allowed_origins == (
        "https://app.example.com",
        "http://localhost",
        "http://127.0.0.1:3000",
    )


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000"])
def test_http_public_url_on_loopback(env: dict[str, str], host: str) -> None:
    env["MCP_PUBLIC_URL"] = f"http://{host}/mcp"
    assert load_config(env).public_url == f"http://{host}/mcp"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MCP_PUBLIC_URL", "http://127.0.0.1:8000/mcp"),
        ("MCP_ALLOWED_ORIGINS", "https://app.example.com,http://localhost:3000"),
    ],
)
def test_http_refused_in_production(env: dict[str, str], name: str, value: str) -> None:
    env |= {name: value, "MCP_ENV": "production"}
    assert _errors(env) == [f"{name}: http refused when MCP_ENV=production"]


def test_dev_principal_file_ignored_outside_dev_mode(env: dict[str, str], tmp_path: Path) -> None:
    env["MCP_DEV_PRINCIPAL_FILE"] = str(tmp_path / "missing")
    load_config(env)


def test_wildcard_client_ids_warns(env: dict[str, str], caplog: pytest.LogCaptureFixture) -> None:
    env["MCP_ALLOWED_CLIENT_IDS"] = "*"
    with caplog.at_level(logging.WARNING, logger="okta_mcp.config"):
        assert load_config(env).allowed_client_ids == ("*",)
    assert "MCP_ALLOWED_CLIENT_IDS is '*'" in caplog.text


def test_no_warning_for_listed_client_ids(
    env: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="okta_mcp.config"):
        load_config(env)
    assert caplog.records == []


def test_wildcard_client_ids_must_be_alone(env: dict[str, str]) -> None:
    env["MCP_ALLOWED_CLIENT_IDS"] = "0oa1client,*"
    assert _errors(env) == ["MCP_ALLOWED_CLIENT_IDS: '*' must be the only entry"]


def test_wildcard_rule_reported_with_other_variables(env: dict[str, str]) -> None:
    env["MCP_ALLOWED_CLIENT_IDS"] = "0oa1client,*"
    env["MCP_PORT"] = "x"
    assert {e.split(":")[0] for e in _errors(env)} == {"MCP_ALLOWED_CLIENT_IDS", "MCP_PORT"}


def test_unknown_env(env: dict[str, str]) -> None:
    env["MCP_ENV"] = "prod"
    assert _errors(env)[0].startswith("MCP_ENV: ")


# Dev mode and SSWS (design §8.6)


def test_dev_mode_needs_no_http_auth(dev_env: dict[str, str]) -> None:
    c = load_config(dev_env)
    assert c.dev_mode
    assert c.public_url is None and c.issuer is None and c.allowed_client_ids == ()


def test_dev_mode_refused_in_production(dev_env: dict[str, str]) -> None:
    dev_env["MCP_ENV"] = "production"
    assert _errors(dev_env) == ["MCP_DEV_MODE: refused when MCP_ENV=production"]


def test_dev_mode_needs_principal_file(dev_env: dict[str, str]) -> None:
    del dev_env["MCP_DEV_PRINCIPAL_FILE"]
    assert _errors(dev_env) == ["MCP_DEV_PRINCIPAL_FILE: required when MCP_DEV_MODE is on"]


@pytest.mark.parametrize("value", ["0", "false"])
def test_dev_mode_off(dev_env: dict[str, str], value: str) -> None:
    dev_env["MCP_DEV_MODE"] = value
    errors = _errors(dev_env)
    assert {e.split(":")[0] for e in errors} == {
        "MCP_PUBLIC_URL",
        "MCP_ISSUER",
        "MCP_ALLOWED_CLIENT_IDS",
    }


def test_bad_bool(dev_env: dict[str, str]) -> None:
    dev_env["MCP_DEV_MODE"] = "maybe"
    assert _errors(dev_env)[0].startswith("MCP_DEV_MODE: ")


@pytest.fixture
def ssws_env(dev_env: dict[str, str]) -> dict[str, str]:
    del dev_env["OKTA_CLIENT_ID"]
    del dev_env["OKTA_PRIVATE_KEY_FILE"]
    dev_env["OKTA_API_TOKEN"] = SSWS
    return dev_env


def test_ssws_in_dev_mode(ssws_env: dict[str, str]) -> None:
    c = load_config(ssws_env)
    assert c.okta_api_token is not None
    assert c.okta_api_token.get_secret_value() == SSWS


def test_ssws_refused_in_production(ssws_env: dict[str, str]) -> None:
    ssws_env["MCP_ENV"] = "production"
    assert "OKTA_API_TOKEN: refused when MCP_ENV=production" in _errors(ssws_env)


def test_ssws_refused_outside_dev_mode(env: dict[str, str]) -> None:
    del env["OKTA_CLIENT_ID"]
    del env["OKTA_PRIVATE_KEY_FILE"]
    env["OKTA_API_TOKEN"] = SSWS
    assert _errors(env) == ["OKTA_API_TOKEN: accepted only in dev mode (MCP_DEV_MODE)"]


def test_ssws_and_service_app_both_set(dev_env: dict[str, str]) -> None:
    dev_env["OKTA_API_TOKEN"] = SSWS
    assert _errors(dev_env) == [
        "OKTA_API_TOKEN: set it or OKTA_CLIENT_ID/OKTA_PRIVATE_KEY_FILE, not both"
    ]


def test_cross_variable_rules_hold_on_direct_construction(dev_env: dict[str, str]) -> None:
    Config.model_validate(dev_env)
    with pytest.raises(ValidationError, match="MCP_DEV_MODE: refused when MCP_ENV=production"):
        Config.model_validate(dev_env | {"MCP_ENV": "production"})


# Secrets and files


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (base64.b64encode(b"k" * 31).decode(), "must decode to at least 32 bytes"),
        ("not base64!", "must be base64"),
    ],
)
def test_bad_cursor_key(env: dict[str, str], value: str, message: str) -> None:
    env["MCP_CURSOR_KEY"] = value
    assert _errors(env) == [f"MCP_CURSOR_KEY: {message}"]


@pytest.mark.parametrize(
    "value",
    [
        base64.urlsafe_b64encode(b"\xfb\xff" * 16).decode().rstrip("="),
        base64.encodebytes(b"\xfb\xff" * 32).decode(),  # wrapped at 76 characters
    ],
)
def test_cursor_key_encodings(env: dict[str, str], value: str) -> None:
    env["MCP_CURSOR_KEY"] = value
    assert load_config(env).cursor_key.get_secret_value().startswith(b"\xfb\xff" * 16)


def test_cursor_key_from_file(env: dict[str, str], tmp_path: Path) -> None:
    (tmp_path / "cursor.key").write_text(KEY + "\n")
    del env["MCP_CURSOR_KEY"]
    env["MCP_CURSOR_KEY_FILE"] = str(tmp_path / "cursor.key")
    assert load_config(env).cursor_key.get_secret_value() == b"k" * 32


def test_api_token_from_file(ssws_env: dict[str, str], tmp_path: Path) -> None:
    (tmp_path / "ssws").write_text("00ssws-from-file\n")
    del ssws_env["OKTA_API_TOKEN"]
    ssws_env["OKTA_API_TOKEN_FILE"] = str(tmp_path / "ssws")
    token = load_config(ssws_env).okta_api_token
    assert token is not None and token.get_secret_value() == "00ssws-from-file"


def test_secret_and_file_both_set(env: dict[str, str], tmp_path: Path) -> None:
    (tmp_path / "cursor.key").write_text(KEY)
    env["MCP_CURSOR_KEY_FILE"] = str(tmp_path / "cursor.key")
    assert _errors(env) == ["MCP_CURSOR_KEY: set MCP_CURSOR_KEY or MCP_CURSOR_KEY_FILE, not both"]


def test_unreadable_secret_file(env: dict[str, str], tmp_path: Path) -> None:
    del env["MCP_CURSOR_KEY"]
    env["MCP_CURSOR_KEY_FILE"] = str(tmp_path / "missing")
    assert _errors(env) == [f"MCP_CURSOR_KEY_FILE: cannot read {tmp_path / 'missing'}"]


def test_unreadable_api_token_file_alone(ssws_env: dict[str, str], tmp_path: Path) -> None:
    del ssws_env["OKTA_API_TOKEN"]
    ssws_env["OKTA_API_TOKEN_FILE"] = str(tmp_path / "missing")
    assert _errors(ssws_env) == [f"OKTA_API_TOKEN_FILE: cannot read {tmp_path / 'missing'}"]


@pytest.mark.parametrize("content", ["", " \n"])
def test_empty_secret_file(ssws_env: dict[str, str], tmp_path: Path, content: str) -> None:
    (tmp_path / "ssws").write_text(content)
    del ssws_env["OKTA_API_TOKEN"]
    ssws_env["OKTA_API_TOKEN_FILE"] = str(tmp_path / "ssws")
    assert _errors(ssws_env) == [f"OKTA_API_TOKEN_FILE: {tmp_path / 'ssws'} is empty"]


@pytest.mark.parametrize("name", ["MCP_POLICY_FILE", "OKTA_PRIVATE_KEY_FILE"])
def test_unreadable_file(env: dict[str, str], tmp_path: Path, name: str) -> None:
    env[name] = str(tmp_path / "missing")
    assert _errors(env) == [f"{name}: cannot read {tmp_path / 'missing'}"]


def test_directory_is_not_a_readable_file(env: dict[str, str], tmp_path: Path) -> None:
    env["MCP_POLICY_FILE"] = str(tmp_path)
    assert _errors(env) == [f"MCP_POLICY_FILE: cannot read {tmp_path}"]


def test_secrets_never_shown(ssws_env: dict[str, str]) -> None:
    c = load_config(ssws_env)
    assert KEY not in repr(c) and SSWS not in repr(c)
    assert "kkkk" not in repr(c)

    short = base64.b64encode(b"s" * 31).decode()
    ssws_env["MCP_CURSOR_KEY"] = short
    ssws_env["MCP_PORT"] = "x"
    with pytest.raises(ConfigError) as e:
        load_config(ssws_env)
    assert short not in str(e.value)
    # The pydantic error (which shows input values) must not be attached at all.
    assert e.value.__cause__ is None and e.value.__context__ is None


# Scopes and numbers


def test_write_scope_rejected(env: dict[str, str]) -> None:
    env["OKTA_SCOPES"] = "okta.users.read okta.users.manage okta.groups.manage"
    assert _errors(env) == [
        "OKTA_SCOPES: only read scopes are allowed, got okta.groups.manage, okta.users.manage"
    ]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MCP_PORT", "0"),
        ("MCP_PORT", "65536"),
        ("MCP_PORT", "http"),
        ("MCP_MAX_ITEMS", "0"),
        ("MCP_MAX_BYTES", "-1"),
        ("MCP_MAX_BYTES", "1023"),
        ("MCP_CALL_TIMEOUT", "inf"),
        ("MCP_CALL_TIMEOUT", "nan"),
        ("MCP_CALL_TIMEOUT", "0"),
        ("MCP_CALL_TIMEOUT", "1"),  # under the executor's 2 s minimum (2.10 review)
        ("MCP_CALL_TIMEOUT", "1.99"),
        ("MCP_OKTA_MAX_INFLIGHT", "1.5"),
        ("OKTA_RATE_LIMIT_MAX_WAIT", "-1"),
        ("MCP_LOG_LEVEL", "verbose"),
        ("MCP_AUDIT_ARGS", "none"),
    ],
)
def test_bad_values(env: dict[str, str], name: str, value: str) -> None:
    env[name] = value
    errors = _errors(env)
    assert len(errors) == 1 and errors[0].startswith(f"{name}: ")


def test_log_level_case_insensitive(env: dict[str, str]) -> None:
    env["MCP_LOG_LEVEL"] = "debug"
    assert load_config(env).log_level == "DEBUG"


def test_default_limit_within_max_items(env: dict[str, str]) -> None:
    env["MCP_DEFAULT_LIMIT"] = "2000"
    assert _errors(env) == ["MCP_DEFAULT_LIMIT: must not exceed MCP_MAX_ITEMS"]


def test_zero_rate_limit_wait_allowed(env: dict[str, str]) -> None:
    env["OKTA_RATE_LIMIT_MAX_WAIT"] = "0"
    assert load_config(env).okta_rate_limit_max_wait == 0


def test_call_timeout_minimum_is_two_seconds(env: dict[str, str]) -> None:
    env["MCP_CALL_TIMEOUT"] = "2"
    assert load_config(env).call_timeout == 2
