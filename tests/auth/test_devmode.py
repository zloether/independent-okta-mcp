"""stdio dev mode's principal file (plan 4.1, design §8.6)."""

from pathlib import Path
from typing import Any

import pytest

from okta_mcp.auth.devmode import dev_principal, load_dev_principal
from okta_mcp.auth.principal import Principal
from okta_mcp.config import Config, ConfigError, load_config

UID = "00u1devuser000000000"
READERS = "00g1readers000000000"
HELPDESK = "00g1helpdsk000000000"
GOOD = f"uid: {UID}\nsub: dev@example.com\ngroups: [{READERS}, {HELPDESK}]\n"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "principal.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def errors_of(tmp_path: Path, text: str) -> list[str]:
    with pytest.raises(ConfigError) as e:
        load_dev_principal(write(tmp_path, text))
    assert all(m.startswith("MCP_DEV_PRINCIPAL_FILE: principal.yaml: ") for m in e.value.errors)
    return [m.removeprefix("MCP_DEV_PRINCIPAL_FILE: principal.yaml: ") for m in e.value.errors]


def test_loads_the_principal(tmp_path: Path) -> None:
    p = load_dev_principal(write(tmp_path, GOOD))
    assert p == Principal(uid=UID, sub="dev@example.com", groups=frozenset({READERS, HELPDESK}))
    assert p.client_id is None
    assert p.exp is None


def test_no_groups_is_a_caller_with_no_role(tmp_path: Path) -> None:
    p = load_dev_principal(write(tmp_path, f"uid: {UID}\nsub: dev@example.com\ngroups: []\n"))
    assert p.groups == frozenset()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", "must be a mapping with keys uid, sub, groups"),
        ("- a\n- b\n", "must be a mapping with keys uid, sub, groups"),
        ("just a string\n", "must be a mapping with keys uid, sub, groups"),
    ],
)
def test_not_a_mapping(tmp_path: Path, text: str, expected: str) -> None:
    assert errors_of(tmp_path, text) == [expected]


def test_every_problem_reported_at_once(tmp_path: Path) -> None:
    errors = errors_of(tmp_path, "uid: 00g1notauser0000000\nrole: admin\n")
    assert errors == [
        "unknown key 'role'; valid: uid, sub, groups",
        "sub is required",
        "groups is required",
        "uid must be an Okta user ID (00u + 17 letters or digits)",
    ]


def test_unknown_keys_are_bounded(tmp_path: Path) -> None:
    keys = "".join(f"k{i}: 1\n" for i in range(9)) + "x" * 200 + ": 1\n"
    (error,) = [e for e in errors_of(tmp_path, GOOD + keys) if e.startswith("unknown")]
    assert error.count("'k") == 5
    assert "xxx" not in error


@pytest.mark.parametrize(
    "uid",
    [
        "00u1devuser00000000",  # 16 after the prefix
        "00u1devuser0000000000",  # 18
        "00g1devuser000000000",
        "00u1devuser00000000-",
        "'00u1devuser000000000\\n'",
        '"00u1devuser000000000\\n"',
        "12345",
        "null",
        "[00u1devuser000000000]",
        "me",
    ],
)
def test_uid_must_be_a_user_id(tmp_path: Path, uid: str) -> None:
    text = f"uid: {uid}\nsub: dev@example.com\ngroups: []\n"
    assert errors_of(tmp_path, text) == ["uid must be an Okta user ID (00u + 17 letters or digits)"]


@pytest.mark.parametrize(
    "sub",
    [
        '""',
        '" dev@example.com"',
        '"dev@example.com "',
        '"dev\\n@example.com"',
        "42",
        "null",
        '"' + "a" * 257 + '"',
    ],
)
def test_sub_must_be_a_printable_login(tmp_path: Path, sub: str) -> None:
    text = f"uid: {UID}\nsub: {sub}\ngroups: []\n"
    (error,) = errors_of(tmp_path, text)
    assert error.startswith("sub must be a login of 1 to 256 printable characters")


def test_groups_must_be_a_list(tmp_path: Path) -> None:
    # One group as a bare string would be a set of characters to the engine.
    for groups in (READERS, "null", "{a: b}"):
        text = f"uid: {UID}\nsub: dev@example.com\ngroups: {groups}\n"
        assert errors_of(tmp_path, text) == [
            "groups must be a list of Okta group IDs (it may be empty)"
        ]


def test_each_group_must_be_a_group_id(tmp_path: Path) -> None:
    text = (
        f"uid: {UID}\nsub: dev@example.com\n"
        f"groups: [{READERS}, mcp-okta-admins, 00u1devuser000000000, 7, {READERS}]\n"
    )
    assert errors_of(tmp_path, text) == [
        "group 'mcp-okta-admins' is not an Okta group ID (00g + 17 letters or digits)",
        "group '00u1devuser000000000' is not an Okta group ID (00g + 17 letters or digits)",
        "group 7 is not an Okta group ID (00g + 17 letters or digits)",
        f"group {READERS} is listed twice",
    ]


def test_long_bad_group_is_cut(tmp_path: Path) -> None:
    text = f"uid: {UID}\nsub: dev@example.com\ngroups: [{'g' * 500}]\n"
    (error,) = errors_of(tmp_path, text)
    assert len(error) < 120


def test_too_many_groups(tmp_path: Path) -> None:
    groups = ", ".join(f"00g{i:017d}" for i in range(1001))
    text = f"uid: {UID}\nsub: dev@example.com\ngroups: [{groups}]\n"
    assert errors_of(tmp_path, text) == ["groups has more than 1000 entries"]


def test_duplicate_key_is_an_error(tmp_path: Path) -> None:
    # PyYAML would keep the second `groups`.
    (error,) = errors_of(tmp_path, GOOD + f"groups: [{HELPDESK}]\n")
    assert error.startswith("not valid YAML:")
    assert "duplicate key 'groups'" in error


def test_yaml_tags_refused(tmp_path: Path) -> None:
    (error,) = errors_of(tmp_path, "!!python/object/apply:os.system [echo hi]\n")
    assert error.startswith("not valid YAML:")


def test_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as e:
        load_dev_principal(tmp_path / "missing.yaml")
    assert e.value.errors == [
        "MCP_DEV_PRINCIPAL_FILE: missing.yaml: cannot be read (FileNotFoundError)"
    ]


# --- dev_principal: only in dev mode, never in production ----------------------------------


def env(tmp_path: Path, **extra: str) -> dict[str, str]:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nroles: {}\n", encoding="utf-8")
    return {
        "MCP_POLICY_FILE": str(policy),
        "MCP_CURSOR_KEY": "A" * 44,
        "OKTA_ORG_URL": "https://example.okta.com",
        "OKTA_SCOPES": "okta.groups.read",
        "OKTA_API_TOKEN": "test-token",
        **extra,
    }


def test_dev_principal_in_dev_mode(tmp_path: Path) -> None:
    path = write(tmp_path, GOOD)
    config = load_config(env(tmp_path, MCP_DEV_MODE="1", MCP_DEV_PRINCIPAL_FILE=str(path)))
    assert dev_principal(config).uid == UID


def test_dev_principal_refused_outside_dev_mode(tmp_path: Path) -> None:
    path = write(tmp_path, GOOD)
    values: dict[str, Any] = {
        "MCP_POLICY_FILE": tmp_path / "policy.yaml",
        "MCP_CURSOR_KEY": b"A" * 32,
        "OKTA_ORG_URL": "https://example.okta.com",
        "OKTA_SCOPES": frozenset({"okta.groups.read"}),
    }
    # `model_construct` skips the validator that refuses these; `dev_principal` checks again.
    for unsafe in (
        {"MCP_DEV_MODE": False, "MCP_DEV_PRINCIPAL_FILE": path},
        {"MCP_DEV_MODE": True, "MCP_DEV_PRINCIPAL_FILE": path, "MCP_ENV": "production"},
        {"MCP_DEV_MODE": True},
    ):
        fields = {
            name: value
            for name, field in Config.model_fields.items()
            for alias, value in {**values, **unsafe}.items()
            if field.alias == alias
        }
        config = Config.model_construct(**fields)
        assert config.dev_mode is unsafe["MCP_DEV_MODE"]
        with pytest.raises(ConfigError) as e:
            dev_principal(config)
        assert e.value.errors[0].startswith("MCP_DEV_MODE: the dev principal needs")


def test_production_config_cannot_hold_dev_mode(tmp_path: Path) -> None:
    path = write(tmp_path, GOOD)
    with pytest.raises(ConfigError) as e:
        load_config(
            env(
                tmp_path,
                MCP_DEV_MODE="1",
                MCP_DEV_PRINCIPAL_FILE=str(path),
                MCP_ENV="production",
            )
        )
    assert "MCP_DEV_MODE: refused when MCP_ENV=production" in e.value.errors
