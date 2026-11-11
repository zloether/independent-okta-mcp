"""stdio development mode (design §8.6): the caller is a fixed principal read from a file.

Only `okta-mcp --stdio` uses this, and only with `MCP_DEV_MODE` on, `MCP_ENV` not `production`
and `MCP_DEV_PRINCIPAL_FILE` set; `Config` refuses the other combinations, and `dev_principal`
checks them again so no caller can reach the file with a `Config` that skipped validation. The
principal goes through the same policy engine as a token's: the file says who the caller is,
never what they may do.

The file is YAML with exactly `uid`, `sub` and `groups`:

    uid: 00u1abcdEFGH2ijkl345     # Okta user ID
    sub: dev@example.com          # login, shown in okta_status
    groups: [00g1readers000000000]  # Okta group IDs the policy maps to roles

Every problem is reported at once, naming the file; nothing here is a secret.
"""

from pathlib import Path
from typing import Any, cast

import yaml

from okta_mcp.auth.principal import Principal
from okta_mcp.config import Config, ConfigError
from okta_mcp.exec.resolve import USER_ID
from okta_mcp.policy.model import GROUP_ID
from okta_mcp.registry.loader import UniqueKeyLoader

_KEYS = ("uid", "sub", "groups")
_SUB_MAX = 256
_GROUPS_MAX = 1000
_SHOWN = 40


def _shown(value: object) -> str:
    text = repr(value)
    return text if len(text) <= _SHOWN else text[: _SHOWN - 3] + "..."


def dev_principal(config: Config) -> Principal:
    """The dev-mode principal for `config`. Raises `ConfigError` outside dev mode, in
    production, or for a missing, unreadable or invalid principal file."""
    if not config.dev_mode or config.env == "production" or config.dev_principal_file is None:
        raise ConfigError(
            [
                "MCP_DEV_MODE: the dev principal needs MCP_DEV_MODE on, MCP_ENV not production "
                "and MCP_DEV_PRINCIPAL_FILE set"
            ]
        )
    return load_dev_principal(config.dev_principal_file)


def load_dev_principal(path: Path) -> Principal:
    """The principal in `path`. Raises `ConfigError` naming the file."""
    where = f"MCP_DEV_PRINCIPAL_FILE: {path.name}"
    try:
        doc = yaml.load(path.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
    except OSError as e:
        raise ConfigError([f"{where}: cannot be read ({type(e).__name__})"]) from None
    except yaml.YAMLError as e:
        raise ConfigError([f"{where}: not valid YAML: {e}"]) from None
    if not isinstance(doc, dict):
        raise ConfigError([f"{where}: must be a mapping with keys {', '.join(_KEYS)}"])
    given = cast(dict[object, object], doc)
    errors: list[str] = []
    unknown = [k for k in given if k not in _KEYS]
    if unknown:
        errors.append(
            f"{where}: unknown key {', '.join(_shown(k) for k in unknown[:5])}; "
            f"valid: {', '.join(_KEYS)}"
        )
    errors += [f"{where}: {k} is required" for k in _KEYS if k not in given]

    uid = given.get("uid")
    if "uid" in given and not (isinstance(uid, str) and USER_ID.fullmatch(uid)):
        errors.append(f"{where}: uid must be an Okta user ID (00u + 17 letters or digits)")
    sub = given.get("sub")
    if "sub" in given and not (
        isinstance(sub, str)
        and sub.strip() == sub
        and 0 < len(sub) <= _SUB_MAX
        and sub.isprintable()
    ):
        errors.append(
            f"{where}: sub must be a login of 1 to {_SUB_MAX} printable characters with no "
            "leading or trailing space"
        )
    groups = given.get("groups")
    if "groups" in given:
        errors += _group_errors(where, groups)

    if errors:
        raise ConfigError(errors)
    return Principal(
        uid=cast(str, uid),
        sub=cast(str, sub),
        groups=frozenset(cast(list[str], groups)),
    )


def _group_errors(where: str, groups: object) -> list[str]:
    if not isinstance(groups, list):
        return [f"{where}: groups must be a list of Okta group IDs (it may be empty)"]
    items = cast(list[Any], groups)
    if len(items) > _GROUPS_MAX:
        return [f"{where}: groups has more than {_GROUPS_MAX} entries"]
    errors: list[str] = []
    seen: set[str] = set()
    for g in items:
        if not (isinstance(g, str) and GROUP_ID.fullmatch(g)):
            errors.append(
                f"{where}: group {_shown(g)} is not an Okta group ID (00g + 17 letters or digits)"
            )
        elif g in seen:
            errors.append(f"{where}: group {g} is listed twice")
        else:
            seen.add(g)
    return errors
