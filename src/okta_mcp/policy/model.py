"""Policy file models (design §9.3) and the compiled policy the engine reads.

The file models check the file's shape. Everything that needs the registry (names exist, what a
wildcard grants) is checked by `policy/loader.py`.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from okta_mcp.registry.model import NAME, ecma_pattern

WILDCARD = "*"
# IDs only: the claim carries group IDs, and a name could be taken by another group (§8.2).
GROUP_ID = re.compile(r"00g[A-Za-z0-9]{17}")

Grant = tuple[str, str]
"""(domain, command), both registry names."""
Patterns = Mapping[StrictStr, tuple[StrictStr, ...]]
"""Domain or `*` → command names or `*`. There are no partial globs (`get-*`)."""


# Strings are `StrictStr`: pydantic would otherwise decode a YAML `!!binary` scalar into one,
# and `b"deny"` beside `"deny"` gets past the duplicate-key check.
class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _unique(values: tuple[str, ...], what: str) -> tuple[str, ...]:
    seen: set[str] = set()
    for v in values:
        if v in seen:
            raise ValueError(f"duplicate {what} {v!r}")
        seen.add(v)
    return values


def _patterns(v: Patterns) -> Patterns:
    for domain, commands in v.items():
        if not commands:
            raise ValueError(f"{domain!r} lists no commands")
        _unique(commands, f"command under {domain!r}")
        if domain == WILDCARD and commands != (WILDCARD,):
            # `"*": [get]` would mean a different command in every domain.
            raise ValueError('the only entry allowed under domain "*" is ["*"]')
    return MappingProxyType(dict(v))


class RoleEntry(_Model):
    groups: tuple[StrictStr, ...] = Field(min_length=1)
    """A principal in any of these groups holds the role."""
    allow: Patterns = Field(min_length=1)
    deny: Patterns = Field(default_factory=lambda: MappingProxyType({}))
    include_sensitive: tuple[StrictStr, ...] = ()
    """Domains (or `*`) where this role's `allow` wildcards also match sensitive commands."""

    @field_validator("groups")
    @classmethod
    def _group_ids(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for g in v:
            if not GROUP_ID.fullmatch(g):
                raise ValueError(
                    f"group {g!r} is not an Okta group ID (00g + 17 letters or digits); "
                    "put the group's name in a comment"
                )
        return _unique(v, "group")

    @field_validator("allow", "deny")
    @classmethod
    def _pattern_shape(cls, v: Patterns) -> Patterns:
        return _patterns(v)

    @field_validator("include_sensitive")
    @classmethod
    def _include_unique(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(v, "domain")


class PolicyFile(_Model):
    version: Literal[1]
    roles: Mapping[StrictStr, RoleEntry] = Field(min_length=1)

    @field_validator("version", mode="before")
    @classmethod
    def _int_version(cls, v: object) -> object:
        # `Literal[1]` alone also takes `true` and `1.0`.
        if type(v) is not int:
            raise ValueError("version must be the integer 1")
        return v

    @field_validator("roles")
    @classmethod
    def _role_names(cls, v: Mapping[str, RoleEntry]) -> Mapping[str, RoleEntry]:
        for name in v:
            if not ecma_pattern(NAME).match(name):
                raise ValueError(f"role name {name!r} must be kebab-case")
        return MappingProxyType(dict(v))


@dataclass(frozen=True)
class Role:
    """A role with its patterns expanded against the registry. `allow` already leaves out the
    sensitive commands its wildcards don't reach; `deny` is not yet subtracted, since it also
    applies to what the principal's other roles allow."""

    name: str
    groups: frozenset[str]
    allow: frozenset[Grant]
    allow_raised: frozenset[Grant]
    """The part of `allow` the role may also call with an argument that raises the call to
    sensitive (`arg_rule: raises_sensitivity_to`): commands it names outright, and those a
    wildcard reaches in a domain in its `include_sensitive`. The same rule as for sensitive
    commands, so a plain wildcard never reaches sensitive data through an argument."""
    deny: frozenset[Grant]


@dataclass(frozen=True)
class Policy:
    roles: Mapping[str, Role]
    warnings: tuple[str, ...]
    """Entries that load but probably don't do what was meant; startup logs them."""
