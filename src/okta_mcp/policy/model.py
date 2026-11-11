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

from okta_mcp.exec.output import ScrubRules
from okta_mcp.policy.expression import ATTRIBUTE, WORDS
from okta_mcp.registry.model import NAME, ecma_pattern

WILDCARD = "*"
# IDs only: the claim carries group IDs, and a name could be taken by another group (§8.2).
GROUP_ID = re.compile(r"00g[A-Za-z0-9]{17}")

Grant = tuple[str, str]
"""(domain, command), both registry names."""
# Every string in the file is a `StrictStr`: pydantic would otherwise decode a YAML `!!binary`
# scalar into one, and a `b"groups"` key beside `"groups"` gets past the duplicate-key check.
Patterns = Mapping[StrictStr, tuple[StrictStr, ...]]
"""Domain or `*` → command names or `*`. There are no partial globs (`get-*`)."""


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
    search_attributes: tuple[StrictStr, ...] = ()
    """Attributes (`profile.login`, `status`) this role may name in a search, filter or sort
    expression on the commands it allows, or `["*"]` for any. Names are matched exactly.
    Empty: no such expressions. Attributes that results redact are never searchable."""

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

    @field_validator("search_attributes")
    @classmethod
    def _attribute_names(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for a in v:
            if a != WILDCARD and not ATTRIBUTE.fullmatch(a):
                raise ValueError(
                    f"{a!r} is not an attribute name (letters, digits and _ in dotted "
                    'segments, like profile.login) or "*"'
                )
            if a.lower() in WORDS:
                # An expression reads this word as an operator or literal, never as a name.
                raise ValueError(f"{a!r} is an operator or literal word, not an attribute")
        if WILDCARD in v and len(v) > 1:
            raise ValueError('"*" must be the only entry')
        return _unique(v, "attribute")


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
    search_attributes: frozenset[str]
    """Attributes the role may name in an `attribute_expression` argument of a command in
    its `allow`; `{"*"}` is any. Never includes one that results redact (the loader)."""


@dataclass(frozen=True)
class Policy:
    roles: Mapping[str, Role]
    warnings: tuple[str, ...]
    """Entries that load but probably don't do what was meant; startup logs them."""
    scrub: ScrubRules
    """The redaction rules `search_attributes` was checked against. The engine tests
    expressions with these, so the load and the per-call check can't use different ones."""
