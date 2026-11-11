"""Registry file models (design §6.2) and the data-class → sensitivity table.

These models check each file's shape. Everything that needs the spec or other commands is
checked by `registry/loader.py`.
"""

import functools
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sensitivity = Literal["normal", "sensitive"]
DataClass = Literal[
    "pii",
    "org-config",
    "mfa-state",
    "credential-material",
    "audit-log",
    "admin-roles",
    "session",
    "risk",
]

# Reviewed table (design §6.2, §9.2). A command is `sensitive` if any of its classes is.
SENSITIVITY: Mapping[DataClass, Sensitivity] = MappingProxyType(
    {
        "pii": "normal",
        "org-config": "normal",
        "mfa-state": "sensitive",
        "credential-material": "sensitive",
        "audit-log": "sensitive",
        "admin-roles": "sensitive",
        "session": "sensitive",
        "risk": "sensitive",
    }
)

NAME = r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"


def sensitivity_of(classes: tuple[DataClass, ...]) -> Sensitivity:
    return "sensitive" if any(SENSITIVITY[c] == "sensitive" for c in classes) else "normal"


@functools.cache
def ecma_pattern(pattern: str) -> re.Pattern[str]:
    """JSON Schema patterns are ECMA-262, where `$` ends the input; Python's `$` also matches
    before a final newline, so `^00g…$` would accept an ID plus `\\n`. Unescaped `$` outside
    a character class becomes `\\Z`."""
    out: list[str] = []
    escaped = in_class = False
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "$" and not in_class:
            ch = r"\Z"
        out.append(ch)
    return re.compile("".join(out))


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArgRule(_Model):
    """What passing the argument does to the call (design §9.2). Exactly one field is set."""

    forbidden: bool = False
    """No caller may pass the argument."""
    raises_sensitivity_to: Literal["sensitive"] | None = None
    """A call that passes it is sensitive, whatever the command's data classes."""
    reviewed: str | None = Field(default=None, pattern=r"\S")
    """The argument leaves the call's sensitivity as it is; the value says why: every field
    the filter can match is one the command returns unredacted (design §6.2 check 6). Only
    for free-form filters (`filter`, `search`, `q`), which the loader enforces."""

    attribute_expression: bool = False
    """The value is an Okta filter expression (`search`, `filter`) or one attribute name
    (`sortBy`). The policy engine reads the attributes it names: none may be one results
    redact, and each must be in the caller's roles' `search_attributes` (design §9.3)."""

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        chosen = (
            self.forbidden,
            self.raises_sensitivity_to is not None,
            self.reviewed is not None,
            self.attribute_expression,
        )
        if sum(chosen) != 1:
            raise ValueError(
                "arg_rule must set exactly one of forbidden, raises_sensitivity_to, reviewed "
                "or attribute_expression"
            )
        return self


class Arg(_Model):
    path_param: str | None = Field(default=None, min_length=1)
    query: str | None = Field(default=None, min_length=1)
    resolve: Literal["user_id"] | None = None
    pattern: str | None = None
    allowed_values: tuple[str, ...] | None = None
    """Empty → the argument is not exposed."""
    arg_rule: ArgRule | None = None
    type: Literal["string", "integer", "boolean", "array"] | None = None
    max_items: int | None = Field(default=None, alias="maxItems", ge=1)

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        # Compile as validation will, so a pattern the translation breaks fails at load.
        if v is not None:
            try:
                ecma_pattern(v)
            except re.error as e:
                raise ValueError(f"invalid pattern: {e}") from e
        return v

    @model_validator(mode="after")
    def _one_target(self) -> Self:
        if (self.path_param is None) == (self.query is None):
            raise ValueError("set exactly one of path_param or query")
        if self.resolve is not None and self.path_param is None:
            raise ValueError("resolve applies only to a path_param")
        return self

    @property
    def param(self) -> str:
        return cast(str, self.path_param or self.query)


class ScopesOverride(_Model):
    """For operations whose spec declares no `oauth2` scopes (design §6.2 check 3)."""

    scopes: tuple[str, ...] = Field(min_length=1)
    reason: str = Field(min_length=1)


class ResponseOverride(_Model):
    """For operations whose spec declares a single object but return a list of it (V8)."""

    kind: Literal["list"]
    reason: str = Field(min_length=1)


class Resumable(_Model):
    unless_args: tuple[str, ...] = Field(min_length=1)


class CommandEntry(_Model):
    operation: str
    summary: str = Field(min_length=1)
    args: Mapping[str, Arg] = Field(default_factory=lambda: MappingProxyType({}))
    one_of_required: tuple[str, ...] | None = Field(default=None, min_length=2)
    """Exactly one of these args must be passed."""
    paginate: Literal["link", "body_links", "link_or_body", "none"] = "none"
    page_size: int | None = Field(default=None, ge=1)
    items_key: str | None = None
    view: tuple[str, ...] | None = Field(default=None, min_length=1)
    data_classes: tuple[DataClass, ...] = Field(min_length=1)
    resumable: bool | Resumable = True
    okta_scopes_override: ScopesOverride | None = None
    response_override: ResponseOverride | None = None
    handler: str | None = None
    """Reserved for post-v1 composite handlers; the loader rejects it."""

    @field_validator("args")
    @classmethod
    def _arg_names(cls, v: Mapping[str, Arg]) -> Mapping[str, Arg]:
        for name in v:
            if not re.match(r"^[a-z][a-z0-9_]*$", name):
                raise ValueError(f"arg name {name!r} must be snake_case")
        return MappingProxyType(dict(v))

    @property
    def sensitivity(self) -> Sensitivity:
        return sensitivity_of(self.data_classes)


class DomainFile(_Model):
    domain: str = Field(pattern=NAME)
    description: str = Field(min_length=1)
    commands: Mapping[str, CommandEntry] = Field(min_length=1)

    @field_validator("commands")
    @classmethod
    def _command_names(cls, v: Mapping[str, CommandEntry]) -> Mapping[str, CommandEntry]:
        for name in v:
            if not re.match(NAME, name):
                raise ValueError(f"command name {name!r} must be kebab-case")
        return MappingProxyType(dict(v))
