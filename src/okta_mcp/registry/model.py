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
    attributes: tuple[str, ...] | None = Field(default=None, min_length=1)
    """With `attribute_expression` only: the closed set of attributes the argument may name,
    whatever the roles allow (`["*"]` included). For filters over a schema with free-form
    objects (System Log `debugContext.debugData`): naming the object itself could match a
    redacted key inside it, which the redaction test, reading names only, can't see."""

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
        if self.attributes is not None:
            if not self.attribute_expression:
                raise ValueError("arg_rule attributes needs attribute_expression")
            if len(set(self.attributes)) != len(self.attributes):
                raise ValueError("arg_rule attributes has duplicates")
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
    required: bool = False
    """Okta rejects calls without it though the spec doesn't flag it required. On a handler
    command: the caller must pass it."""
    max_length: int | None = Field(default=None, ge=1)
    """Handler commands only: the longest string accepted (default `HANDLER_STRING_MAX`)."""
    description: str | None = Field(default=None, min_length=1)
    """Handler commands only, and required there: `okta_help`'s text for the arg, which has no
    spec parameter to take it from."""

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
        # Neither is a handler command's arg; `CommandEntry` checks which kind it is in.
        if self.path_param is not None and self.query is not None:
            raise ValueError("set exactly one of path_param or query")
        if self.resolve is not None and self.path_param is None:
            raise ValueError("resolve applies only to a path_param")
        return self

    @property
    def targeted(self) -> bool:
        """It maps to a spec parameter (an operation command's arg)."""
        return self.path_param is not None or self.query is not None

    @property
    def param(self) -> str:
        if not self.targeted:
            raise RuntimeError("a handler command's arg has no spec parameter")
        return cast(str, self.path_param or self.query)


class ScopesOverride(_Model):
    """For operations whose spec declares no `oauth2` scopes (design §6.2 check 3)."""

    scopes: tuple[str, ...] = Field(min_length=1)
    reason: str = Field(min_length=1)


class ResponseOverride(_Model):
    """Where Okta's response doesn't have the spec's shape (V8). `list`: the spec declares one
    object, Okta returns a list of them. `wrapped`: the spec declares a list, Okta returns it
    inside an object, under the command's `items_key` (`{"keys": [...]}`)."""

    kind: Literal["list", "wrapped"]
    reason: str = Field(min_length=1)


HANDLER_STRING_MAX = 256
"""Default `max_length` of a handler command's string arg."""


class Uses(_Model):
    """The operations a handler command may call (design §5.6), each a GET from the pinned spec.
    The handler's context refuses any other. `required` decide whether the command can run at
    all (its scope sets); an `optional` one whose scopes the service app lacks is skipped and
    reported, so an org that doesn't grant, say, `okta.devicePostureChecks.read` still gets the
    rest of the diagnosis."""

    required: tuple[str, ...] = Field(min_length=1)
    optional: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _distinct(self) -> Self:
        every = (*self.required, *self.optional)
        if len(set(every)) != len(every):
            raise ValueError("uses lists an operation twice")
        return self


class Resumable(_Model):
    unless_args: tuple[str, ...] = Field(min_length=1)


class CommandEntry(_Model):
    operation: str | None = None
    """The one operation of a simple command. Exactly one of `operation` and `handler`."""
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
    unpaged_args: tuple[str, ...] = ()
    """Args with which Okta doesn't page the list (`listGroups` `q`): no next link, and a result
    cut at `page_size` gives no sign of it. A call that passes one is read as one page, is never
    resumable, and is reported truncated when Okta returns a full page (design §7.2)."""
    okta_scopes_override: ScopesOverride | None = None
    response_override: ResponseOverride | None = None
    handler: str | None = Field(default=None, pattern=NAME)
    """A composite command (design §5.6): the name of a Python handler in
    `okta_mcp.handlers`, which calls the operations in `uses`. Its args map to no spec
    parameter; it takes no `view`, paging or response overrides, and is never resumable."""
    uses: Uses | None = None

    @model_validator(mode="after")
    def _kind(self) -> Self:
        if (self.operation is None) == (self.handler is None):
            raise ValueError("set exactly one of operation or handler")
        if self.operation is not None:
            if self.uses is not None:
                raise ValueError("uses is only for handler commands")
            for name, arg in self.args.items():
                if not arg.targeted:
                    raise ValueError(f"arg {name}: set exactly one of path_param or query")
                if arg.max_length is not None or arg.description is not None:
                    raise ValueError(
                        f"arg {name}: max_length and description are only for handler "
                        "commands (the spec gives them)"
                    )
            return self
        if self.uses is None:
            raise ValueError("a handler command needs uses")
        simple_only = {
            "one_of_required": self.one_of_required is not None,
            "paginate": self.paginate != "none",
            "page_size": self.page_size is not None,
            "items_key": self.items_key is not None,
            "view": self.view is not None,
            "unpaged_args": bool(self.unpaged_args),
            "okta_scopes_override": self.okta_scopes_override is not None,
            "response_override": self.response_override is not None,
        }
        if bad := [k for k, set_ in simple_only.items() if set_]:
            raise ValueError(f"{', '.join(bad)}: not for handler commands")
        if self.resumable is not True:
            raise ValueError("resumable: handler commands are never resumable; leave it out")
        for name, arg in self.args.items():
            if arg.targeted or arg.resolve is not None or arg.arg_rule is not None:
                raise ValueError(
                    f"arg {name}: a handler command's args take no path_param, query, resolve "
                    "or arg_rule (the handler validates and uses them)"
                )
            if arg.description is None:
                raise ValueError(f"arg {name}: a handler command's args need a description")
            if arg.type not in (None, "string") and arg.max_length is not None:
                raise ValueError(f"arg {name}: max_length is for strings")
            if arg.type == "array" or arg.max_items is not None:
                raise ValueError(f"arg {name}: handler args are strings, integers or booleans")
        return self

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
