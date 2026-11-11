"""Request building from a command's arguments (design §6.4).

Okta decodes `%2F` and collapses dot segments server-side, so percent-encoding alone doesn't keep
a value inside its path segment: a path value is restricted first, then encoded with no safe
characters. The rule applies whatever the argument's `pattern`, so it also covers "ID or login"
parameters that have none. A value that stays inside its segment can still name another
endpoint (`rules` as a group ID is `/api/v1/groups/rules`, the group-rules list), so the literal
segments the spec has in the parameter's place (`Operation.reserved`) are refused as well, and so
are names Okta routes that the spec doesn't list (`me` after `/users/`, `OKTA_ALIASES`). Query
values go out as a params mapping, never concatenated.
"""

import re
import unicodedata
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import quote

import httpx2

from okta_mcp.okta.client import on_origin
from okta_mcp.registry.loader import Command
from okta_mcp.registry.schema import InvalidArguments, schema_problems
from okta_mcp.registry.spec import Operation

PATH_VALUE_MAX = 256
_FORBIDDEN = frozenset("/\\%?#")
_VAR = re.compile(r"\{([^}]*)\}")

OKTA_ALIASES: Mapping[str, frozenset[str]] = MappingProxyType({"users": frozenset({"me"})})
"""Literal segment → names Okta routes in the path segment right after it that no spec path
lists. `/api/v1/users/me` is the token's own user (the SSWS token's owner in dev mode), so `me`
as a user ID would read the service identity, not the user asked for."""


def reserved_for(operation: Operation, param: str) -> frozenset[str]:
    """Values `param` of `operation` may not take: the spec's literals in its place
    (`Operation.reserved`) and the `OKTA_ALIASES` of the segment before it. Casefolded."""
    segments = operation.path.strip("/").split("/")
    var = f"{{{param}}}"
    i = segments.index(var) if var in segments else 0
    none = frozenset[str]()
    aliases = OKTA_ALIASES.get(segments[i - 1], none) if i > 0 else none
    return operation.reserved.get(param, none) | aliases


def _path_problem(value: object, reserved: frozenset[str] = frozenset()) -> str | None:
    if not isinstance(value, str):
        return "must be a string"
    if len(value) > PATH_VALUE_MAX:
        return f"is over {PATH_VALUE_MAX} characters"
    # The NFKC form too, in case Okta folds lookalikes (fullwidth `..`, `/`) after decoding.
    for form in (value, unicodedata.normalize("NFKC", value)):
        if form in ("", ".", ".."):
            return "can't be empty, . or .."
        # Category C: control, format, surrogate, private-use and unassigned code points.
        if any(c in _FORBIDDEN or c.isspace() or unicodedata.category(c)[0] == "C" for c in form):
            return "can't contain / \\ % ? #, whitespace or control characters"
        # Casefolded: Okta may match path literals case-insensitively.
        if form.casefold() in reserved:
            return "is the name of another endpoint, not an ID"
    return None


def path_segment(arg: str, value: object, reserved: frozenset[str] = frozenset()) -> str:
    """`value` percent-encoded with no safe characters. Raises `InvalidArguments` naming `arg`,
    never the value, if the value breaks the §6.4 character rule or is one of `reserved` (the
    parameter's `Operation.reserved` entry)."""
    if (problem := _path_problem(value, reserved)) is not None:
        raise InvalidArguments(f"arg {arg!r} {problem}")
    return quote(str(value), safe="")


def build_url(org_url: str, template: str, segments: Mapping[str, str]) -> str:
    """`org_url` joined to the spec's path `template`, each `{name}` replaced by `segments[name]`
    (from `path_segment`). The result must be on `org_url` with exactly that path; a mismatch is
    a bug, not bad input, so it raises `RuntimeError`."""
    if set(_VAR.findall(template)) != set(segments):
        raise RuntimeError("path segments don't match the operation's template")
    path = _VAR.sub(lambda m: segments[m[1]], template)
    url = httpx2.URL(org_url + path)
    if not on_origin(url, httpx2.URL(org_url)) or url.raw_path != path.encode():
        raise RuntimeError("built URL is off the operation's path")
    return str(url)


def check_args(command: Command, args: object) -> None:
    """Raise `InvalidArguments` listing every schema problem (`registry.schema`) and every path
    value that breaks the §6.4 rule, at once. No request is built; `build_request` runs this
    too, so no caller can skip it."""
    entry = command.entry
    problems = schema_problems(command, args)
    if isinstance(args, Mapping):
        problems |= {
            f"arg {name!r} {problem}"
            for name, value in cast(Mapping[object, object], args).items()
            if isinstance(name, str)
            and name in entry.args
            and (param := entry.args[name].path_param) is not None
            and (problem := _path_problem(value, reserved_for(command.operation, param)))
            is not None
        }
    if problems:
        raise InvalidArguments("; ".join(sorted(problems)))


def build_request(
    command: Command, args: Mapping[str, Any], org_url: str
) -> tuple[str, dict[str, str | list[str]]]:
    """The URL and query params for `command` with `args`, which are validated here too
    (`check_args`). A `resolve: user_id` arg must already hold the resolved user ID. The
    server's `page_size` goes out as `limit`."""
    entry = command.entry
    check_args(command, args)
    segments: dict[str, str] = {}
    params: dict[str, str | list[str]] = {}
    for name, value in args.items():
        arg = entry.args[name]
        if arg.path_param is not None:
            segments[arg.path_param] = quote(value, safe="")
        elif isinstance(value, list):
            items = [_query_value(v) for v in cast(list[object], value)]
            params[arg.param] = (
                items if command.operation.params[arg.param].explode else ",".join(items)
            )
        else:
            params[arg.param] = _query_value(value)
    if entry.page_size is not None:
        params["limit"] = str(entry.page_size)
    return build_url(org_url, command.operation.path, segments), params


def _query_value(value: object) -> str:
    return ("true" if value else "false") if isinstance(value, bool) else str(value)
