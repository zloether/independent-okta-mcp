"""Request building from a command's arguments (design §6.4).

Okta decodes `%2F` and collapses dot segments server-side, so percent-encoding alone doesn't keep
a value inside its path segment: a path value is restricted first, then encoded with no safe
characters. The rule applies whatever the argument's `pattern`, so it also covers "ID or login"
parameters that have none. Query values go out as a params mapping, never concatenated.
"""

import re
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

import httpx2

from okta_mcp.registry.loader import Command
from okta_mcp.registry.schema import InvalidArguments, validate_args

PATH_VALUE_MAX = 256
_FORBIDDEN = frozenset("/\\%?#")
_VAR = re.compile(r"\{([^}]*)\}")


def _path_problem(value: object) -> str | None:
    if not isinstance(value, str):
        return "must be a string"
    if value in ("", ".", ".."):
        return "can't be empty, . or .."
    if len(value) > PATH_VALUE_MAX:
        return f"is over {PATH_VALUE_MAX} characters"
    # Category C: control, format, surrogate, private-use and unassigned code points.
    if any(c in _FORBIDDEN or c.isspace() or unicodedata.category(c)[0] == "C" for c in value):
        return "can't contain / \\ % ? #, whitespace or control characters"
    return None


def path_segment(arg: str, value: object) -> str:
    """`value` percent-encoded with no safe characters. Raises `InvalidArguments` naming `arg`,
    never the value, if the value breaks the §6.4 character rule."""
    if (problem := _path_problem(value)) is not None:
        raise InvalidArguments(f"arg {arg!r} {problem}")
    return quote(str(value), safe="")


def build_url(org_url: str, template: str, segments: Mapping[str, str]) -> str:
    """`org_url` joined to the spec's path `template`, each `{name}` replaced by `segments[name]`
    (from `path_segment`). The result must be on `org_url` with exactly that path; a mismatch is
    a bug, not bad input, so it raises `RuntimeError`."""
    if set(_VAR.findall(template)) != set(segments):
        raise RuntimeError("path segments don't match the operation's template")
    path = _VAR.sub(lambda m: segments[m[1]], template)
    url, org = httpx2.URL(org_url + path), httpx2.URL(org_url)
    origin = (org.scheme, org.host, org.port, b"")
    if (url.scheme, url.host, url.port, url.userinfo) != origin or url.raw_path != path.encode():
        raise RuntimeError("built URL is off the operation's path")
    return str(url)


def build_request(
    command: Command, args: Mapping[str, Any], org_url: str
) -> tuple[str, dict[str, str]]:
    """The URL and query params for `command` with `args`, which are validated here too. The
    server's `page_size` goes out as `limit`. Raises `InvalidArguments` listing every problem."""
    validate_args(command, args)
    segments: dict[str, str] = {}
    params: dict[str, str] = {}
    problems: list[str] = []
    for name, value in args.items():
        arg = command.entry.args[name]
        if arg.path_param is None:
            params[arg.param] = _query_value(value)
        elif (problem := _path_problem(value)) is not None:
            problems.append(f"arg {name!r} {problem}")
        else:
            segments[arg.path_param] = path_segment(name, value)
    if problems:
        raise InvalidArguments("; ".join(sorted(problems)))
    if command.entry.page_size is not None:
        params["limit"] = str(command.entry.page_size)
    return build_url(org_url, command.operation.path, segments), params


def _query_value(value: object) -> str:
    match value:
        case bool():
            return "true" if value else "false"
        case int() | str():
            return str(value)
        case _:
            # Okta's encoding of array query params varies by endpoint (Phase 5).
            raise TypeError("only string, integer and boolean query values are supported")
