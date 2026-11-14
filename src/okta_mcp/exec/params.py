"""Request building from a command's arguments (design §6.4).

Okta decodes `%2F` and collapses dot segments server-side, so percent-encoding alone doesn't keep
a value inside its path segment: a path value is restricted first, then encoded with no safe
characters. The rule applies whatever the argument's `pattern`, so it also covers "ID or login"
parameters that have none. A value that stays inside its segment can still name another
endpoint (`rules` as a group ID is `/api/v1/groups/rules`, the group-rules list), so the literal
segments the spec has in the parameter's place (`Operation.reserved`, which also holds names Okta
routes that the spec doesn't list, such as `me` after `/users/`) are refused as well, with any
trailing dots (`me.`), and so is a reserved name followed by `.` and more (`oauth2.json`), in case
Okta matches a suffix. Okta was seen not to for `me` and `rules` (`/users/me.json`,
`/groups/rules.json` are literal values; 2.10 dev-org check), so those two take a suffix and a login
such as `me.smith@…` resolves. Query values go out as a params mapping, never concatenated.
"""

import re
import unicodedata
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import quote

import httpx2

from okta_mcp.okta.client import on_origin
from okta_mcp.registry.loader import Command
from okta_mcp.registry.schema import InvalidArguments, schema_problems

PATH_VALUE_MAX = 256
# `;` too: Okta strips a matrix parameter before routing (`/users/me;x` is `/users/me`, 2.10
# dev-org check). No ID or login needs it.
_FORBIDDEN = frozenset("/\\%?#;")
_VAR = re.compile(r"\{([^}]*)\}")
# Reserved names Okta was seen to route as literals when suffixed (2.10 dev-org check:
# `/users/me.json` E0000007, `/groups/rules.json` E0000008). Others stay refused with a suffix
# until the live-org probes (plan 8.2.1) cover them.
_SUFFIX_IS_LITERAL = frozenset({"me", "rules"})


def _path_problem(value: object, reserved: frozenset[str]) -> str | None:
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
            return "can't contain / \\ % ? #, a semicolon, whitespace or control characters"
        # Casefolded: Okta may match path literals case-insensitively. Trailing dots stripped:
        # whether Okta drops them (`me.` as `me`) is unverified, and no ID or login ends in one.
        # The part before a first `.` too, in case Okta matches a suffix (`export.csv`), except
        # for the names seen not to (`me.smith@…` is a login).
        folded = form.casefold()
        head = folded.partition(".")[0]
        if folded.rstrip(".") in reserved or (head in reserved and head not in _SUFFIX_IS_LITERAL):
            return "is the name of another endpoint, not an ID"
    return None


def path_segment(arg: str, value: object, reserved: frozenset[str]) -> str:
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
    reserved = command.operation.reserved
    problems = schema_problems(command, args)
    if isinstance(args, Mapping):
        problems |= {
            f"arg {name!r} {problem}"
            for name, value in cast(Mapping[object, object], args).items()
            if isinstance(name, str)
            and name in entry.args
            and (param := entry.args[name].path_param) is not None
            and (problem := _path_problem(value, reserved.get(param, frozenset()))) is not None
        }
        problems |= {
            f"arg {name!r} must be valid Unicode text (no lone surrogates)"
            for name, value in cast(Mapping[object, object], args).items()
            if isinstance(name, str)
            and name in entry.args
            and entry.args[name].query is not None
            and not _encodable(value)
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


def _encodable(value: object) -> bool:
    """A query value, or every item of one, can be sent as UTF-8 (a lone surrogate can't)."""
    items = cast(list[object], value) if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
    return True


def _query_value(value: object) -> str:
    return ("true" if value else "false") if isinstance(value, bool) else str(value)
