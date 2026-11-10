"""Per-item output options (design §7.2, T1 D4-D6): secret scrub → `links` → `select`/view or prune.

Scrubbing always runs first, on the whole item, so no later option can expose a scrubbed field.
"""

from dataclasses import dataclass
from functools import cached_property
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Annotated, Any, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from okta_mcp.registry.loader import UniqueKeyLoader
from okta_mcp.registry.schema import InvalidArguments

SCRUB = files("okta_mcp") / "data" / "scrub.yaml"
REDACTED = "[redacted]"
WHOLE = "*"


class ScrubError(Exception):
    pass


# Dotted keys, no wildcards: a `*` segment would be a literal key and silently match nothing.
# `\s` is excluded, so `$` can't let a trailing newline through.
_Path = Annotated[str, Field(pattern=r"^[^.\s*]+(\.[^.\s*]+)*$")]


class _ScrubFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    paths: tuple[_Path, ...] = Field(min_length=1)
    strings: tuple[_Path, ...] = ()


@dataclass(frozen=True)
class ScrubRules:
    paths: tuple[tuple[str, ...], ...]
    """Lower-cased key chains; the value is redacted whatever its type."""
    strings: tuple[tuple[str, ...], ...] = ()
    """Lower-cased key chains; the value is redacted only if it is a string."""

    @cached_property
    def chains(self) -> tuple[tuple[tuple[str, ...], bool], ...]:
        """(key chain, strings only) for every rule."""
        return tuple((p, False) for p in self.paths) + tuple((p, True) for p in self.strings)

    @cached_property
    def starts(self) -> dict[str, tuple[int, ...]]:
        """First key → indices into `chains` starting with it, so a key isn't tested against
        every rule."""
        starts: dict[str, list[int]] = {}
        for c, (chain, _) in enumerate(self.chains):
            starts.setdefault(chain[0], []).append(c)
        return {k: tuple(v) for k, v in starts.items()}


def load_scrub(path: Traversable = SCRUB) -> ScrubRules:
    """Raises `ScrubError` on a missing, malformed or empty file: the server must not start."""
    try:
        doc = yaml.load(path.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
        parsed = _ScrubFile.model_validate(doc)
    except (OSError, yaml.YAMLError, ValidationError) as e:
        raise ScrubError(f"{path.name}: {e}") from e
    return ScrubRules(
        tuple(tuple(p.lower().split(".")) for p in parsed.paths),
        tuple(tuple(p.lower().split(".")) for p in parsed.strings),
    )


def scrub(value: Any, rules: ScrubRules) -> Any:
    """A copy of `value` with every value at a `rules` path replaced by `REDACTED`."""
    return _scrub(value, rules, ())


def _scrub(value: Any, rules: ScrubRules, partial: tuple[tuple[int, int], ...]) -> Any:
    # `partial` holds (index into `rules.chains`, keys matched so far) for chains that are under
    # way here.
    if isinstance(value, list):
        return [_scrub(v, rules, partial) for v in cast(list[Any], value)]
    if not isinstance(value, dict):
        return value
    chains, starts = rules.chains, rules.starts
    out: dict[str, Any] = {}
    for key, v in cast(dict[str, Any], value).items():
        k = key.lower()
        advanced = [(c, n + 1) for c, n in partial if chains[c][0][n] == k]
        advanced += [(c, 1) for c in starts.get(k, ())]
        complete = [chains[c][1] for c, n in advanced if n == len(chains[c][0])]
        if any(not strings_only or isinstance(v, str) for strings_only in complete):
            out[key] = REDACTED
        else:
            out[key] = _scrub(v, rules, tuple((c, n) for c, n in advanced if n < len(chains[c][0])))
    return out


def strip_links(value: Any) -> Any:
    """A copy of `value` without `_links` at any depth. `_embedded` stays: it carries `expand`."""
    if isinstance(value, list):
        return [strip_links(v) for v in cast(list[Any], value)]
    if isinstance(value, dict):
        return {k: strip_links(v) for k, v in cast(dict[str, Any], value).items() if k != "_links"}
    return value


def prune(value: Any) -> Any:
    """A copy of `value` without object members that are `null`, `{}` or `[]` once pruned
    themselves (T1 D6). Empty strings and array elements stay, so `REDACTED` always survives."""
    if isinstance(value, list):
        return [prune(v) for v in cast(list[Any], value)]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for k, v in cast(dict[str, Any], value).items():
        v = prune(v)
        if v is not None and v != {} and v != []:
            out[k] = v
    return out


def columns(select: str | None, view: tuple[str, ...] | None) -> tuple[str, ...] | None:
    """The dotted paths to output, or `None` for the whole object. An omitted `select` means the
    command's view; `"*"` means the whole object. Paths aren't checked against the schema, so
    custom profile attributes stay selectable (T1 D5). A repeated path is kept once."""
    if select is None:
        return view
    paths = tuple(p.strip() for p in select.split(","))
    if paths == (WHOLE,):
        return None
    if any(p == WHOLE or any(not s or s != s.strip() for s in p.split(".")) for p in paths):
        raise InvalidArguments(
            "select is '*' or comma-separated dotted paths, e.g. 'id,profile.login'"
        )
    return tuple(dict.fromkeys(paths))


def pick(value: Any, path: str) -> Any:
    """The value at dotted `path`, or `None` if absent. An array on the way maps the rest of the
    path over its elements, so `gateways.value` lists every gateway's value."""
    return _pick(value, path.split("."))


def _pick(value: Any, keys: list[str]) -> Any:
    if not keys:
        return value
    if isinstance(value, list):
        return [_pick(v, keys) for v in cast(list[Any], value)]
    if isinstance(value, dict):
        return _pick(cast(dict[str, Any], value).get(keys[0]), keys[1:])
    return None


def render(item: Any, rules: ScrubRules, *, links: bool, cols: tuple[str, ...] | None) -> Any:
    """`item` as output: a row of `cols` values (cells keep `null`, so columns never shift), or
    with `cols` `None` the pruned whole object."""
    item = scrub(item, rules)
    if not links:
        item = strip_links(item)
    if cols is None:
        return prune(item)
    return [pick(item, c) for c in cols]
