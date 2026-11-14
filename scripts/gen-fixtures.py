#!/usr/bin/env python3
"""Default per-command fixtures from the pinned spec (design §14).

    uv run python scripts/gen-fixtures.py [--domain NAME] [--check]

Writes tests/fixtures/<domain>/<command>.json for every registry command: the operation's 200
response example from the spec when it has one, else a body built from the response schema.
Either way hosts, mail addresses and IPs are rewritten to reserved ones (fixturelib.py), IDs
that the generator makes up have Okta's shape (3-character prefix, 17 base-62 characters), and
the output is deterministic, so a re-run after a spec update shows only real changes.

A file whose `source` is `recorded` (made by sanitize-fixture.py) is never overwritten.

--check writes nothing; it exits 1 and lists every fixture that is missing, out of date, or
left over from a command that no longer exists. Exit status 2: invalid spec or registry.
"""

import argparse
import copy
import functools
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import yaml
from fixturelib import Neutralizer, okta_id

from okta_mcp.exec.output import pick
from okta_mcp.registry.loader import Command, Registry, RegistryError, load_registry
from okta_mcp.registry.spec import SPEC, Resolver, SpecError, load_spec

FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures"
MAX_DEPTH = 8
SCALARS: Mapping[str, Any] = {
    "date-time": "2026-01-01T00:00:00.000Z",
    "date": "2026-01-01",
    "email": "user@example.com",
    "uri": "https://example.okta.com/",
    "url": "https://example.okta.com/",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "ipv4": "203.0.113.1",
    "ipv6": "2001:db8::1",
}


class Synth(Resolver):
    """Builds a value from a spec schema. A schema met again on its own path, or below
    MAX_DEPTH, is left out, so recursive schemas terminate."""

    def __init__(self, spec: Mapping[str, Any], seed: str) -> None:
        super().__init__(spec)
        self._seed = seed

    def value(self, node: Any, path: str = "", stack: tuple[int, ...] = ()) -> Any:
        schema = self.deref(node)
        if not isinstance(schema, dict):
            return None
        schema = cast(dict[str, Any], schema)
        if "example" in schema:
            return schema["example"]
        if id(schema) in stack or len(stack) > MAX_DEPTH:
            return _OMIT
        stack = (*stack, id(schema))
        for key in ("oneOf", "anyOf"):
            if variants := cast(list[Any], schema.get(key) or []):
                return self.value(variants[0], path, stack)
        if self.is_object(schema):
            return self._object(schema, path, stack)
        kind = schema.get("type")
        if kind == "array":
            item = self.value(schema.get("items"), f"{path}[]", stack)
            return [] if item is _OMIT else [item]
        if enum := schema.get("enum"):
            return cast(list[Any], enum)[0]
        if "default" in schema:
            return schema["default"]
        if kind in ("integer", "number"):
            return schema.get("minimum", 0)
        if kind == "boolean":
            return False
        if kind == "string" or kind is None:
            return self._string(schema, path)
        return None

    def _object(self, schema: dict[str, Any], path: str, stack: tuple[int, ...]) -> Any:
        out: dict[str, Any] = {}
        for name, sub in self.properties(schema).items():
            if isinstance(s := self.deref(sub), dict) and cast(dict[str, Any], s).get("writeOnly"):
                continue  # Never in a response.
            v = self.value(sub, f"{path}.{name}" if path else name, stack)
            if v is not _OMIT:
                out[name] = v
        return out

    def _string(self, schema: dict[str, Any], path: str) -> str:
        fmt = schema.get("format")
        if isinstance(fmt, str) and fmt in SCALARS:
            return SCALARS[fmt]
        name = path.rsplit(".", 1)[-1].removesuffix("[]")
        if name == "id" or name.endswith("Id"):
            return okta_id(f"{self._seed}:{path}")
        if name == "href":
            return "https://example.okta.com/"
        return name or "string"


_OMIT: Any = object()


def raw_spec() -> dict[str, Any]:
    return cast(dict[str, Any], yaml.load(SPEC.read_bytes(), Loader=yaml.CSafeLoader))


def body(spec: Mapping[str, Any], command: Command) -> Any:
    """The fixture body: the first spec example of the 200 response, else a synthesized one;
    wrapped in a list when the registry reads the response as one (`response_override` list) or
    the spec's schema is an array whose examples show one item (`listAuthenticatorMethods`);
    unwrapped from a one-item list under an object schema (`getOAuth2Claim`); and a list in an
    object under `items_key` for `response_override` wrapped
    (`listOAuth2ResourceServerJsonWebKeys`) or for an object schema whose example is the bare
    list (`listOktaSupportCases`)."""
    synth = Synth(spec, f"{command.domain}.{command.name}")
    op = cast(dict[str, Any], spec["paths"][command.operation.path]["get"])
    ok = synth.deref(op.get("responses", {}).get("200", {}))
    content = cast(dict[str, Any], ok.get("content", {}).get("application/json", {}))
    # An empty list or object exercises nothing; such an example falls back to the schema.
    examples = [synth.deref(e).get("value") for e in (content.get("examples") or {}).values()]
    examples += [content["example"]] if "example" in content else []
    found = [e for e in examples if e]
    if found:
        value = found[0]
    else:
        value = synth.value(content.get("schema"))
        value = None if value is _OMIT else value
    # Under an array schema, only a value that looks like one item is wrapped: a wrapper or
    # error object stays exactly as it is, unfilled, so the fixture test fails on it.
    spec_list = command.operation.response.kind == "list"
    if spec_list and not isinstance(value, list) and _item_like(value, command):
        value = [value]
    # And the reverse: under an object schema, a one-item list of an object is that object
    # (`getOAuth2Claim`'s example is the list example). Longer lists stay, and fail the test.
    one = cast(list[Any], value) if isinstance(value, list) else []
    if (
        command.operation.response.kind == "object"
        and command.entry.response_override is None
        and len(one) == 1
        and _item_like(one[0], command)
    ):
        value = one[0]
    if found and not (spec_list and not isinstance(value, list)):
        value = _fill_view(value, lambda: synth.value(content.get("schema")), command)
    override = command.entry.response_override
    if override is not None and override.kind == "list" and not isinstance(value, list):
        value = [value]
    # A wrapped list: by override, or by a wrapper schema whose example is the bare list
    # (`listOktaSupportCases`; the schema wins).
    wrapped = override is not None and override.kind == "wrapped"
    by_schema = override is None and command.operation.response.kind == "object"
    if isinstance(value, list) and command.entry.items_key is not None and (wrapped or by_schema):
        value = {command.entry.items_key: value}
    return Neutralizer()(value)


def _item_like(value: Any, command: Command) -> bool:
    if not isinstance(value, dict):
        return False
    # `_links` and `_embedded` sit on wrappers too, so they prove nothing.
    tops = {f.split(".")[0] for f in command.operation.response.fields} - {"_links", "_embedded"}
    return bool(set(cast(dict[str, Any], value)) & tops)


def _items(value: Any, command: Command) -> list[Any]:
    if isinstance(value, dict) and command.entry.items_key is not None:
        value = cast(dict[str, Any], value).get(command.entry.items_key)
    return cast(list[Any], value) if isinstance(value, list) else [value]


def _fill_view(example: Any, synthesize: Callable[[], Any], command: Command) -> Any:
    """A spec example can leave out a field the command's view shows (the users-groups example
    has no `type`). Such a path is copied from the schema-built body into the first item, so
    the fixture carries every view column. A column counts as present by the fixture test's
    rule (`pick`, with `[]` and `[None]` blank); a path through a non-object is left alone."""
    items = [i for i in _items(example, command) if isinstance(i, dict)]
    missing = [p for p in command.entry.view or () if all(_blank(pick(i, p)) for i in items)]
    if not items or not missing:
        return example
    built = [i for i in _items(synthesize(), command) if isinstance(i, dict)]
    if not built:
        return example
    example = copy.deepcopy(example)
    first = next(i for i in _items(example, command) if isinstance(i, dict))
    for path in missing:
        if _blank(v := pick(built[0], path)):
            continue
        *parents, leaf = path.split(".")
        node: Any = first
        for k in parents:
            node = cast(dict[str, Any], node).setdefault(k, {})
            if not isinstance(node, dict):
                break
        else:
            cast(dict[str, Any], node)[leaf] = v
    return example


def _blank(cell: Any) -> bool:
    if isinstance(cell, list):
        return all(_blank(c) for c in cast(list[Any], cell))
    return cell is None


def fixture(spec: Mapping[str, Any], command: Command) -> dict[str, Any]:
    return {
        "source": "generated",
        "operation": command.operation.operation_id,
        "body": body(spec, command),
    }


def dumps(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def path_of(root: Path, command: Command) -> Path:
    return root / command.domain / f"{command.name}.json"


def plan(
    registry: Registry, spec: Mapping[str, Any], root: Path, domain: str | None = None
) -> tuple[dict[Path, str], list[Path]]:
    """(path → wanted content for every generated fixture, recorded fixtures kept)."""
    wanted: dict[Path, str] = {}
    kept: list[Path] = []
    for d in registry.domains.values():
        if domain is not None and d.name != domain:
            continue
        for command in d.commands.values():
            if command.operation is None:
                continue  # a handler command has no one response; tests/handlers cover it
            path = path_of(root, command)
            if _recorded(path):
                kept.append(path)
                continue
            wanted[path] = dumps(fixture(spec, command))
    return wanted, kept


def _recorded(path: Path) -> bool:
    """A readable fixture made by sanitize-fixture.py. A malformed file is regenerated."""
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and cast(dict[str, Any], doc).get("source") == "recorded"


def problems(
    registry: Registry, wanted: Mapping[Path, str], root: Path, domain: str | None = None
) -> list[str]:
    out = [
        f"{p.relative_to(root)}: {'missing' if not p.exists() else 'out of date'}"
        for p, text in wanted.items()
        if not p.exists() or p.read_text() != text
    ]
    known = {
        path_of(root, c)
        for d in registry.domains.values()
        for c in d.commands.values()
        if c.operation is not None
    }
    out += [
        f"{p.relative_to(root)}: no such command"
        for p in sorted(root.glob(f"{domain or '*'}/*.json"))
        if p not in known
    ]
    return out


@functools.cache
def _inputs() -> tuple[Registry, dict[str, Any]]:
    return load_registry(load_spec()), raw_spec()


def main(argv: list[str] | None = None, root: Path = FIXTURES) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--domain", help="only this registry domain")
    parser.add_argument("--check", action="store_true", help="write nothing; report drift")
    args = parser.parse_args(argv)
    try:
        registry, spec = _inputs()
    except (SpecError, RegistryError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.domain is not None and args.domain not in registry.domains:
        print(f"error: no registry domain {args.domain}", file=sys.stderr)
        return 2
    try:
        wanted, kept = plan(registry, spec, root, args.domain)
    except (SpecError, KeyError) as e:  # A $ref/allOf cycle, or a path the raw spec lacks.
        print(f"error: {e!r}", file=sys.stderr)
        return 2
    if args.check:
        found = problems(registry, wanted, root, args.domain)
        for line in found:
            print(line)
        return 1 if found else 0
    for path, text in wanted.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text:
            path.write_text(text)
            print(f"wrote {path.relative_to(root)}")
    for path in kept:
        print(f"kept {path.relative_to(root)} (recorded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
