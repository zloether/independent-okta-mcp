"""Every registry command has a fixture that fits it (design §14).

Generated fixtures must match what scripts/gen-fixtures.py makes from the pinned spec today:
after a spec or registry change, re-run it and commit the diff. Recorded ones (sanitize-fixture.py)
are only checked for shape.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from okta_mcp.exec.output import columns, load_scrub, render
from okta_mcp.registry.loader import Command, load_registry
from okta_mcp.registry.spec import load_spec

FIXTURES = Path(__file__).parent
SCRIPTS = Path(__file__).parents[2] / "scripts"


def _gen() -> ModuleType:
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("gen_fixtures", SCRIPTS / "gen-fixtures.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _gen()
REGISTRY = load_registry(load_spec())
# Simple commands: a handler command has no one response (tests/handlers covers those).
COMMANDS = [
    c for d in REGISTRY.domains.values() for c in d.commands.values() if c.operation is not None
]
RULES = load_scrub()


def test_generated_fixtures_are_current() -> None:
    wanted, _ = gen.plan(REGISTRY, gen.raw_spec(), FIXTURES)
    assert gen.problems(REGISTRY, wanted, FIXTURES) == [], (
        "run `uv run python scripts/gen-fixtures.py` and commit the result"
    )


def _load(command: Command) -> dict[str, Any]:
    path = FIXTURES / command.domain / f"{command.name}.json"
    assert path.exists(), f"no fixture for {command.domain} {command.name}"
    return cast(dict[str, Any], json.loads(path.read_text()))


def _blank(cell: Any) -> bool:
    """No value: `pick` gives a list through an array, so `[]` and `[None]` are blank too."""
    if isinstance(cell, list):
        return all(_blank(c) for c in cast(list[Any], cell))
    return cell is None


def _item_fields(command: Command) -> frozenset[str]:
    """Declared fields of one list item: the wrapped list's for an `items_key` command."""
    response = command.operation.response
    override = command.entry.response_override
    if command.entry.items_key is not None and not (override and override.kind == "wrapped"):
        return response.item_fields.get(command.entry.items_key, frozenset())
    return response.fields


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: f"{c.domain}-{c.name}")
def test_fixture_fits_command(command: Command) -> None:
    doc = _load(command)
    assert set(doc) == {"source", "operation", "body"}
    assert doc["source"] in ("generated", "recorded")
    assert doc["operation"] == command.operation.operation_id
    body = doc["body"]
    entry = command.entry
    if not command.is_list:
        assert isinstance(body, dict)
        items: list[Any] = [body]
    elif entry.items_key is not None:
        assert isinstance(body, dict)
        items = cast(dict[str, Any], body)[entry.items_key]
    else:
        assert isinstance(body, list)
        items = cast(list[Any], body)
    assert isinstance(items, list) and items, "a fixture needs at least one item"
    cols = columns(None, entry.view)
    rows: list[Any] = []
    for item in items:
        # Only items whose schema declares no properties may be plain values (interclient
        # app IDs are strings).
        assert isinstance(item, dict) or not _item_fields(command)
        rows.append(render(item, RULES, links=False, cols=cols))
        assert render(item, RULES, links=True, cols=None)
    if cols is not None:
        empty = [c for i, c in enumerate(cols) if all(_blank(row[i]) for row in rows)]
        assert not empty, f"no item has the view paths {empty}"
