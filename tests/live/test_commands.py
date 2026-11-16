"""Checks 2 and 3 (plan 8.2.1): every registry command once, against the live org.

**Check 2.** Each command runs through `Tools` and the executor as `platform-admin` (every
command, sensitive ones too). Fails on: Okta's `E0000006` (the service app's admin role is too
narrow: keeps V6 current), `invalid_arguments` or `internal_error` on args built from the
registry, and a view field missing from every item returned. Paging is checked on the seeded
paging group, both raw (`paginate` with a small page) and through the executor's cursors.

**Check 3.** Live keys against the pinned spec's schema. Fails on a key the spec doesn't have
whose name looks secret- or credential-like and whose value isn't redacted (V14); reports
other new keys.

Path IDs come from the seed data where the path is a seeded object's (`/users/{}`,
`/groups/{}`, `/apps/{}`, `/policies/{}`, `/groups/rules/{}`), else from the first item of the
list command one path segment up (`/authorizationServers/{}/credentials/keys/{}` takes a key
from `…/credentials/keys`). A command whose IDs can't be found (an empty list, a list Okta
refuses) is skipped and reported, not failed: the org has no such object.

The report (`OKTA_LIVE_REPORT`, a JSON file) holds command names, codes, counts and key names.
Never values.
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from _live import PAGING_SIZE, Call, Refusals, Seeds

from okta_mcp.exec.output import REDACTED
from okta_mcp.okta.paginate import paginate
from okta_mcp.registry.loader import Command, Registry, load_registry
from okta_mcp.registry.spec import load_spec

pytestmark = pytest.mark.anyio

_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_SECRET_LIKE = re.compile(
    r"secret|password|passwd|private|apikey|api_key|credential|^key$|^token$|_token$|token_value",
    re.IGNORECASE,
)
_SKIP_KEYS = ("_links", "_embedded")
# Args the sweep fills when a command requires them and the registry closes their values.
_REQUIRED_DEFAULTS = {("policies", "list", "type"): "PASSWORD"}

REGISTRY: Registry = load_registry(load_spec())
COMMANDS: list[Command] = [
    c
    for d in REGISTRY.domains.values()
    for c in d.commands.values()
    if c.handler is None and c.operation is not None
]


def _shape(path: str) -> str:
    return _PLACEHOLDER.sub("{}", path)


LISTS: dict[str, Command] = {}
for _c in COMMANDS:
    if _c.is_list and _c.operation is not None:
        LISTS.setdefault(_shape(_c.operation.path), _c)


@dataclass
class Sweep:
    ran: list[str] = field(default_factory=list[str])
    skipped: dict[str, str] = field(default_factory=dict[str, str])
    failed: dict[str, str] = field(default_factory=dict[str, str])
    """Command → why it fails check 2. Names and codes only."""
    upstream: dict[str, str] = field(default_factory=dict[str, str])
    """Command → an error code Okta or the executor gave that isn't a check-2 failure."""
    missing_view: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    secret_like: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    new_keys: dict[str, list[str]] = field(default_factory=dict[str, list[str]])


class Ids:
    """Path-parameter values, found once per concrete prefix."""

    def __init__(self, call: Call, seeds: Seeds) -> None:
        self._call = call
        self._cache: dict[str, str | None] = {
            "/api/v1/users": seeds.user_id,
            "/api/v1/groups": seeds.group_id,
            "/api/v1/apps": seeds.app_id,
            "/api/v1/policies": seeds.policy_id,
            "/api/v1/groups/rules": seeds.rule_id,
        }
        self.why: str = ""

    async def path_values(self, template: str) -> list[str] | None:
        """A value for each placeholder of `template`, in order, or None (`why` says which
        prefix had none)."""
        values: list[str] = []
        for m in _PLACEHOLDER.finditer(template):
            prefix_template = template[: m.start()].rstrip("/")
            prefix = _fill(prefix_template, values)
            if prefix not in self._cache:
                self._cache[prefix] = await self._first_id(prefix_template, values)
            value = self._cache[prefix]
            if value is None:
                self.why = f"no id under {_shape(prefix_template)}"
                return None
            values.append(value)
        return values

    async def _first_id(self, prefix_template: str, values: list[str]) -> str | None:
        lister = LISTS.get(_shape(prefix_template))
        if lister is None or lister.operation is None:
            return None
        args = _args_for(lister, values)
        if args is None:
            return None
        result = await self._call(lister.domain, lister.name, args, select="*", limit=1)
        if not result.ok:
            return None
        items = result.body.get("items") or []
        first = items[0] if items else None
        if isinstance(first, dict):
            value = first.get("id") or first.get("kid")  # pyright: ignore[reportUnknownMemberType]
            return value if isinstance(value, str) else None
        return None


def _fill(template: str, values: list[str]) -> str:
    it = iter(values)
    return _PLACEHOLDER.sub(lambda _m: next(it), template)


def _args_for(command: Command, values: list[str]) -> dict[str, Any] | None:
    """The command's args: its path params from `values` (in template order), and any other
    required arg the sweep knows a value for. None if one is required and unknown."""
    assert command.operation is not None
    names = _PLACEHOLDER.findall(command.operation.path)
    by_param = {a.path_param: n for n, a in command.entry.args.items() if a.path_param}
    args: dict[str, Any] = {}
    for param, value in zip(names, values, strict=True):
        if param not in by_param:
            return None
        args[by_param[param]] = value
    for name, arg in command.entry.args.items():
        if arg.required and not arg.path_param and name not in args:
            default = _REQUIRED_DEFAULTS.get((command.domain, command.name, name))
            if default is None and arg.allowed_values:
                default = arg.allowed_values[0]
            if default is None:
                return None
            args[name] = default
    return args


def _paths(value: Any, prefix: str = "") -> dict[str, Any]:
    """Dotted key paths of an object's leaves (arrays are leaves, as in the spec index)."""
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for k, v in value.items():  # pyright: ignore[reportUnknownVariableType]
            key = str(k)  # pyright: ignore[reportUnknownArgumentType]
            if not prefix and key in _SKIP_KEYS:
                continue
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(v, dict) and v:
                out |= _paths(v, path)
            else:
                out[path] = v
    return out


def _spec_fields(command: Command) -> frozenset[str]:
    assert command.operation is not None
    response = command.operation.response
    if command.entry.items_key:
        return response.item_fields.get(command.entry.items_key, frozenset())
    return response.fields


def _known(path: str, spec: frozenset[str]) -> bool:
    """In the spec, or under a spec leaf (a free-form object such as a custom `profile`)."""
    return path in spec or any(path.startswith(f + ".") for f in spec)


def _present(view_field: str, paths: dict[str, Any]) -> bool:
    """A view field is in an item: as a leaf, or as an object with leaves under it."""
    return view_field in paths or any(p.startswith(view_field + ".") for p in paths)


def _items(body: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(body.get("item"), dict):
        return [body["item"]]
    return [i for i in body.get("items") or [] if isinstance(i, dict)]


def _report(sweep: Sweep) -> None:
    target = os.environ.get("OKTA_LIVE_REPORT")
    if not target:
        return
    Path(target).write_text(json.dumps(sweep.__dict__, indent=1, sort_keys=True))


async def test_every_command(call: Call, seeds: Seeds, refusals: Refusals) -> None:
    ids = Ids(call, seeds)
    sweep = Sweep()
    for command in COMMANDS:
        name = f"{command.domain} {command.name}"
        assert command.operation is not None
        values = await ids.path_values(command.operation.path)
        if values is None:
            sweep.skipped[name] = ids.why
            continue
        args = _args_for(command, values)
        if args is None:
            sweep.skipped[name] = "a required arg the sweep can't fill"
            continue
        seen = len(refusals.codes)
        result = await call(command.domain, command.name, args, select="*", limit=3)
        codes = refusals.codes[seen:]
        sweep.ran.append(name)
        if "E0000006" in codes:
            sweep.failed[name] = "E0000006: the service app's admin role is too narrow"
            continue
        if not result.ok:
            if result.code in ("invalid_arguments", "internal_error"):
                sweep.failed[name] = str(result.code)
            else:
                sweep.upstream[name] = f"{result.code} {','.join(c or '-' for c in codes)}".strip()
            continue
        items = _items(result.body)
        if not items:
            continue
        found = [_paths(i) for i in items]
        view = command.entry.view or ()
        absent = [v for v in view if not any(_present(v, f) for f in found)]
        if absent:
            sweep.missing_view[name] = absent
        spec = _spec_fields(command)
        new: set[str] = set()
        for paths in found:
            for path, value in paths.items():
                if _known(path, spec):
                    continue
                new.add(path)
                leaf = path.rsplit(".", 1)[-1]
                if _SECRET_LIKE.search(leaf) and value not in (None, "", REDACTED):
                    sweep.secret_like.setdefault(name, []).append(path)
        if new:
            sweep.new_keys[name] = sorted(new)
    _report(sweep)
    print(
        f"ran {len(sweep.ran)}, skipped {len(sweep.skipped)}, "
        f"upstream errors {len(sweep.upstream)}, new keys in {len(sweep.new_keys)} commands"
    )
    assert len(sweep.ran) > 0, "no command ran"
    assert not sweep.failed, f"check 2 failures: {sweep.failed}"
    assert not sweep.missing_view, f"view fields missing from every item: {sweep.missing_view}"
    assert not sweep.secret_like, f"unredacted secret-like new keys: {sweep.secret_like}"


async def test_paging_raw(okta: tuple[Any, Any, list[Any]], org_url: str, seeds: Seeds) -> None:
    """A small page size over the seeded paging group follows `next` to every member."""
    _provider, client, sent = okta
    command = REGISTRY.domains["groups"].commands["get-members"]
    assert command.operation is not None
    url = org_url + _fill(command.operation.path, [seeds.paging_group_id])
    before = len(sent)
    ids: list[str] = []
    async for item, _state, _index in paginate(client, url, {"limit": "10"}, mode="link"):
        if isinstance(item, dict) and isinstance(item.get("id"), str):  # pyright: ignore[reportUnknownMemberType]
            ids.append(item["id"])  # pyright: ignore[reportUnknownArgumentType]
    pages = len(sent) - before
    assert len(ids) == PAGING_SIZE, f"members read: {len(ids)}, seeded: {PAGING_SIZE}"
    assert len(set(ids)) == len(ids), "a member came back twice"
    assert pages >= -(-PAGING_SIZE // 10), f"pages fetched: {pages}"


async def test_paging_cursor(call: Call, seeds: Seeds) -> None:
    """Through the executor: a `limit` under the group's size gives a cursor, and resuming
    reads every member exactly once."""
    args = {"group": seeds.paging_group_id}
    ids: list[str] = []
    cursor: str | None = None
    for _ in range(PAGING_SIZE):
        result = await call("groups", "get-members", args, select="id", limit=10, cursor=cursor)
        assert result.ok, f"get-members failed: {result.code}"
        ids += [r[0] for r in result.body.get("rows", [])]
        cursor = result.body.get("next_cursor")
        if cursor is None:
            break
    assert len(ids) == PAGING_SIZE, f"members read: {len(ids)}, seeded: {PAGING_SIZE}"
    assert len(set(ids)) == len(ids), "a member came back twice"
