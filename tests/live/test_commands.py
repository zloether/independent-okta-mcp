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
refuses) is skipped and reported, not failed: the org has no such object. Likewise a command
Okta answers with `E0000015` (the org lacks the feature) is reported, not failed.

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
from _hygiene import redact_ids
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
# Args the sweep always sends: Okta requires them though the spec doesn't mark them required.
_DEFAULTS = {("policies", "list", "type"): "PASSWORD"}
# Path values the list one segment up can't give: `list-log-stream-schemas` items name their
# type only inside `$id`, and their `type` is the JSON Schema's (`object`). From the spec's
# `LogStreamType` enum.
_PATH_VALUES = {("schemas", "get-log-stream-schema"): ["aws_eventbridge"]}
# Not called at all on the CI org (user decision, 2026-11-22): it will never have what these
# need, so a refusal would say nothing about the server.
_NOT_RUN = {
    ("org-settings", "list-support-cases"): "needs an Okta support contract (plan 5.5)",
    # The CI org doesn't offer these scopes, so the server refuses them before calling Okta.
    ("device-integrations", "list"): "org doesn't offer okta.deviceIntegrations.read",
    ("realms", "list"): "org doesn't offer okta.realms.read",
    ("realms", "list-assignments"): "org doesn't offer okta.realmAssignments.read",
    ("realms", "list-operations"): "org doesn't offer okta.realmAssignments.read",
    ("security", "get-bot-protection-config"): "org doesn't offer okta.botProtection.read",
    ("users", "get-risk"): "org doesn't offer okta.userRisk.read",
}
# A failure here is the harness's or the config's, not the org's: it fails check 2.
_FATAL = ("invalid_arguments", "internal_error", "unavailable", "rate_limited", "timeout")
_ID_KEYS = ("id", "kid", "client_id", "type", "label", "name", "contactType")
"""Where a list item keeps the value its child path takes, tried in order after the
placeholder's own name (`{clientId}` → `clientId`, `client_id`)."""

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
    ok: list[str] = field(default_factory=list[str])
    skipped: dict[str, str] = field(default_factory=dict[str, str])
    failed: dict[str, str] = field(default_factory=dict[str, str])
    """Command → why it fails check 2. Names and codes only."""
    upstream: dict[str, str] = field(default_factory=dict[str, str])
    feature_off: list[str] = field(default_factory=list[str])
    """Commands Okta answered with `E0000015`: the org lacks the feature (reported, like a
    command with no object to read, not failed)."""
    """Command → an error code Okta or the executor gave that isn't a check-2 failure."""
    missing_view: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    """View fields absent from every item and unknown to the spec: a registry bug (fails)."""
    unseen_view: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    """View fields absent from every item but in the spec: null or empty here, so pruned
    (reported)."""
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
                self._cache[prefix] = await self._first_id(prefix_template, values, m.group(1))
            value = self._cache[prefix]
            if value is None:
                self.why = f"no id under {_shape(prefix_template)}"
                return None
            values.append(value)
        return values

    async def _first_id(self, prefix_template: str, values: list[str], param: str) -> str | None:
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
        if not isinstance(first, dict):
            return None
        for key in (param, _snake(param), *_ID_KEYS):
            value = first.get(key)  # pyright: ignore[reportUnknownMemberType]
            if isinstance(value, str) and value:
                return value
        return None


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", name).lower()


def _fill(template: str, values: list[str]) -> str:
    it = iter(values)
    return _PLACEHOLDER.sub(lambda _m: next(it), template)


def _args_for(command: Command, values: list[str]) -> dict[str, Any] | None:
    """The command's args: its path params from `values` (in template order), `_DEFAULTS`, and
    any other required arg with a closed set of values. None if one is required and unknown."""
    assert command.operation is not None
    names = _PLACEHOLDER.findall(command.operation.path)
    by_param = {a.path_param: n for n, a in command.entry.args.items() if a.path_param}
    args: dict[str, Any] = {}
    for param, value in zip(names, values, strict=True):
        if param not in by_param:
            return None
        args[by_param[param]] = value
    for name, arg in command.entry.args.items():
        if arg.path_param or name in args:
            continue
        default = _DEFAULTS.get((command.domain, command.name, name))
        if default is None and arg.required and arg.allowed_values:
            default = arg.allowed_values[0]
        if default is not None:
            args[name] = default
        elif arg.required:
            return None
    return args


def _paths(value: Any, prefix: str = "", *, links: bool = False) -> dict[str, Any]:
    """Dotted key paths of an object's leaves (arrays are leaves, as in the spec index).
    `_links` and `_embedded` are left out unless `links`."""
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for k, v in value.items():  # pyright: ignore[reportUnknownVariableType]
            key = str(k)  # pyright: ignore[reportUnknownArgumentType]
            if not prefix and key in _SKIP_KEYS and not links:
                continue
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(v, dict) and v:
                out |= _paths(v, path, links=links)
            else:
                out[path] = v
    return out


def _spec_fields(command: Command) -> frozenset[str]:
    assert command.operation is not None
    response = command.operation.response
    if command.entry.items_key and command.entry.items_key in response.item_fields:
        return response.item_fields[command.entry.items_key]
    # A `response_override: wrapped` command: the spec says a bare list, whose item schema
    # is `fields`.
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
    # The workflow copies this into the run summary, which pytest's report hook doesn't see.
    Path(target).write_text(redact_ids(json.dumps(sweep.__dict__, indent=1, sort_keys=True)))


async def test_every_command(call: Call, seeds: Seeds, refusals: Refusals) -> None:
    ids = Ids(call, seeds)
    sweep = Sweep()
    for command in COMMANDS:
        name = f"{command.domain} {command.name}"
        assert command.operation is not None
        if why := _NOT_RUN.get((command.domain, command.name)):
            sweep.skipped[name] = why
            continue
        values = _PATH_VALUES.get((command.domain, command.name))
        if values is None:
            values = await ids.path_values(command.operation.path)
        if values is None:
            sweep.skipped[name] = ids.why
            continue
        args = _args_for(command, values)
        if args is None:
            sweep.skipped[name] = "a required arg the sweep can't fill"
            continue
        seen = len(refusals.codes)
        # links: a view may name a `_links` href, which `links=False` would strip.
        result = await call(command.domain, command.name, args, select="*", limit=3, links=True)
        codes = refusals.codes[seen:]
        sweep.ran.append(name)
        if "E0000006" in codes:
            sweep.failed[name] = "E0000006: the service app's admin role is too narrow"
            continue
        if not result.ok and "E0000015" in codes:
            sweep.feature_off.append(name)
            continue
        if not result.ok:
            if result.code in _FATAL:
                sweep.failed[name] = str(result.code)
            else:
                sweep.upstream[name] = f"{result.code} {','.join(c or '-' for c in codes)}".strip()
            continue
        sweep.ok.append(name)
        items = _items(result.body)
        if not items:
            continue
        found = [_paths(i, links=True) for i in items]
        spec = _spec_fields(command)
        view = command.entry.view or ()
        absent = [v for v in view if not any(_present(v, f) for f in found)]
        if unknown := [v for v in absent if not _known(v, spec) and not v.startswith("_links.")]:
            sweep.missing_view[name] = unknown
        if seen_none := [v for v in absent if v not in unknown]:
            sweep.unseen_view[name] = seen_none
        found = [_paths(i) for i in items]
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
        f"ran {len(sweep.ran)}, answered {len(sweep.ok)}, skipped {len(sweep.skipped)}, "
        f"upstream errors {len(sweep.upstream)}, feature off {len(sweep.feature_off)}, "
        f"new keys in {len(sweep.new_keys)} commands"
    )
    assert sweep.ok, "no command was answered"
    assert not sweep.failed, f"check 2 failures: {sweep.failed}"
    assert not sweep.missing_view, f"view fields missing from every item: {sweep.missing_view}"
    assert not sweep.secret_like, f"unredacted secret-like new keys: {sweep.secret_like}"


async def test_paging_raw(okta: tuple[Any, Any, list[Any]], org_url: str, seeds: Seeds) -> None:
    """A small page size over the seeded paging group follows `next` to every member."""
    _provider, client, sent = okta
    command = REGISTRY.domains["groups"].commands["get-members"]
    assert command.operation is not None
    url = org_url + _fill(command.operation.path, [seeds.paging_group_id])
    path = _fill(command.operation.path, [seeds.paging_group_id])
    before = len(sent)
    ids: list[str] = []
    async for item, _state, _index in paginate(client, url, {"limit": "10"}, mode="link"):
        if isinstance(item, dict) and isinstance(item.get("id"), str):  # pyright: ignore[reportUnknownMemberType]
            ids.append(item["id"])  # pyright: ignore[reportUnknownArgumentType]
    # Requests to the members path only: token POSTs and nonce retries aren't pages.
    pages = len([r for r in sent[before:] if r.url.path == path])
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
