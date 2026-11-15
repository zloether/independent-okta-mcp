#!/usr/bin/env python3
"""Coverage report: okta-skills catalogue vs registry vs pinned spec (design §5.6).

    uv run python scripts/coverage-report.py [--catalogue PATH] [--out PATH]

Reads docs/coverage/catalogue.yaml, the packaged registry and the pinned spec, and writes
docs/coverage/report.md. A simple or resolved catalogue entry is done when its domain's registry
has a command for each of its operations; composite entries are deferred past v1. Also lists
registry commands outside the catalogue and spec GET operations neither covers. Informational,
not a CI gate. Exit status: 0 when written, 2 when the catalogue or registry is invalid.
"""

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from okta_mcp.registry.loader import Registry, RegistryError, UniqueKeyLoader, load_registry
from okta_mcp.registry.spec import Operation, SpecError, SpecIndex, load_spec

DOCS = Path(__file__).parents[1] / "docs" / "coverage"
CATALOGUE = DOCS / "catalogue.yaml"
REPORT = DOCS / "report.md"
KINDS = ("simple", "resolved", "composite", "excluded")
PAGINATE = ("link", "body_links", "link_or_body", "none")
KEYS = {"operations", "kind", "paginate", "items_key", "gotcha", "notes", "reason"}


class CatalogueError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


def parse_catalogue(doc: Any, spec: SpecIndex) -> dict[str, dict[str, dict[str, Any]]]:
    """domain → command → entry, after checking every entry; all problems are raised together."""
    if not (isinstance(doc, dict) and set(doc) == {"domains"} and isinstance(doc["domains"], dict)):
        raise CatalogueError(["catalogue must be a mapping with only a `domains` mapping"])
    errors: list[str] = []
    for domain, commands in doc["domains"].items():
        if not isinstance(commands, dict):
            errors.append(f"{domain}: must map command names to entries")
            continue
        for name, e in commands.items():
            errors += [f"{domain} {name}: {m}" for m in _entry_errors(e, spec)]
    if errors:
        raise CatalogueError(errors)
    return doc["domains"]


def _entry_errors(e: Any, spec: SpecIndex) -> list[str]:
    if not isinstance(e, dict):
        return ["must be a mapping"]
    errors: list[str] = []
    if unknown := sorted(set(e) - KEYS):
        errors.append(f"unknown keys: {', '.join(unknown)}")
    kind = e.get("kind")
    if kind not in KINDS:
        errors.append(f"kind must be one of {', '.join(KINDS)}")
    ops = e.get("operations")
    if not (isinstance(ops, list) and ops and all(isinstance(o, str) for o in ops)):
        errors.append("operations must be a non-empty list of operationIds")
    else:
        errors += [
            f"{o} is not a GET operation in the pinned spec"
            for o in ops
            if o not in spec.operations
        ]
    if kind == "excluded" and not e.get("reason"):
        errors.append("excluded needs a reason")
    if kind != "excluded" and "reason" in e:
        errors.append("only excluded entries take a reason")
    if "paginate" in e and e["paginate"] not in PAGINATE:
        errors.append(f"paginate must be one of {', '.join(PAGINATE)}")
    elif kind in ("simple", "resolved") and not errors:
        errors += _shape_errors(e, spec.operations[ops[0]])
    return errors


def _shape_errors(e: dict[str, Any], op: Operation) -> list[str]:
    """`paginate` and `items_key` must still match the spec, which they were derived from."""
    errors: list[str] = []
    items_key = e.get("items_key")
    if items_key is not None and items_key not in (
        *op.response.item_fields,
        *op.response.scalar_lists,
    ):
        errors.append(f"items_key {items_key} is not a list property of {op.operation_id}")
    # As in the registry loader: `after` pages; `_links.next` pages only on a list command.
    is_list = op.response.kind == "list" or items_key is not None
    pages = "after" in op.params or (is_list and op.response.links_next)
    paginate = e.get("paginate", "none")
    if (paginate != "none") != pages:
        errors.append(
            f"paginate {paginate} but {op.operation_id} {'pages' if pages else 'does not page'}"
        )
    elif (paginate == "link_or_body") != (pages and items_key is not None):
        errors.append("link_or_body goes with items_key on a paginated operation")
    return errors


def statuses(
    catalogue: dict[str, dict[str, dict[str, Any]]], registry: Registry
) -> dict[tuple[str, str], str]:
    registered = {
        (d.name, c.operation.operation_id)
        for d in registry.domains.values()
        for c in d.commands.values()
        if c.operation is not None
    }
    status: dict[tuple[str, str], str] = {}
    for domain, commands in catalogue.items():
        for name, e in commands.items():
            if e["kind"] == "excluded":
                status[domain, name] = "excluded"
            elif e["kind"] == "composite":
                status[domain, name] = "deferred"
            else:
                done = all((domain, o) in registered for o in e["operations"])
                status[domain, name] = "done" if done else "todo"
    return status


def render(
    catalogue: dict[str, dict[str, dict[str, Any]]], registry: Registry, spec: SpecIndex
) -> str:
    status = statuses(catalogue, registry)
    entries = [(d, n, e) for d, cmds in catalogue.items() for n, e in cmds.items()]
    kinds = Counter(e["kind"] for _, _, e in entries)
    done = Counter(e["kind"] for d, n, e in entries if status[d, n] == "done")
    lines = [
        "# Coverage report",
        "",
        "Generated by `scripts/coverage-report.py` from `docs/coverage/catalogue.yaml`,",
        f"the registry and the pinned spec {spec.version}. Do not edit; rerun the script.",
        "",
        "## Summary",
        "",
        "| Kind | Commands | Done |",
        "|---|---|---|",
    ]
    for kind in KINDS:
        label = "composite (post-v1)" if kind == "composite" else kind
        shown = done[kind] if kind in ("simple", "resolved") else "—"
        lines.append(f"| {label} | {kinds[kind]} | {shown} |")
    lines += [f"| **total** | **{len(entries)}** | **{done.total()}** |", ""]
    gotchas = [
        (d, n) for d, n, e in entries if e.get("gotcha") and e["kind"] in ("simple", "resolved")
    ]
    todo_gotchas = sum(status[k] == "todo" for k in gotchas)
    lines += [f"Gotcha endpoints (record a fixture): {len(gotchas)}, {todo_gotchas} to do", ""]

    lines += [
        "## By domain",
        "",
        "| Domain | Catalogue | Simple | Resolved | Composite | Excluded | Done | To do |",
        "|---|---|---|---|---|---|---|---|",
    ]
    todo: dict[str, list[str]] = defaultdict(list)
    for domain in sorted(catalogue):
        cmds = catalogue[domain]
        k = Counter(e["kind"] for e in cmds.values())
        s = Counter(status[domain, n] for n in cmds)
        todo[domain] = [n for n in cmds if status[domain, n] == "todo"]
        counts = " | ".join(str(k[kind]) for kind in KINDS)
        lines.append(f"| {domain} | {len(cmds)} | {counts} | {s['done']} | {s['todo']} |")
    lines += ["", "## To do", ""]
    lines += [f"- **{d}**: {', '.join(cmds)}" for d, cmds in todo.items() if cmds] or ["None."]

    catalogued = {(d, o) for d, _, e in entries for o in e["operations"]}
    extra = sorted(
        (d.name, c.name, c.operation.operation_id)
        for d in registry.domains.values()
        for c in d.commands.values()
        if c.operation is not None and (d.name, c.operation.operation_id) not in catalogued
    )
    lines += ["", "## Registry commands outside the catalogue", ""]
    if extra:
        lines += ["| Domain | Command | Operation |", "|---|---|---|"]
        lines += [f"| {d} | {n} | `{o}` |" for d, n, o in extra]
    else:
        lines.append("None.")

    covered = {o for _, o in catalogued} | {
        c.operation.operation_id
        for d in registry.domains.values()
        for c in d.commands.values()
        if c.operation is not None
    }
    by_tag: dict[str, list[str]] = defaultdict(list)
    for op_id, op in spec.operations.items():
        if op_id not in covered:
            by_tag[op.tags[0] if op.tags else "(untagged)"].append(op_id)
    total = f"{sum(len(v) for v in by_tag.values())} of {len(spec.operations)}"
    lines += [
        "",
        f"## Spec GET operations not in the catalogue or registry ({total})",
        "",
        "| Tag | Operations |",
        "|---|---|",
    ]
    lines += [
        f"| {tag} | {', '.join(f'`{o}`' for o in sorted(ops))} |"
        for tag, ops in sorted(by_tag.items())
    ]
    return "\n".join(lines) + "\n"


def run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--catalogue", type=Path, default=CATALOGUE)
    parser.add_argument("--out", type=Path, default=REPORT)
    args = parser.parse_args(argv)
    try:
        spec = load_spec()
        doc = yaml.load(args.catalogue.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
        catalogue = parse_catalogue(doc, spec)
        registry = load_registry(spec)
    except (CatalogueError, RegistryError, SpecError, yaml.YAMLError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    args.out.write_text(render(catalogue, registry, spec))
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
