#!/usr/bin/env python3
"""Fetch and pin the Okta Management OpenAPI spec (design §6.1).

    uv run python scripts/update-spec.py [--ref REF]     # pin the latest spec on REF
    uv run python scripts/update-spec.py --check         # report only; writes nothing

Resolves REF (default: the upstream default branch) to the last commit that touched the spec,
downloads the file at that commit, and writes it with `PINNED.json` (URL, commit, version,
sha256, dates) under src/okta_mcp/data/specs/. Prints the GET operations added (+), removed (-)
or changed (~) against the current pin; a change to a component an operation uses counts.
Exit status: 0 when pinned or up to date, 1 when `--check` finds a newer spec, 2 on errors
(including, with `--check`, a local spec that doesn't match its pin; a re-pin replaces it).
"""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
import yaml

REPO = "okta/okta-management-openapi-spec"
SPEC_PATH = "dist/current/management-minimal.yaml"
SPEC_FILE = "management-minimal.yaml"
PIN_FILE = "PINNED.json"
SPEC_DIR = Path(__file__).parents[1] / "src" / "okta_mcp" / "data" / "specs"


class SpecError(Exception):
    pass


def parse(body: bytes) -> dict[str, Any]:
    try:
        spec = yaml.load(body, Loader=yaml.CSafeLoader)
    except yaml.YAMLError as e:
        raise SpecError(f"spec is not valid YAML: {e}") from e
    if not (
        isinstance(spec, dict)
        and "openapi" in spec
        and isinstance(spec.get("info"), dict)
        and isinstance(spec["info"].get("version"), str)
        and isinstance(spec.get("paths"), dict)
        and all(isinstance(item, dict) for item in spec["paths"].values())
    ):
        raise SpecError("download is not an OpenAPI document with info.version and paths")
    return spec


def _refs(node: Any) -> set[str]:
    """Refs into components. Others occur only as data (JSON Schema documents in examples)."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        found = {ref} if isinstance(ref, str) and ref.startswith("#/components/") else set()
        return found.union(*(_refs(v) for v in node.values()))
    if isinstance(node, list):
        return set().union(*(_refs(v) for v in node))
    return set()


def _target(spec: dict[str, Any], ref: str) -> Any:
    node: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise SpecError(f"dangling $ref: {ref}")
        node = node[part]
    return node


def get_operations(spec: dict[str, Any]) -> dict[str, str]:
    """operationId → canonical JSON of what defines the call: path, parameters, operation, and
    every component reachable from them through $ref (cycles end at a component already seen)."""
    ops: dict[str, str] = {}
    for path, item in spec["paths"].items():
        op = item.get("get")
        if op is None:
            continue
        if not (isinstance(op, dict) and isinstance(op.get("operationId"), str)):
            raise SpecError(f"GET {path} has no operationId")
        if op["operationId"] in ops:
            raise SpecError(f"duplicate operationId: {op['operationId']}")
        shape = {"path": path, "parameters": item.get("parameters", []), "operation": op}
        components: dict[str, Any] = {}
        todo = _refs(shape)
        while todo:
            ref = todo.pop()
            components[ref] = _target(spec, ref)
            todo |= _refs(components[ref]) - components.keys()
        shape["components"] = components
        ops[op["operationId"]] = json.dumps(shape, sort_keys=True, default=str)
    return ops


def diff(old: dict[str, str], new: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    changed = sorted(k for k in old.keys() & new.keys() if old[k] != new[k])
    return added, removed, changed


def print_diff(old: dict[str, Any] | None, new: dict[str, Any]) -> None:
    added, removed, changed = diff(get_operations(old) if old else {}, get_operations(new))
    for mark, names in (("+", added), ("-", removed), ("~", changed)):
        for name in names:
            print(f"  {mark} {name}")
    print(f"GET operations: {len(added)} added, {len(removed)} removed, {len(changed)} changed")


def load_pinned(spec_dir: Path) -> tuple[dict[str, Any], bytes] | None:
    pin_file, spec_file = spec_dir / PIN_FILE, spec_dir / SPEC_FILE
    if not pin_file.exists():
        return None
    pin = json.loads(pin_file.read_text())
    body = spec_file.read_bytes()
    if hashlib.sha256(body).hexdigest() != pin["sha256"]:
        raise SpecError(f"{spec_file} does not match the sha256 in {pin_file}")
    return pin, body


def fetch(http: httpx2.Client, ref: str | None) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    params = {"path": SPEC_PATH, "per_page": "1", **({"sha": ref} if ref else {})}
    response = http.get(
        f"https://api.github.com/repos/{REPO}/commits",
        params=params,
        headers={"Accept": "application/vnd.github+json"},
    )
    response.raise_for_status()
    commits = response.json()
    if not isinstance(commits, list):
        raise SpecError("GitHub commits lookup did not return a list")
    if not commits:
        raise SpecError(f"no commit on {ref or 'the default branch'} touches {SPEC_PATH}")
    commit = commits[0]
    url = f"https://raw.githubusercontent.com/{REPO}/{commit['sha']}/{SPEC_PATH}"
    response = http.get(url)
    response.raise_for_status()
    body = response.content
    spec = parse(body)
    pin = {
        "url": url,
        "commit": commit["sha"],
        "committed": commit["commit"]["committer"]["date"],
        "version": spec["info"]["version"],
        "sha256": hashlib.sha256(body).hexdigest(),
        "fetched": datetime.now(UTC).date().isoformat(),
    }
    return pin, body, spec


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def run(argv: list[str], http: httpx2.Client, spec_dir: Path = SPEC_DIR) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ref", help="branch, tag or commit to pin from")
    parser.add_argument("--check", action="store_true", help="report a newer spec; write nothing")
    args = parser.parse_args(argv)
    try:
        try:
            pinned = load_pinned(spec_dir)
        except SpecError as e:
            if args.check:
                raise
            print(f"warning: {e}; re-pinning without a diff", file=sys.stderr)
            pinned = None
        if args.check and pinned is None:
            raise SpecError(f"nothing pinned in {spec_dir}; run without --check first")
        pin, body, spec = fetch(http, args.ref)
        if pinned and pinned[0]["sha256"] == pin["sha256"]:
            print(f"Up to date: {pinned[0]['version']} ({pinned[0]['commit']})")
            return 0
        print(f"{'Newer spec' if args.check else 'Pinning'}: {pin['version']} ({pin['commit']})")
        print_diff(parse(pinned[1]) if pinned else None, spec)
        if args.check:
            return 1
        spec_dir.mkdir(parents=True, exist_ok=True)
        # Spec first, pin last: an interrupted run leaves a mismatch that a re-pin repairs.
        _write(spec_dir / SPEC_FILE, body)
        _write(spec_dir / PIN_FILE, (json.dumps(pin, indent=2) + "\n").encode())
    except (SpecError, OSError, httpx2.HTTPError, KeyError, TypeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    with httpx2.Client(timeout=60) as client:
        sys.exit(run(sys.argv[1:], client))
