"""Check 4 (plan 8.2.1): how Okta routes paths that the §6.4 path rule refuses or allows.

The executor never sends these: they are raw requests through the bare client, to confirm what
the rule is built on. **Recorded** probes repeat the 2.10 dev-org check (2026-11-13, decisions
log) and must still answer as they did; if one changes, the rule in `exec/params.py` was built
on behavior Okta no longer has, so it needs a look either way. **Open** probes are the 8.1
change's untested cases: their answers go to the report (`OKTA_LIVE_REPORT_ROUTING`) and the
test output, so `_SUFFIX_IS_LITERAL` can be decided from them. Any probe answered with a JSON
**list** fails: a single-object path routed to a sibling collection is the aliasing §6.4 item 5
guards against.
"""

import contextlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from _hygiene import redact_ids
from _live import ANSWERS, DOMAIN, Seeds

from okta_mcp.okta.client import UpstreamError

pytestmark = pytest.mark.anyio


async def _probe(client: Any, org_url: str, path: str) -> tuple[int, str | None, str]:
    with contextlib.suppress(UpstreamError):  # a 4xx is an answer here
        await client.get(org_url + path)
    answer = ANSWERS.get(path)
    assert answer is not None, f"no answer recorded for probe {path}"
    return answer.status, answer.error_code, answer.kind


def _recorded(seeds: Seeds) -> dict[str, tuple[int, str | None]]:
    """Path → (status, errorCode) the 2.10 check saw."""
    return {
        # Matrix parameters are stripped: `00u…;x` is that user. The `;` refusal is load-bearing.
        f"/api/v1/users/{seeds.user_id};x": (200, None),
        # Suffixes are not: these are looked up as literals.
        f"/api/v1/users/{seeds.user_id}.json": (404, "E0000007"),
        "/api/v1/users/me.json": (404, "E0000007"),
        "/api/v1/groups/rules.json": (404, "E0000008"),
    }


def _open(seeds: Seeds) -> list[str]:
    return [
        f"/api/v1/users/me.smith@{DOMAIN}",
        "/api/v1/apps/export.csv",
        "/api/v1/policies/simulate.json",
        "/api/v1/users/me.",
        "/api/v1/groups/rules.",
        "/api/v1/users/.json",
        f"/api/v1/groups/{seeds.group_id}.",
    ]


def _label(path: str, seeds: Seeds) -> str:
    """`path` as printed: seeded IDs by role, any other Okta ID redacted."""
    path = path.replace(seeds.user_id, "<user>").replace(seeds.group_id, "<group>")
    return redact_ids(path)


async def test_routing(okta: tuple[Any, Any, list[Any]], org_url: str, seeds: Seeds) -> None:
    _provider, client, _sent = okta
    changed: dict[str, str] = {}
    lists: list[str] = []
    for path, (status, code) in _recorded(seeds).items():
        got = await _probe(client, org_url, path)
        if got[2] == "list":
            lists.append(_label(path, seeds))
        if got[:2] != (status, code):
            was, now = f"{status} {code or '-'}", f"{got[0]} {got[1] or '-'}"
            changed[_label(path, seeds)] = f"was {was}, now {now}"
    report: dict[str, str] = {}
    for path in _open(seeds):
        got = await _probe(client, org_url, path)
        if got[2] == "list":
            lists.append(_label(path, seeds))
        report[_label(path, seeds)] = f"{got[0]} {got[1] or '-'} ({got[2]})"
    # Paths with seeded IDs labeled by role and fixed literals only (no Okta IDs in logs).
    print("open routing probes:", json.dumps(report, indent=1))
    if target := os.environ.get("OKTA_LIVE_REPORT_ROUTING"):
        Path(target).write_text(json.dumps({"open": report, "changed": changed}, indent=1))
    assert not lists, f"a single-object path answered with a list: {lists}"
    assert not changed, f"Okta routes these differently than at the 2.10 check: {changed}"
