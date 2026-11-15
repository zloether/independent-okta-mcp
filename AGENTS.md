# AGENTS.md

Rules for agents working in this repo. Loaded every session: keep it to what every task needs.

`independent-okta-mcp` is a self-hosted, **read-only** MCP server for the Okta Management API. OAuth users (Okta custom authorization server) map by `groups` claim to roles in a YAML policy that decides which commands they may call; Okta is called with one service app (`private_key_jwt` + DPoP, `.read` scopes).

## Docs: read only what the task needs

| File | Read when |
|---|---|
| [`docs/implementation-plan.md`](docs/implementation-plan.md) | Starting or finishing a step: its status, checklist, Verify block and "How to work a step" |
| [`docs/decisions-log.md`](docs/decisions-log.md) | Before changing something a step decided (search by step ID); append a row for every decision and review outcome |
| [`docs/design/mcp-server.md`](docs/design/mcp-server.md) | Only the § refs the step names; update it in the same PR if the step changes the design |
| [`docs/agents/subagents.md`](docs/agents/subagents.md) | Before delegating to a subagent |
| [`docs/runbook.md`](docs/runbook.md), [`docs/okta-setup.md`](docs/okta-setup.md), [`docs/compatibility-matrix.md`](docs/compatibility-matrix.md), [`CHANGELOG.md`](CHANGELOG.md) | Changing operator-visible behavior (human docs: update them with it) |

## Working a step

Follow the plan's "How to work a step": tests first, update the plan's status and the decisions log. Every change gets **`/code-review`** before a PR is opened (or, on a branch with one, before it's called done); fix the findings or log why not, then re-run the checks. A change to a trust boundary (below) also gets **`/security-review`**; neither replaces the other. Re-run both on fix commits that touch a trust boundary. Log each review's outcome.

Done means these pass, plus the reviews:

```
uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
uv lock --check                           # lockfile committed and current
```

Other commands: `uv sync` (install), `uv run okta-mcp` (serve HTTP), `--stdio` (dev mode), `--check` (load config and policy, exit 0 or 2).

## Conventions

- **Read-only invariant.** The server never writes to Okta: the registry loader rejects non-GET operations and the Okta client exposes only `get`. Add no code path in `src/` that sends any other method. Only `scripts/okta-setup.py`, run separately by an Okta admin, creates objects; it never deletes or loosens anything.
- **Registry first.** A command is a YAML entry in `src/okta_mcp/data/registry/` naming an `operationId` from the pinned spec, not code. Every entry is classified (`data_classes`); sensitivity is derived, never declared. Code is only for composite handlers (`handler:` + `uses:`, design §5.6), which reach Okta only through `exec/composite.Context`.
- **Fail closed.** Unknown roles, unclassified commands, scope-less operations or an invalid policy expose nothing. No fallbacks that widen access.
- **Tests with every change.** HTTP is mocked. Fixtures use only `example.okta.com` (the org) and `*.example.com` (other hosts, emails).
- **Never log** tokens, keys or Okta result bodies.
- Python ≥3.12, fully async (`anyio`, `httpx2`); async tests use `@pytest.mark.anyio`.
- Package data (spec, registry, guides, `scrub.yaml`) lives under `src/okta_mcp/data/` so it ships in the wheel. `tests/` mirrors `src/`; `scripts/` holds developer tools.
- `../okta-skills` is **reference only** (design §3): nothing in `src/`, `tests/` or CI imports, runs or reads it. Re-implement with tests; copied prose keeps attribution.

## Documentation

One audience per doc: humans or agents. Complete, not verbose; link instead of repeating.

- **Human docs:** READMEs as short as possible (what it is, how to start, where to read more); depth in separate files under `docs/`.
- **Agent docs:** token-efficient. This file holds only rules every task needs; task-specific guidance gets its own file, listed in the table above with when to read it.
- **MCP guides** (`src/okta_mcp/data/resources/`) are read by the model calling the server: one per domain, short, checked by `tests/test_resources.py`.

## Trust boundaries

Hardest to undo (design §12.2); changes need `/security-review`, and their plan steps are marked 🔒.

- `src/okta_mcp/auth/`: JWT validation, PRM, 401/403, dev mode
- `src/okta_mcp/policy/`, registry classification fields, the data-class → sensitivity table, `data/scrub.yaml`: who may call what, what leaves the server
- `exec/params.py` and URL building, reserved path literals in `registry/spec.py`: path injection, sibling-endpoint aliasing
- `exec/resolve.py`: Okta lookups on user input
- `exec/composite.py`, `handlers/`, registry `uses` lists: what a composite command reaches and returns
- `exec/cursor.py`, `okta/paginate.py`: token-attached URL following
- `okta/token.py`, `okta/dpop.py`: service credentials
- `Dockerfile`, `docker/compose.example.yaml`: runtime privileges
- `scripts/okta-setup.py`, `terraform/okta/`: run with Super Admin; decide who gets tokens
