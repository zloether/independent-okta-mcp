# AGENTS.md

Instructions for agents and contributors working in this repo.

## Purpose

`independent-okta-mcp` is a self-hosted, **read-only** MCP server for the Okta Management API. Users authenticate with OAuth (Okta custom authorization server); their `groups` claim maps to roles in a YAML policy that decides which domains and commands they may call. Okta is called with a shared service app (`private_key_jwt` + DPoP, read scopes).

- Design: [`docs/design/mcp-server.md`](docs/design/mcp-server.md) — what and why
- Plan: [`docs/implementation-plan.md`](docs/implementation-plan.md) — order of work, per-step verification, decisions log

Follow the plan's "How to work a step" section: branch `step/<id>-<slug>`, tests first, update the plan's status and decisions log, update the design doc in the same PR if the step changes it.

## Layout

```
src/okta_mcp/          package (layout in design §4.1)
  __main__.py          console script `okta-mcp`
  auth/ policy/ registry/ okta/ exec/   (added by later steps)
  data/                package data: specs/, registry/*.yaml, resources/, scrub.yaml
tests/                 pytest; mirrors src/ layout
scripts/               developer tools (spec pinning, coverage, fixtures)
docs/                  design, plan, coverage reports
```

Data files live under `src/okta_mcp/data/` so they ship in the wheel; the image installs with `uv sync --no-editable`.

## Commands

```
uv sync                                   # install runtime + dev deps
uv run okta-mcp                           # run the server entrypoint
uv run pytest                             # tests
uv run ruff check . && uv run ruff format --check .
uv run pyright                            # strict on src/
uv lock --check                           # lockfile is committed and must be current
```

A step is done only when all of these pass:

```
uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
```

## Conventions

- **Read-only invariant.** The server never writes to Okta. The registry loader rejects non-GET operations; the Okta HTTP client exposes only `get`. Do not add methods, flags or code paths in `src/` that issue any other HTTP method to Okta. The one exception is the admin tool `scripts/okta-setup.py`, which an Okta admin runs separately from the server; it creates objects and adds links but never deletes or loosens anything.
- **Registry first.** A command is a YAML entry in `src/okta_mcp/data/registry/` naming an Okta `operationId` from the pinned spec. Add or change commands there, not in code. Every entry must be classified (`data_classes`); sensitivity is derived, never declared. Code is only for post-v1 composite handlers.
- **Fail closed.** Unknown roles, unclassified commands, scope-less operations or invalid policy expose nothing. Don't add fallbacks that widen access.
- **Tests with every change.** New behavior comes with tests in the same change. HTTP is mocked; fixtures use reserved example domains only: `example.okta.com` for the Okta org, `*.example.com` for other hosts and for emails.
- **Never log** tokens, keys, or Okta result bodies.
- Python ≥3.12, fully async (`anyio`, `httpx2`). Async tests use anyio's pytest plugin (`@pytest.mark.anyio`).

## Trust boundaries

Mistakes in these paths are the hardest to undo (design §12.2). Code touching them must pass **`/security-review`** before it is considered complete; these steps are marked 🔒 in the plan.

- `src/okta_mcp/auth/` — JWT validation, Protected Resource Metadata, 401/403, dev mode
- `src/okta_mcp/policy/`, the classification fields in `src/okta_mcp/data/registry/*.yaml`, the data-class → sensitivity table, `src/okta_mcp/data/scrub.yaml` — who may call what; what leaves the server
- `src/okta_mcp/exec/params.py` and URL building — path-parameter injection
- `src/okta_mcp/exec/resolve.py` — runs Okta lookups on user input
- `src/okta_mcp/exec/cursor.py`, `src/okta_mcp/okta/paginate.py` — token-attached URL following
- `src/okta_mcp/okta/token.py`, `src/okta_mcp/okta/dpop.py` — service credential handling
- `Dockerfile`, `docker/compose.example.yaml` — runtime privileges
- `scripts/okta-setup.py`, `terraform/okta/` — run with a Super Admin credential; create the clients, policy, groups claim and service-app grants that decide who gets tokens

## okta-skills

`../okta-skills` is **reference only** (design §3). Nothing in `src/`, `tests/` or CI may import from, shell out to, or read files from it. Borrow ideas and endpoint gotchas; re-implement them here with tests. Copied prose keeps attribution.
