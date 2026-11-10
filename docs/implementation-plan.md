# Implementation Plan

Companion to [`design/mcp-server.md`](design/mcp-server.md) (r4). The design says *what* and *why*; this file says *in what order* and *how we know each step is done*. Work top to bottom; tick boxes as you go.

## How to work a step

1. Read the step's **Design** refs. If the step changes the design, update the design doc in the same PR.
2. Branch: `step/<id>-<slug>` (e.g. `step/2.6-url-builder`).
3. Write tests first (or alongside). Every step has a **Verify** block; it must pass locally and in CI.
4. Standard checks before calling a step done:
   ```
   uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
   ```
5. Steps marked **🔒 trust boundary** (design §12.2) must pass `/security-review` before merge.
6. Record anything learned that changes later steps in **Decisions log** (bottom). Resolve **Open questions** when their blocking step arrives.
7. Update the step's status in the table below.

Status key: ☐ todo · ◐ in progress · ☑ done · ⏸ blocked

## Status

| Phase | Steps | Status |
|---|---|---|
| 0. Bootstrap & spikes | 0.1–0.6 | ◐ |
| 1. Spec & registry core | 1.1–1.6 | ☑ |
| 2. Okta client & executor | 2.1–2.10 | ◐ |
| 3. Policy & tool surface | 3.1–3.4 | ☐ |
| 4. MCP server & auth | 4.1–4.6 | ☐ |
| 5. Registry authoring (all domains) | 5.0–5.7 | ☐ |
| 6. Audit, limits, logging | 6.1–6.2 | ☐ |
| 7. Packaging & deployment | 7.1–7.3 | ☐ |
| 8. Hardening & release | 8.1–8.4 | ☐ |

**Ordering note vs design §15:** the MCP server (Phase 4) comes *before* bulk registry authoring (Phase 5), so two pilot domains run end to end early and every later registry entry can be smoke-tested through the real server.

**Critical path:** 0.1 → 1.x → 2.x → 3.x → 4.x. The Okta dev-org spike (0.5) runs in parallel; only live checks (2.2 live item, 4.1 manual, 4.6) wait on it.

**Thin slice first (2026-11-03).** The pilot domains run in a real client over stdio before the rest of Phase 2 is built, so the T1 tool surface is tried on a model early. Slice order:

> 2.1 → 2.2 → 2.3 → 2.6 → 2.5 (`link` only) → 2.7 → 2.8 (no cursor) → 3.1 → 3.2 → 2.10 (no resolver) → 3.3 → **4.1**

Then: 2.4, the rest of 2.5 (`body_links`, `link_or_body`), 2.9, cursor resume in 2.8, the resolver in 2.10, 3.4, 4.2 onward. Slice parts of a step are marked **(slice)**; the step is ☑ only when all of it is done. 🔒 reviews run on each slice part as it merges, not deferred.

---

## Phase 0 — Bootstrap & spikes

### 0.1 Package skeleton ☑
Design: §4.1, §11.1 · Depends: —
- [x] `pyproject.toml`: `[project]` (name `okta-mcp`, `requires-python = ">=3.12"`, `license = { file = "LICENSE" }`, `readme = "README.md"`), console script `okta-mcp`, `dev` dependency group (`pytest`, `respx`, `ruff`, `pyright`, `pip-audit`); async tests via anyio's bundled pytest plugin
- [x] Runtime deps: `httpx`, `anyio`, `PyJWT[crypto]`, `pydantic`, `PyYAML`, `jsonschema`, `uvicorn`. `mcp` is added in 0.4 once the v2 version is chosen (exact pin)
- [x] `src/okta_mcp/__init__.py`, `__main__.py` (prints version, exits 0); `src/okta_mcp/data/` included as package data
- [x] Ruff, pyright (strict on `src/`), pytest config in `pyproject.toml`
- [x] `uv lock`; commit `uv.lock`
- [x] `tests/test_smoke.py` imports the package

Verify:
```
uv sync && uv run okta-mcp && uv run pytest && uv lock --check
```
Done when: standard checks pass on a clean clone.

### 0.2 AGENTS.md, CLAUDE.md, README ☑
Design: §12.2 · Depends: 0.1
- [x] `AGENTS.md`: purpose, layout, commands (sync/test/lint), conventions (read-only invariant, registry-first, tests with every change), **trust boundaries** list from design §12.2 with the `/security-review` rule, pointer to this plan, note that `okta-skills` is reference-only
- [x] `CLAUDE.md`: single line `@AGENTS.md`
- [x] `README.md`: one-paragraph description, status (pre-alpha), links to design + plan, license note

Verify: open a new Claude Code session and confirm AGENTS.md content is loaded (ask it for the trust boundaries).

### 0.3 CI ☑
Design: §14 (Hygiene row) · Depends: 0.1
- [x] `.github/workflows/ci.yml`: Python 3.12 + 3.13 + 3.14 matrix; `uv sync --frozen`; ruff check + format check; pyright; pytest; `uv lock --check`; `pip-audit`
- [x] Pin action versions by SHA

Verify: push the branch; workflow green on every Python version in the matrix.

### 0.3.1 Dependabot ☑
Design: §12.1 (Supply chain row) · Depends: 0.3
- [x] `.github/dependabot.yml`: `uv` and `github-actions` ecosystems, weekly, 14-day cooldown, minor+patch grouped per ecosystem (majors separate)
- [x] Repo settings: Dependabot alerts and security updates on (user)

Verify: GitHub shows the config parsed without errors (Insights → Dependency graph → Dependabot); `gh api repos/zloether/independent-okta-mcp/vulnerability-alerts` returns 204; `…/automated-security-fixes` reports `enabled: true`.

### 0.4 SDK spike (V5) ☑
Design: §5.2, §8.1, §16 V5 · Depends: 0.1
Throwaway code under `spikes/sdk/` (deleted at end of 4.2, together with the `spikes/**` ruff ignore in `pyproject.toml`). Run: `uv run pytest spikes/sdk`.
- [x] Choose and exact-pin `mcp` v2; confirm current protocol revision (2026-07-28 expected) and 2025-11-25 back-compat
- [x] Add a Dependabot `ignore` for `mcp` in `.github/dependabot.yml` (removed after 4.5)
- [x] Low-level server (`on_*` handlers) over stateless Streamable HTTP
- [x] Per-request principal from a fake `Authorization` header (SDK auth hooks or ASGI middleware + contextvar)
- [x] `tools/list` returns different tools for two fake principals, with `cacheScope: "private"` and `ttlMs`
- [x] Return `structuredContent` + text fallback; tool `annotations`
- [x] Evaluate the SDK's resource-server helpers (`token_verifier`/`auth`, `get_access_token()`): do they cover PRM at both URLs and the design §8.5 checks?
- [x] Decide `httpx` vs `httpx2` for the Okta client, and the matching HTTP mock for tests (`respx` mocks `httpx` only)

Verify: SDK client (both revisions) shows different tool lists for the two principals. Findings and choices recorded in Decisions log.

### 0.5 Okta dev-org spike — Path A and service app ☑
Design: §8.2–8.5, §10, Appendix C · Depends: — · **Needs: Okta dev org admin access (user-driven)**
Helpers under `spikes/okta/` (deleted with `spikes/sdk/` at end of 4.2). Run: `uv run pytest spikes/okta`; `uv run python spikes/okta/okta_spike.py --help`.
- [x] Create dedicated custom AS, scope `okta-mcp`, `groups` access-token claim emitting **IDs** of Okta-mastered `mcp-okta-*` groups, two test groups, two test users
- [x] `scripts/okta-setup.py` (`check`/`apply`) for admins, from the setup used here, and the equivalent `terraform/okta/` module; guide in `docs/okta-setup.md`
- [x] Register a public OIDC client (PKCE); obtain a token via a real MCP client or a local PKCE script
- [x] Record: claims present (`uid`, `sub`, `groups` as IDs, `cid`, `scp`) — **V1, V13**
- [x] Test `resource` param on authorize/token — **V9**
- [x] Test metadata discovery (OIDC discovery vs RFC 8414-only) and loopback redirect ports — **V10, V11**. Per-client discovery moved to the 4.6 compatibility matrix (needs the server)
- [x] Create API Services app with `private_key_jwt`; record whether "Require DPoP" is on by default and Okta's nonce behavior — **V15**; grant `okta.users.read okta.groups.read`, assign Read-only Admin; fetch a token and call `GET /api/v1/users?limit=1`
- [x] Write `docs/design/spike-findings.md` (one section per V-item: result, evidence, design impact)

Verify: findings doc complete for V1, V9, V10, V11, V13, V15; design doc updated where results differ.

### 0.6 Client OAuth check (V3) ◐
Design: §8.3, §16 V3 · Depends: 0.4, 0.5 · **Needs: real MCP clients and dev-org admin access (user-driven)**
Pulled forward from 4.6: if a target client can't sign in with a pre-registered `client_id` and a fixed redirect URI (V11), Path A doesn't work for it, and that is cheaper to learn before Phases 2–4. `spikes/oauth/client_check.py` (deleted with `spikes/sdk/` at end of 4.2) serves 401 + PRM at both URLs, validates real tokens from the spike AS, and exposes one `whoami` tool. Run: `uv run pytest spikes/oauth`.
- [x] Check server and tests (mock JWKS: valid token, wrong `aud`/`iss`, expired, missing `uid`, disallowed `cid`, missing scope → 403, `HS256`/`none`)
- [ ] For each target client: register its redirect URI on the spike public client, connect to `http://127.0.0.1:8000/mcp`, sign in as each test user, call `whoami` (Claude Code done)
- [x] Refresh tokens tested both ways (A: none; B: rotating); both supported by `scripts/okta-setup.py` and `terraform/okta/` via `refresh_tokens`, A the default; `offline_access` added to the rule in both
- [ ] Fill the compatibility matrix in [`design/spike-findings.md`](design/spike-findings.md) (discovery URLs from the server log, client-ID and redirect configuration, scopes requested, result)

Verify: at least Claude Code completes sign-in and `whoami` shows the user's `uid` and group ID; every target client has a matrix row. A client that can't connect is a design decision (drop it, or revisit §8.3), recorded in the Decisions log.

---

## Phase 1 — Spec & registry core

### 1.1 Pin Okta spec ☑
Design: §6.1 · Depends: 0.1
- [x] `scripts/update-spec.py`: download management-minimal spec, write `specs/PINNED.json` (source URL, version, sha256, fetched date), print added/removed/changed GET operations vs. previous pin
- [x] Commit initial spec under `src/okta_mcp/data/specs/`
- [x] `tests/test_spec_pin.py`: file hashes to `PINNED.json`

Verify: `uv run python scripts/update-spec.py --check` is a no-op on a clean tree; hash test passes.

### 1.2 Spec index ☑
Design: §6.1, §6.2 (checks 1–3, 9) · Depends: 1.1
- [x] `registry/spec.py`: load with `yaml.CSafeLoader`; index **GET** operations by `operationId` → path template, path/query params (with schema, enum, pattern), `security.oauth2` scopes, tags, success response schema (list vs wrapped object, `_links`)
- [x] Tests: known operations resolve (`getUser`, `listUserGroups`, `listAuthenticatorEnrollments`); non-GET ops absent; scopes extracted; operations without `oauth2` security report empty scopes; load time under 2s

Verify: `uv run pytest tests/registry/test_spec.py`

### 1.3 Registry model & loader ☑
Design: §6.2, [T1](design/t1-tool-surface.md) D3, D5 · Depends: 1.2
- [x] Spec index follow-up (T1 D5): `Response.fields` / `item_fields` hold the response's dotted property paths, base schema only for polymorphic items
- [x] `registry/model.py`: pydantic models for domain file, command (simple/resolved; `handler` reserved for post-v1), args (`path_param`, `query`, `resolve: user_id`, `pattern`, `allowed_values`, `arg_rule`, `type`, `maxItems`), `paginate` (`link | body_links | link_or_body | none`), `items_key`, `page_size`, `view`, `data_classes`, `resumable`, `okta_scopes_override`, `response_override`
- [x] Data-class → sensitivity table (reviewed config); sensitivity derived, never declared
- [x] `registry/loader.py`: load all `registry/*.yaml`, resolve against spec index, run **checks 1–6, 8–10** from design §6.2 (no derived scope set is an error without override; check 7 is 3.4's guide test), produce immutable `Registry`
- [x] Tests: one fixture registry per failure mode (non-GET op, missing path param, unknown query, no scope set without override, missing/unknown data class, same-operationId sensitivity mismatch, widening arg without rule, unknown operation, `items_key` not an array-of-objects property of the response, list without view, view path not in the (base) schema, duplicate classification on one operation)
- [x] `/security-review` (classification fields and the sensitivity table are a trust boundary)

Verify: `uv run pytest tests/registry/`; every check has a failing fixture.

### 1.4 Argument schemas & synopsis ☑
Design: §5.3, §6.3, [T1](design/t1-tool-surface.md) D1, D11 · Depends: 1.3
- [x] Build JSON Schema per command from spec param schemas + registry overlays (`one_of_required`, `maxItems`, `pattern`, renames, `allowed_values`); validate with `jsonschema`
- [x] Synopsis line generator (`get-groups <user>`, `list [filter] [search]`), capped at 60 characters with the summary (T1 D1)
- [x] Text help renderer for `okta_help` (T1 D11)
- [x] Validation function returning `invalid_arguments` details naming valid keys/values
- [x] Tests: snapshot schemas for pilot commands; error messages list valid options

Verify: `uv run pytest tests/registry/test_schema.py`

### 1.5 Coverage inventory ☑
Design: §5.6 · Depends: 1.2
- [x] Build the okta-skills command catalogue (minus ai-agents) by hand or one-off script run **outside** this repo's code paths (reference only); save as `docs/coverage/catalogue.yaml`: domain, command, operationId(s), kind (simple/resolved/composite/excluded), pagination style and `items_key`, notes on gotchas, exclusion reason (e.g. `getAerialConsent`, `listSupportedSecurityQuestions`)
- [x] `scripts/coverage-report.py`: catalogue vs registry vs spec GET ops → `docs/coverage/report.md`. First move the importlib loader for hyphenated scripts, now copied in `tests/scripts/test_okta_setup.py` and `test_update_spec.py`, into a `load_script(name)` helper in `tests/scripts/conftest.py`, so this script's tests don't add a third copy. Also have `scripts/update-spec.py` reuse `SpecError` and `$ref` resolution from `okta_mcp.registry.spec` instead of its own copies (1.2 review)
- [x] Count commands per kind; **re-estimate M3** in design §15 from the counts and the share of gotcha endpoints that need recorded fixtures

Verify: report generated; every catalogue entry has a kind; Decisions log records the counts and the new estimate.

### 1.6 Pilot registries ☑
Design: §6.2 · Depends: 1.3, 1.4
- [x] `registry/network-zones.yaml` and `registry/groups.yaml`, fully classified, `pattern` on every ID path param
- [x] Loader + schema tests pass with real files

Verify: `uv run pytest`; coverage report shows both domains complete.

---

## Phase 2 — Okta client & executor

### 2.1 Configuration ☑
Design: §11.3 · Depends: 0.1
- [x] `config.py`: a pydantic model populated from `os.environ` for every variable in §11.3; `_FILE` variants; fail-fast messages; `MCP_ENV` handling (no `pydantic-settings` dependency)
- [x] Tests: missing required vars, bad URLs, `*` client IDs warning, SSWS and dev mode refused in production, short cursor key rejected

Verify: `uv run pytest tests/test_config.py`

### 2.2 Token providers & DPoP 🔒 ☑
Design: §6.5, §10 · Depends: 2.1
- [x] `okta/token.py`: `TokenProvider` interface; `private_key_jwt` provider (RS256, `kid`, 5-min, `jti`), client-credentials request, in-memory cache, refresh under `anyio.Lock` at <60s; SSWS provider (stdio dev mode only); a fake provider for tests
- [x] `okta/dpop.py`: ephemeral EC P-256 key; proof builder (`jti`, `htm`, `htu` without query/fragment, `iat`, `ath`); nonce capture for `use_dpop_nonce` / `DPoP-Nonce`; `OKTA_DPOP=false` path
- [x] Tests (mocked HTTP): assertion claims, refresh once under 20 concurrent callers, DPoP proof claims and nonce retry at the token endpoint, error mapping, key never logged
- [x] Live check after 0.5: fetch a real token against the dev org (DPoP on and off as the app allows)

Verify: `uv run pytest tests/okta/test_token.py tests/okta/test_dpop.py`; `/security-review`.

### 2.3 HTTP client core ☑
Design: §6.5 · Depends: 2.2 (interface and fake only)
- [x] `okta/client.py`: async HTTP client (`httpx2`, per 0.4; tests use `httpx2.MockTransport`), GET-only public API, global in-flight semaphore, timeouts, origin assertion on every request, per-request DPoP proof + nonce retry at the resource server, request counter hook (principal contextvar), error → `upstream_error` mapping with sanitized 401/403 text
- [x] Tests: semaphore caps concurrency, non-origin URL refused, fresh DPoP `jti` per request, deadline cancellation aborts in-flight request

Verify: `uv run pytest tests/okta/test_client.py`

### 2.4 Rate limiting ☑
Design: §6.5 · Depends: 2.3
- [x] `okta/ratelimit.py`: on 429, wait = `x-rate-limit-reset` − `Date` header (local clock if absent) + jitter; retry once if ≤ `OKTA_RATE_LIMIT_MAX_WAIT` and within the deadline, else `rate_limited`; per-principal Okta-request limiter (`MCP_REQUESTS_PER_MINUTE`)
- [x] Tests: skewed local clock doesn't change the wait; wait over cap raises; retry once only; limiter window

Verify: `uv run pytest tests/okta/test_ratelimit.py tests/okta/test_client.py`

### 2.5 Pagination 🔒 ☑
Design: §6.5, §7.2 · Depends: 2.3
- [x] **(slice)** `okta/paginate.py`: async generator yielding `(item, page_state, index_in_page)`; mode `link`; next link must match origin **and** expanded path after RFC 3986 normalisation
- [x] Modes `body_links`, `link_or_body`; `items_key`
- [x] Tests: multi-page fixtures for each mode and a wrapped response; cross-origin / cross-path / encoding-variant next link raises; empty page stops; each hop goes through `client.get` (fresh DPoP proof) with no `params`, so the next link is sent unchanged (`client.get` re-encodes an existing query when `params` is non-empty; 2.3 review)

Verify: `uv run pytest tests/okta/test_paginate.py`; `/security-review`.

### 2.6 URL builder & path-injection controls 🔒 ☑
Design: §6.4 · Depends: 1.4, 2.3
- [x] `exec/params.py`: map validated args → path params (reject empty, `.`, `..`, >256 chars, and any `/ \ % ? #`, whitespace or control character; enforce registry/spec `pattern`; then encode with no safe chars) and query params mapping
- [x] Trailing newline: the schema rejects an ID plus `\n` since 1.6 (`$` checked with ECMA-262 semantics); `params.py`'s whitespace/control-character rejection must catch it too, independently of `pattern`
- [x] Injection regression suite generated over **every path param of every registry command** with the design §6.4 payload set (incl. `a/../b`, `a%2F..%2Fb`, `a\..\b`, a valid ID plus trailing `\n`)
- [x] Assert rejected payloads produce `invalid_arguments` and **no recorded request**; accepted values produce a URL whose origin == `OKTA_ORG_URL` and whose path matches the template

Verify: `uv run pytest tests/exec/test_params.py`; `/security-review`.

### 2.7 Output options & scrubbing ☐
Design: §9.2, §7.2 · Depends: 0.1
- [ ] `scrub.yaml` initial paths (design §9.2); `exec/output.py`: scrub → strip_links → select, per item
- [ ] Tests: fixture per scrub path; `select` dotted paths and arrays; `strip_links` nested

Verify: `uv run pytest tests/exec/test_output.py`

### 2.8 Envelope & budgets ☐
Design: §7.1, §7.2 · Depends: 2.5, 2.7
- [ ] **(slice)** `exec/envelope.py`: consume paginator item-by-item; stop on items / post-select bytes / deadline; `truncated`, `truncation_reason`, `untrusted: true`; single-resource shape; `result_too_large`. No `next_cursor` until 2.9
- [ ] Tests: cap mid-page, byte cap, deadline, non-list oversize

Verify: `uv run pytest tests/exec/test_envelope.py`

### 2.9 Cursors 🔒 ☐
Design: §7.3 · Depends: 2.8
- [ ] `exec/cursor.py`: HMAC-signed payload (single key), `uid`/tool/cmd/`args_sha256` (original args) binding, resolved `path_params`, relative `page.rel` only (first page = initial request), 15-min expiry; resume requires resent args matching the hash, re-derives the URL from `path_params` and checks the path against the template. `page.rel` is the paginator's page state as sent, so an equivalent-encoding next link Okta returned (e.g. `%75sers`) is kept: compare paths with `paginate.normalise_path` on both sides, not literally (2.5 review)
- [ ] Tests: tamper, wrong uid, wrong args, expired, wrong key, absolute URL in payload rejected, first-page truncation, **resume yields every item exactly once on an unchanged list** across item and byte caps

Verify: `uv run pytest tests/exec/test_cursor.py`; `/security-review`.

### 2.10 Executor & resolver 🔒 ☐
Design: §5.5, §5.6 · Depends: 2.4, 2.6, 2.9
- [ ] **(slice)** `exec/executor.py`: (principal, tool, command, args, select, strip_links, limit, cursor) → envelope or structured error; policy check (incl. `arg_rules`) before any resolver or Okta request; deadline wrapper; maps exceptions to §5.5 codes. Cursor argument rejected until 2.9
- [ ] `exec/resolve.py`: `user_id` only — `00u…` ID short-circuit, else exact `getUser` lookup, `not_found` otherwise; cached per call
- [ ] `groups list` with `q`: Okta doesn't page `q`, so the forced `limit=200` (`page_size`) cuts results with no next link and no sign of truncation (1.6 review). Don't send `limit` when `q` is passed (or mark the result truncated); needs a registry field or executor rule, test with a mocked 250-item response
- [ ] Map `RuntimeError` from `OktaClient.get` (DPoP token with no DPoP key on the client) to `internal_error` (2.3)
- [ ] Tests: pilot commands end to end against mocked Okta; each error code reachable; forbidden call records no Okta request (no resolver oracle)

Verify: `uv run pytest tests/exec/`; `/security-review` (resolver).

---

## Phase 3 — Policy & tool surface

### 3.1 Policy model & loader 🔒 ☐
Design: §9.3 · Depends: 1.3
- [ ] `policy/model.py`, `policy/loader.py`: schema, load-time validations (group entries must be `00g…` IDs; domains/commands exist; no empty roles; duplicates), warnings
- [ ] `tests/policy/fixtures/pilot.yaml`: example policy restricted to the pilot domains (network-zones, groups); test that it loads clean. The full `docker/policy.example.yaml` lands in 5.7
- [ ] Tests: each validation failure

Verify: `uv run pytest tests/policy/test_loader.py`; `/security-review`.

### 3.2 Policy engine 🔒 ☐
Design: §9.1, §9.4 · Depends: 3.1
- [ ] `policy/engine.py`: `permitted(principal) -> frozenset[(domain, command)]`, memoized by matched-role set; wildcard excludes sensitive unless `include_sensitive`; deny wins; per-call check applies `arg_rules`; capability gate vs `OKTA_SCOPES` with explicit `.manage ⇒ .read` table (V4)
- [ ] Property tests: "deny always wins", "no role ⇒ nothing", "wildcard never yields sensitive without include_sensitive"

Verify: `uv run pytest tests/policy/test_engine.py`; `/security-review`.

### 3.3 Tool definitions ☐
Design: §5.1–5.3 · Depends: 1.4, 3.2
- [ ] `tools.py`: per-principal tool list (filtered enum + synopsis), `okta_help`, `okta_status`; annotations
- [ ] Tests: two principals → different tools; `okta_help` on forbidden command → `forbidden_by_policy`; `okta_status` reveals nothing about other users/roles

Verify: `uv run pytest tests/test_tools.py`

### 3.4 Resources ☐
Design: §5.4, §3 · Depends: 3.2
- [ ] `resources/filters.md`, `resources/expression-language.md`, guides for the two pilot domains (re-authored from okta-skills with attribution)
- [ ] `resources.py`: visibility per principal
- [ ] Test: every command named in a guide exists in the registry

Verify: `uv run pytest tests/test_resources.py`

---

## Phase 4 — MCP server & auth

### 4.1 Dev mode over stdio 🔒 ☐
Design: §8.6 · Depends: 2.10, 3.3, 0.4
- [ ] `auth/devmode.py`: `MCP_DEV_MODE` + principal file; refuse when `MCP_ENV=production`
- [ ] `okta-mcp --stdio` entrypoint wiring executor + tools + policy; HTTP entrypoint refuses to start when `MCP_DEV_MODE` is set
- [ ] Manual (after 0.5): connect Claude Code (or Inspector) to the dev org; run every pilot command
- [ ] T1 check: give the model a few real helpdesk-style tasks on the pilot domains; record tokens per call and whether it reads tables, uses `okta_help` and `select` correctly; revise T1 decisions in the Decisions log before 2.9 and Phase 5 build on them

Verify: refusal tests pass; pilot commands return real data from the dev org; T1 check recorded; `/security-review`.

### 4.2 HTTP app ☐
Design: §4, §5.2, §11.4 · Depends: 4.1, 0.4
- [ ] `app.py`: stateless Streamable HTTP at `/mcp`, `/healthz`, `/readyz`; per-principal list results with `cacheScope: "private"` + `ttlMs`; `Origin` validation (reject a present `Origin` not in `MCP_ALLOWED_ORIGINS`); `MCP_TRUST_PROXY`
- [ ] Delete `spikes/sdk/` and `spikes/oauth/`
- [ ] Tests: health endpoints; bad Origin rejected, missing Origin allowed; `cacheScope` present

Verify: `uv run pytest tests/test_app.py`

### 4.3 Token verifier 🔒 ☐
Design: §8.5 · Depends: 4.2
- [ ] `auth/verifier.py` (on top of SDK auth helpers where 0.4 found them sufficient): JWKS discovery + cache + rate-limited refetch; all §8.5 checks; `Principal` contextvar; JWKS not loaded → 503 and `/readyz` not ready, with background retry (startup does not require the issuer)
- [ ] Tests with a local signing key: forged sig, `alg=none`, HS256, wrong iss/aud, expired, nbf, missing scope, cid not allowed, missing `uid`, malformed groups, unknown kid refetch limit, issuer down at startup

Verify: `uv run pytest tests/auth/test_verifier.py`; `/security-review`.

### 4.4 Protected Resource Metadata & challenges 🔒 ☐
Design: §8.1 · Depends: 4.3
- [ ] `auth/metadata.py` (only what the SDK doesn't provide): PRM at path-specific and root URLs; `401` with `resource_metadata`; `403 insufficient_scope`; header-only bearer

Verify: `uv run pytest tests/auth/test_metadata.py`; `/security-review`.

### 4.5 Integration tests ☐
Design: §14 (Integration, Protocol) · Depends: 4.4
- [ ] Full ASGI app + mock AS (local JWKS) + mocked Okta: 401 → token → per-principal `tools/list` → call → denial
- [ ] SDK-client protocol smoke over Streamable HTTP at 2026-07-28 and 2025-11-25; `structuredContent` + annotations present

Verify: `uv run pytest tests/integration/`

### 4.6 Real-client check (Path A) ☐
Design: §8.3 · Depends: 4.5, 0.5, 0.6
- [ ] Run locally behind a TLS proxy (e.g. Caddy) or tunnel; connect each target MCP client via Path A (auth is always on, so exposure is safe)
- [ ] Move the 0.6 matrix from `design/spike-findings.md` to `docs/compatibility-matrix.md` (client × discovery × registration × works/limitations) and re-run each client against the real server
- [ ] Under option B, the server accepts refreshed tokens with no new sign-in (Claude Code)

Verify: at least one real client completes OAuth and calls a pilot command; matrix moved and re-run.

---

## Phase 5 — Registry authoring (all domains)

### 5.0 Fixture tooling ☐
Design: §14 (Fixtures) · Depends: 1.3
- [ ] `scripts/gen-fixtures.py`: default per-command fixture from the spec's response schema/examples (realistic IDs, `example.com` emails, `example.okta.com` links)
- [ ] `scripts/sanitize-fixture.py`: rewrite recorded dev-org responses (org hostname, emails, names, IDs consistently remapped)
- [ ] `tests/test_fixture_hygiene.py`: fails on non-`example.*` email domains or org hostnames other than `example.okta.com` under `tests/fixtures/`

Verify: `uv run pytest tests/test_fixture_hygiene.py`; a sanitized real recording passes, an unsanitized one fails.

### Domain batches

Each batch: write registry entries, classify (`data_classes`, `arg_rules`, `pattern`), extend `scrub.yaml`, generate fixtures (record + sanitize only for endpoints with known gotchas), write the domain guide in `resources/`, and smoke-test through the stdio dev-mode server.

Verify (every batch):
```
uv run pytest tests/registry tests/fixtures && uv run python scripts/coverage-report.py
```
plus manual dev-org smoke of each new command; V14 review (does any "normal" command return secrets?) noted in the Decisions log.

| Step | Domains | Notes | Status |
|---|---|---|---|
| 5.1 | users, apps | Largest; `user_id` resolver; `get-factors`/`get-enrollments` simple; `expand` rules | ☐ |
| 5.2 | policies, authenticators, network-zones (done in 1.6), behaviors, attack-protection | Security-analyst role coverage | ☐ |
| 5.3 | logs (simple commands only), sessions, security | Mostly `sensitive`; free-form `filter` rules; SSF stream secret | ☐ |
| 5.4 | iam, oauth-client-roles, api-tokens, authorization-servers | Admin roles / credential material; wrapped lists (`items_key`, `link_or_body`) | ☐ |
| 5.5 | identity-providers, schemas, org-settings, realms | IdP `client_secret` scrub | ☐ |
| 5.6 | devices, device-assurance, device-posture, device-integrations | | ☐ |

### 5.7 Full example policy ☐
Design: §9.3 · Depends: 5.1–5.6
- [ ] `docker/policy.example.yaml` = design §9.3 example; test that it loads clean against the full registry

Done when (phase): coverage report shows every simple/resolved catalogue entry implemented; V6 (Read-only Admin sufficiency) recorded per domain; example policy loads.

---

## Phase 6 — Audit, limits, logging

### 6.1 Audit log ☐
Design: §12.3 · Depends: 4.5
- [ ] `audit.py`: one JSON line per call/denial; `MCP_AUDIT_ARGS=hash`; arg redaction; never result bodies
- [ ] Tests: fields present; hash mode; no secrets/tokens in output

### 6.2 Limiter & operational logs ☐
Design: §6.5, §13 · Depends: 2.4, 4.5
- [ ] Per-principal Okta-request limiter enforced in the HTTP path; `rate_limited` errors
- [ ] Structured operational logs with `request_id`; 429/retry/limiter/truncation/JWKS events
- [ ] Tests: integration test trips the limiter; log events emitted

Verify (phase): `uv run pytest tests/test_audit.py tests/integration/test_limits.py`

---

## Phase 7 — Packaging & deployment

### 7.1 Container 🔒 ☐
Design: §11.2 · Depends: 4.5
- [ ] `Dockerfile`, `.dockerignore` per design (allow-list includes `LICENSE`, `README.md`; `uv sync --no-editable`); non-root; `MCP_ENV=production`
- [ ] CI job: build image, run container tests (non-root, read-only FS, health endpoints, no tests/docs/keys in image), image scan

Verify: `docker build . && docker run --read-only …` health checks pass; CI container job green; `/security-review`.

### 7.2 Compose example ☐
Design: §11.4 · Depends: 7.1
- [ ] `docker/compose.example.yaml`: secrets as files, read-only policy file mount, read-only root FS, `cap_drop: [ALL]`, `no-new-privileges`, loopback port binding

Verify: `docker compose -f docker/compose.example.yaml config` validates; bring-up with dev-org values works.

### 7.3 Runbook ☐
Design: §11.4, Appendix C · Depends: 7.2, 0.5
- [ ] `docs/runbook.md`: Okta setup (from spike findings), exposure decision, deploy, policy changes (restart), key rotation, kill switch, audit log handling
- [ ] Refresh tokens and user removal (spike 0.6): choosing A or B (link [`okta-setup.md`](okta-setup.md#refresh-tokens-option-a-or-b)); removing a user is group removal under A, plus clearing sessions with `oauthTokens=true` (or deactivating the user) under B; under B the Global Session Policy doesn't bound refresh chains, so `lifetime_minutes` is the re-sign-in and MFA interval; failed refreshes have no `User` target in the System Log, so find them by client ID

Verify: someone (or a fresh Claude session) follows the runbook on a clean machine to a working `/readyz`.

---

## Phase 8 — Hardening & release

### 8.1 Security review sweep ☐
- [ ] `/security-review` over all 🔒 paths together (cross-cutting issues)
- [ ] Resolve or ticket every finding

### 8.2 Compatibility matrix & E2E ☐
- [ ] Complete `docs/compatibility-matrix.md` for all target clients (Path A)
- [ ] E2E checklist: groups claim; per-role tool lists; revocation (A: group removal takes effect within one access-token lifetime; B: group removal and role changes at the next refresh, token revocation ends the chain, an expired Okta session doesn't); 429 behavior under load

### 8.3 Documentation pass ☐
- [ ] README usage, AGENTS.md current, design doc reflects what was built (bump revision if changed)

### 8.4 Release v1.0.0 ☐
- [ ] Tag, build and publish image, changelog

Verify: all phases ☑; CI green on tag.

---

## Post-v1 backlog (on demand)

| Item | Design | Notes |
|---|---|---|
| Composite handlers: batch `get-factors`/`get-enrollments` (`ids[]`), `policies get-rules` multi-ID, `logs list --member-of/--count-by`, `logs timeline`, `logs login-failures`, `logs diagnose` | §5.6, §7.2 | Each needs its own fan-out/aggregation caps; okta-skills as behavioral reference only |
| Path B (Cross App Access / ID-JAG) | §8.4 | V2, V12 |
| Per-bucket 429 handling, proactive slowdown | §6.5, R6 | Only if logged 429s show starvation |
| `/metrics` | §13 | |
| ai-agents domain with a separate, risk-accepted credential | §10 | Vendors the workload-principals spec |
| One session-scoped `spec` (and `registry`) fixture in `tests/conftest.py` instead of a module-scoped `load_spec()` per test module | §14 | Only if suite time or the flaky `test_load_time_under_two_seconds` gets worse; each module re-parses the spec (~1–2 s) (1.6 review) |

---

## Open questions (blocking step → design §16 ID)

| ID | Question | Blocks | Resolved in |
|---|---|---|---|
| V1 | `groups` claim (IDs) on access tokens; >100 groups | 3.2, 4.3 | 0.5 ☑ (>100 untested) |
| V3 | Client registration: pre-registered vs DCR vs CIMD | 0.6 | 0.6 ◐ |
| V4 | `.manage ⇒ .read` implication | 3.2 | 3.2 (Okta docs) |
| V5 | SDK v2 / 2026-07-28: stateless per-request principal, `cacheScope`, back-compat, auth helpers, `httpx` vs `httpx2` | 0.1 deps, 2.3, 4.2 | 0.4 ☑ (see Decisions log) |
| V6 | Read-only Admin sufficiency per domain | 5.x | 5.x |
| V8 | Spec accuracy (scopes, operationIds, params) | 1.3, 5.x | 1.5 ◐ (5 gotchas catalogued) / 5.x |
| V9–V11 | `resource` param, discovery, loopback, static client IDs | 4.4, 4.6 | 0.5 ☑; per-client results in 4.6 |
| V13 | `uid` vs `sub`; ID-emitting groups expression | 4.3 | 0.5 ☑ |
| V14 | Secrets in "normal" endpoints | 5.x | 5.x |
| V15 | DPoP default and nonce behavior | 2.2 live check | 0.5 ☑ |
| T1 | **Discuss with the user (not a design §16 item; proposal: [`design/t1-tool-surface.md`](design/t1-tool-surface.md)):** which tools and commands to expose over MCP, and what their responses look like. Goal: be token-conscious. Do as much as possible in code (filtering, projection, summarising, defaults for `select`/`strip_links`, compact envelopes and errors, short synopses) so results stay small in the model's context. Revisit §5.1–5.3, §7.1–7.2 | 1.4, 2.7, 2.8, 3.3 | 2026-11-02 ☑ (D1–D11 accepted) |

## Decisions log

| Date | Step | Decision | Why |
|---|---|---|---|
| 2026-10-23 | — | Repo independent of okta-skills; native registry-based implementation | Design r3 §0.2 |
| 2026-10-23 | — | License: Apache-2.0 + Commons Clause (same as okta-skills) | Free to use, not to sell |
| 2026-10-23 | — | MCP server (Phase 4) before bulk registry authoring (Phase 5) | Early end-to-end pilot; live smoke-testing of every entry |
| 2026-10-23 | — | Design r4 from independent review: path-value character rejection; group IDs only; MCP 2026-07-28 + SDK v2 target; DPoP on by default; stdio-only dev mode; ai-agents out of v1; simple `get-factors`/`get-enrollments`; `user_id` resolver only, after policy | Design §0.1 |
| 2026-10-23 | — | Deferred past v1: Path B, per-bucket 429, policy hot-reload, cursor key rotation, `/metrics`, tool-call limiter, `GroupResolver`, composite handlers | Single-engineer v1; ~5–8 days saved |
| 2026-10-23 | — | Data files ship as package data under `src/okta_mcp/data/` | Required by `uv sync --no-editable` in the image |
| 2026-10-23 | 0.1 | Build backend `uv_build` (`>=0.12,<0.13`); `__version__` read from package metadata; empty `data/` kept with `.gitkeep` (wheel contents checked) | `uv_build` ships everything under the module dir as package data, no extra config; one version source in `pyproject.toml` |
| 2026-10-23 | 0.1 | Ruff rules `E W F I B UP S SIM RUF` (`S101` allowed in `tests/`); pyright covers `src` + `tests`, strict on `src` only | Bandit (`S`) checks suit a security-sensitive server; strict typing where it matters |
| 2026-10-23 | 0.1 | `.gitignore` ignores `*.spec` (PyInstaller template); step 1.1 must confirm spec files aren't silently ignored | Found during 0.1; affects 1.1 |
| 2026-10-23 | 0.2 | Project name in prose and headings is `independent-okta-mcp`; `okta-mcp` is only the distribution, console script and `okta_mcp` import name | User decision |
| 2026-10-23 | 0.3 | CI pins `actions/checkout` v7.0.1 and `astral-sh/setup-uv` v10.2.0 by SHA (v10.3.x skipped: released 1–2 days before), uv `0.12.5`; checkout without persisted credentials; `permissions: contents: read` | Supply chain: avoid brand-new releases, least-privilege token. When bumping uv, consider bumping the `uv_build` range in `pyproject.toml` with it |
| 2026-10-23 | 0.3 | `pip-audit --skip-editable` audits the synced environment (runtime + dev deps); the project itself is skipped as it isn't on PyPI | Audits exactly what CI installs from `uv.lock` |
| 2026-10-23 | 0.3 | CI matrix 3.12–3.14; 3.15 deferred until CI's uv pin moves to a release (≥ ~2 weeks old) that ships 3.15.0 final, then added as a normal (blocking) job. Image stays on 3.12 | uv 0.12.5 only provides 3.15.0rc1, so a 3.15 job now would test the release candidate. Checks passed locally on 3.14.7 and 3.15.0rc1 |
| 2026-10-23 | 0.3.1 | Dependabot for `uv` + `github-actions`: weekly, 14-day cooldown (security updates bypass it), minor+patch grouped. `mcp` ignored from 0.4 until 4.5. Not covered, stays manual: uv version in `ci.yml` (the `uv_build` range in `[build-system]` *is* covered; first run opened PR #5 for it) | Keeps SHA pins and lockfile current while matching the "no brand-new releases" rule; SDK upgrades change protocol/auth behavior (V5) and should be deliberate until integration tests exist |
| 2026-10-24 | 0.4 | `mcp==2.3.0` (2026-10-02; latest at the time). Protocol: 2026-07-28 is the "modern" stateless revision (`server/discover`, per-request envelope); handshake-era 2024-11-05 … 2025-11-25 still served by the same app. Spike verified with the SDK client at `mode="2026-07-28"` and `mode="legacy"` (negotiates 2025-11-25) | Newest v2 release; ≥ ~2 weeks old |
| 2026-10-24 | 0.4 | Server shape: low-level `Server(on_list_tools=…, on_call_tool=…)` + `streamable_http_app(stateless_http=True, json_response=True, auth=AuthSettings(…), token_verifier=…)`; no `Mcp-Session-Id` issued. Handlers return typed results; `ListToolsResult(ttl_ms=…, cache_scope="private")` explicit fields win over server-wide `cache_hints` (SDK default is already `ttl_ms=0, scope="private"`). `get_tool_input_schema` runs before middleware, so it is not caller-scoped; don't use it for per-principal schemas | Verified in `spikes/sdk/` |
| 2026-10-24 | 0.4 | Principal: SDK `TokenVerifier.verify_token(token) -> AccessToken \| None` + `BearerAuthBackend`/`AuthContextMiddleware`; handlers read `get_access_token()` (contextvar). `AccessToken` carries `subject` and `claims`, enough for our `Principal`. 4.3 builds on this, with three gaps of our own: (1) a verifier exception becomes a 500, so "JWKS not loaded → 503" needs its own handling; (2) the backend only checks `expires_at` and an optional `resource` match, so all §8.5 checks live in our verifier; (3) PRM is registered only at the path-inserted URL (`/.well-known/oauth-protected-resource/mcp`), so the root PRM URL (§8.1) is our own route in 4.4. 401/403 responses already carry `WWW-Authenticate` with `resource_metadata` | Read from SDK source; 401 path verified in spike |
| 2026-10-24 | 0.4 | DNS-rebinding protection is auto-enabled only when `host` is localhost; for the deployed server, pass `TransportSecuritySettings(allowed_hosts=…, allowed_origins=…)` explicitly (4.2). The modern transport internally re-invokes `on_list_tools` to validate `Mcp-Param` headers, so `tools/list` must stay cheap and side-effect free (it runs under the same request's principal) | Read from SDK source |
| 2026-10-24 | 0.4 | HTTP client: `httpx2` (replaces 0.1's `httpx`; `mcp` already depends on it, so one HTTP stack). Test mock: `httpx2.MockTransport`; `respx` dropped (mocks `httpx` only). httpx2 pulls in `truststore` (system trust store), so 2.3 should check which CA bundle the Okta client actually uses | Avoids two HTTP/TLS stacks; the GET-only Okta client doesn't need respx's routing DSL |
| 2026-10-30 | 0.5 | Okta-side setup ships as `scripts/okta-setup.py`, outside the package: it writes to Okta, so it must never be importable from `src/` (read-only invariant). It uses its own `OKTA_SETUP_API_TOKEN` (Super Admin), so it is never confused with server credentials. `apply` only creates objects and adds links; anything else that differs is reported. It reads only the public key; `kid` is the RFC 7638 thumbprint, or the registered `kid` when the key is already uploaded | Verified live: `apply` then `check` on a fresh set of names in the dev org; the created service app minted a DPoP token |
| 2026-10-30 | 0.5 | `terraform/okta/` (okta/okta `~> 7.1`) mirrors the script's objects and input checks for orgs managed with Terraform. It takes the public key as a JWK (Terraform can't parse PEM) and computes the same RFC 7638 `kid`. Sets `dpop_bound_access_tokens = true` on the `client_credentials` service app although the provider docs say the two don't combine: the provider doesn't enforce it, and V15 shows Okta accepts it | `validate` clean; `plan` against the dev org: 12 to add; bad inputs fail at plan; `kid` matches the script's on a test key. Not yet applied |
| 2026-10-31 | 0.5 | Setup tooling fails closed: an existing object that fails any check (imported or duplicate group, wrong app type/grants/redirects/keys, inactive AS or wrong audience, `ALL_CLIENTS` policy, rule with `EVERYONE`, extra grants, refresh tokens or long tokens) is reported and nothing that depends on it is created, linked or printed. Duplicate names are an error rather than a guess. Paging follows `next` links only on the org's own origin, since the admin token rides along. A `CUSTOM` admin role on the service app is accepted in place of Read-only Administrator (Appendix C), so the tool trusts the admin's choice of permissions. Terraform's provider takes its org from `okta_org_url`, so the provider and the grants' issuer can't name different orgs. `AGENTS.md` scopes the read-only invariant to `src/` and lists both tools as trust boundaries | `/security-review` and `/code-review` findings; 44 tests; live `check` clean; `plan` 12 to add |
| 2026-11-01 | 0.5 | V1/V13 hold as designed: `groups` carries the IDs of the user's `mcp-okta-*` Okta groups; principal is `uid` (`sub` is the login). V9: Okta ignores `resource` and always issues the AS's one audience, so the dedicated AS is a hard requirement and the server never relies on `resource`. V11: redirect URIs match exactly (no any-port loopback; `localhost` ≠ `127.0.0.1`), so each client needs a fixed, registered redirect URI. `scp` order varies, so compare as a set. The per-client compatibility matrix moves to 4.6, because real clients only start sign-in from the server's 401 + PRM. V15: "Require DPoP" is on by default for API Services apps made in the admin console, off for apps made through the API or Terraform; the server keeps DPoP on by default and both setup tools turn it on | `user-token` runs in the trial org, both test users, seven variants ([findings](design/spike-findings.md)) |
| 2026-11-01 | 0.5 | Re-review of the setup tooling: no High/Medium findings. Hardening applied: (1) `apply` gives grants and the admin role only to a service app it created in the same run; an existing app that passes its checks is reported `manual` with its ID and creation date, since its public key is public and anyone with app-create rights could plant a matching app. (2) Extra grants or admin roles on the service app now make it untrusted (no grants, role or printed settings), like any other failed check. (3) Terraform `okta_org_url` must be `https://` + hostname characters only, so `user@host`, ports, paths and queries are rejected | `/security-review` of `scripts/okta-setup.py` and `terraform/okta/`; 43 setup tests (3 new, failing on the old script); `terraform validate` clean |
| 2026-11-01 | 1.1 | Spec pinned at upstream commit `5cf2dc4` (version 2026.42.1, 319 GET operations, 3.9 MB). `update-spec.py` resolves a ref to the last commit touching the file and downloads from that commit's raw URL, so `PINNED.json` names an immutable source. "Changed" means the operation object, its path-level parameters, or any component reachable from them through `#/components/` refs differ (421 of 422 path-level parameter lists are refs). Other `$ref`s appear only as data in examples and are not followed. Duplicate operationIds and dangling refs are errors. `--check` downloads the latest and writes nothing: 0 up to date, 1 newer, 2 local file ≠ pin. A plain re-pin warns and replaces a local file ≠ pin, so a run interrupted between the two writes is repairable. `.gitattributes` marks the spec `-text` (the sha256 pins exact bytes) and `linguist-generated`. The `*.spec` gitignore rule doesn't match `management-minimal.yaml` (`git check-ignore` clean); `data/.gitkeep` removed now that `data/specs/` exists. Running the script needs the sandbox off on macOS (httpx2's `truststore` uses the keychain) | Spec is data reviewed in PRs, so the newest commit (5 days old) was taken rather than applying the 2-week package rule. Wheel contains both spec files |
| 2026-11-01 | 1.2 | `registry/spec.py` builds an immutable `SpecIndex`: GET operations by `operationId` (path, path/query `Param`s with `$ref`s inlined, `oauth2` scopes, tags, `Response`), plus `non_get` (operationId → method) so 1.3 can tell "non-GET" from "unknown". Operation-level params override path-level ones with the same name and location (4 GET ops declare both). Header params (2) are dropped. Scopes are the union over all `oauth2` security entries; there's no fallback to spec-level `security` (none exists), so an operation without one gets empty scopes and 1.3 rejects it (fail closed). `Response.kind` is `list` (array), `object` (object/`allOf`, with `list_keys` = array-valued properties and `links_next` = `_links.next` present), or `other` (non-JSON, `oneOf`/`anyOf`, untyped). Of 319 GETs: 133 list, 177 object, 9 other. **V8:** `listAuthenticatorEnrollments` declares a single `AuthenticatorEnrollment` as its 200 schema but returns a list, so the 1.3 check 9 must allow a registry override for spec-inaccurate shapes. Load takes ~1 s locally (design said ~0.5 s); the 2 s test may need loosening on slow CI runners | Probed the pinned spec; 17 tests |
| 2026-11-01 | 1.2 | `/code-review` fixes (supersede the row above where they differ): (1) path params are always `required` (the spec omits it on `getHookKey`'s `id`; a blank value would hit `listHookKeys`). (2) Separate `oauth2` security entries are alternatives, not a union: `Operation.scope_sets` holds one set per entry, empty entries dropped (they'd be always-satisfied); design §6.2 check 3, §5.6 and §9.4 updated. Only `getApplicationsCsvExport` and `listApplicationsBySearch` have more than one. (3) `list_keys` counts only arrays of objects: `get*` ops with candidates fell from 36 to 15 (e.g. `getGroup` → `objectClass` gone), but some remain (`getDevice` → `registrationGrants`), so check 9 now validates a declared `items_key` instead of requiring one from the spec. (4) Path template variables must equal the path params. (5) `allOf` cycles, non-dict schemas, malformed params and path-item `$ref`s raise `SpecError`. The index isn't deeply immutable: `Param.schema` holds plain dicts and lists, so 1.4 copies before changing them. Sharing `$ref` resolution with `update-spec.py` moves to 1.5 | Pinned spec probed for each finding; 27 tests |
| 2026-11-02 | T1 | All of [T1](design/t1-tool-surface.md) D1–D11 accepted. Refinements: (D5) view paths must exist in the **base** schema of polymorphic items (20 of 133 list operations), and an explicit `select` is not checked against the schema, so custom profile attributes stay selectable; (D6) pruning removes `null`, `{}`, `[]` and keeps `""`; (D7) logs with `select: "*"` stop on `max_bytes` at ~33 events and resume through `skip`. Design §5–7 and §11.3 change in the steps that implement each decision (T1 §8), not now, so the design describes built behavior. 1.3 now also needs the spec index to keep response property paths (a 1.2 follow-up) | User decision on the proposal; polymorphic count probed on the pinned spec |
| 2026-11-02 | 1.3 | Spec index: `Response.fields` (dotted paths of the object, or of each item of a top-level list) and `item_fields` (`items_key` candidate → its items' paths; `list_keys` is now derived from it). Arrays are leaves; a schema repeated on its own path is a leaf (recursion ends). Polymorphism: a discriminated base keeps only its own properties (the mapping is ignored); `oneOf`/`anyOf` gives the intersection of the variants. Load time unchanged (~1 s, ~10k paths). Registry: pydantic models with `extra="forbid"` (a typo like `arg_rules` fails instead of dropping a rule); errors from all files are collected into one `RegistryError`. Overrides take a mandatory `reason` instead of a YAML comment (comments don't survive parsing): `okta_scopes_override: {scopes, reason}`, allowed only when the spec declares no scopes; `response_override: {kind: list, reason}` for V8 (`listAuthenticatorEnrollments`). Extra checks beyond §6.2: `after`/`limit` can't be args, `page_size` needs `limit`, required query params need an arg, one arg per spec param, `paginate` only on list commands, views never under `_links`, file name = `<domain>.yaml`. D3 "classification differs" = different `data_classes` set or `arg_rule`s; differing `allowed_values` alone do not count. The packaged `data/registry/` is absent until 1.6, so the shipped registry is empty | Probed the pinned spec; 153 tests |
| 2026-11-02 | 1.3 | `/security-review`: no findings at confidence ≥ 8. Hardening applied: registry YAML rejects duplicate mapping keys (PyYAML keeps the last, so a second `data_classes` or `arg_rule` would silently replace the reviewed one, a hole `extra="forbid"` can't see). YAML errors become a `RegistryError` naming the file. The policy loader (3.1) should reject duplicate keys the same way | Review finding scored 3/10 (trusted, reviewed input) but cheap to close; 157 tests |
| 2026-11-02 | 1.3 | `/code-review` fixes. Six pinned-spec operations could never be registered. `after` now makes an operation a list command: an object response needs an `items_key`, which may name an array of plain values (new `Response.scalar_lists`) only on such operations, so `getGroup` → `objectClass` stays rejected. `_links.next` counts only for list commands (`getIdentityProviderApplicationUser` is a single resource). A view is required only when list items declare properties (`listInterclient*Applications`, `listAllSignInWidgetVersions`). YAML: merge keys may be overridden, unhashable keys and `.yml` files are `RegistryError`s, and errors from every file are reported together. A required `limit` needs `page_size`; `path_param`/`query` must be non-empty. Not changed: `fields()` ignores `oneOf` inside an `allOf` part (none in the pinned spec; revisit on spec update), and response schemas are walked twice (~1 s load) | Probed the pinned spec; 165 tests |
| 2026-11-02 | 1.4 | `registry/schema.py` builds each command's argument schema at load; `Command` carries `schema` (read-only top level) and `synopsis`. Spec keywords kept: `type`, `enum`, `pattern`, `minimum`/`maximum`, `minLength`/`maxLength`, `maxItems`, and `items` recursively. Dropped: descriptions, examples, defaults, the spec's prose `format`s (`"Opaque token"`, `"ISO 8601 compliant timestamp"`) and `oneOf` (only on `roleRef`, where it allows any string). Path params are always `string`. Overlays: the arg name is the rename; `allowed_values` sets `enum` (on `items` for arrays), must be a subset of a spec enum, only on string args, and `[]` on a required param is an error; `maxItems` only on arrays; a registry `pattern` is an error where the spec already sets one (9 path params), so it can't replace a spec constraint. New field `one_of_required: [a, b, …]` means **exactly one** (`oneOf` of `required`). Synopsis: `<required>`, `[optional]`, `<a\|b>` for `one_of_required`; the cap (T1 D1) is on `usage + "  " + summary`, column padding excluded; over it, optional args collapse to `[options]`, and still over it is a load error. The design's own `get-enrollments` example ("Authenticator enrollments for a user") is over, so Phase 5 summaries must be short. Help text (D11): arg descriptions are the first sentence of the spec description (HTML and Markdown links removed, ≤ 100 chars), or "user ID (00u…) or exact login" for `resolve: user_id`. `validate_args` raises `InvalidArguments` with every problem, sorted, never echoing values; option lists capped at 20 (T1 §3.4). Note for 2.6: `jsonschema` checks `pattern` with `re.search`, so `$` also matches before a trailing newline; the §6.4 control-character rule must still run on path values | Probed the pinned spec; 184 tests |
| 2026-11-02 | 1.4 | `/code-review` fixes: (1) a registry `pattern` on an array arg was set on the array and checked nothing; `pattern` and `allowed_values` now go on `items`, and the spec-conflict check looks there too. (2) `type` could replace a spec type and widen the arg (`type: string` on `labels` accepted any string); it now only fills a missing type. (3) Duplicate names in `one_of_required` made a command uncallable; now a load error. (4) Unknown key names in `invalid_arguments` were echoed unbounded; now cut to 40 chars, at most 20. (5) Help text now states item constraints (`each min length 20`). (6) Design §5.1/§5.3 still said `okta_help` returns JSON Schema; fixed (merging `okta_status` stays with 3.3). (7) `integer` args accepted `5.0` (JSON Schema 2020-12); the validator's type checker now takes only non-bool `int`. (8) The validator is built once at load (`Command.validator`), not per call | 7 new tests, each failing on the pre-fix code; 191 tests |
| 2026-11-02 | 1.5 | Catalogue (`docs/coverage/catalogue.yaml`, okta-skills commit `d6c8725`, minus ai-agents and terraform): **206 commands in 23 domains: 170 simple, 30 resolved, 4 composite, 2 excluded**. Extracted once by a script in a scratch directory outside the repo, then kinds, `items_key`, gotchas and exclusions set by hand against the pinned spec. Resolved = every `users` command taking a user except `get` (okta-skills resolves logins there too). Composite: `logs timeline`/`login-failures`/`diagnose` and `apps get-saml-metadata` (XML, not JSON). Excluded: `getAerialConsent` (`okta.orgs.manage`), `listSupportedSecurityQuestions` (`apiToken` only). `paginate` comes from the spec (53 paginate, 10 of them `link_or_body`; 12 need `items_key`). Variants (users/groups `search`, `logs list` filters) share one operation, so the report counts an entry done when its domain registers each of its operations, not by command name (check 5). **M3 re-estimated 8–10 d → 7–9 d** (total ≈32–35 d): 200 commands (198 registry entries), not ~230, and only 5 (2.5%) gotcha endpoints need a recorded fixture. **V8 gotchas:** `listJwk` and `listOAuth2ResourceServerJsonWebKeys` return `{"keys": [...]}`, so Phase 5 extends `response_override` to a wrapped object with `items_key`; `listAuthenticatorEnrollments` (list, done in 1.3); `listActiveIdentityProviderSigningKey` and `listRefreshTokensForAuthorizationServerAndClient` are noted in the catalogue. 118 of 319 spec GETs are in neither catalogue nor registry (listed in the report, informational). `ref_target` in `registry/spec.py` is now shared with `update-spec.py` (with `SpecError`); `tests/scripts/_load.py` has `load_script` | Report generated; 23 new tests; 214 tests |
| 2026-11-02 | 1.5 | `/code-review` fixes: (1) the catalogue loads with the registry's duplicate-key loader (now public `UniqueKeyLoader`), so a repeated command can't silently drop one. (2) Excluded entries' operations must exist in the spec too (both are indexed GETs). (3) `paginate` and `items_key` are checked against the pinned spec with the loader's rules, so a spec update that changes them fails the catalogue test. (4) YAML, file and spec errors exit 2 with a message. (5) `load_script` lives in `tests/scripts/_load.py`, not `conftest.py` as the step said: importing a conftest by name breaks once a second conftest exists. (6) Counts corrected: 12 `items_key`, not 13; 200 commands are 198 registry entries. Not changed: non-string YAML keys crash rather than report (hand-edited, reviewed file), and `run()` tests reload the spec (~2 s) | 8 new tests; 222 tests |
| 2026-11-03 | 1.6 | Pilot registries: `network-zones` (2 commands) and `groups` (11; catalogue `search` is `list` with `q`, T1 D3). Classes: groups/zones/rules/apps `org-config`; `get-members`, `get-owners` `pii`; the four role commands `admin-roles` (sensitive, `okta.roles.read`). **Free-form `filter`/`search`/`q` all `raises_sensitivity_to: sensitive`** (fail closed; the arg-rule vocabulary has no "reviewed, stays normal" option), so under the §9.3 example policy group lookup by name needs `include_sensitive` — revisit with 3.1/3.2 if that's too strict. `expand` closed with `allowed_values` (single values only; comma-joined lists are rejected). `fields` on `listGroups` not exposed (`select` covers it). ID patterns: group `^00g…{17}$`, zone `^nzo…{17}$`, group rule `^0pr…{17}$`; role assignment IDs are base32 role types or `irb…`/`ra…`, so `^[A-Za-z0-9]{1,64}$`. `page_size` 200, 20 on role targets (spec max). `list` is not resumable with `q` (unpaged). Synopsis cap forced short summaries on the role-target commands | Coverage report: both domains complete (14 done); 20 new tests; 242 tests |
| 2026-11-03 | 1.6 | `/security-review`: no findings. `/code-review` fixes: (1) `groups list` `expand: stats` returns `_embedded.stats.hasAdminPrivlege` (admin-role data) from a normal command; `expand` now `raises_sensitivity_to: sensitive`. (2) `pattern` used Python `$`, which matches before a final `\n`, so an ID plus newline passed every anchored pattern; `registry/schema.py` now checks patterns with ECMA-262 `$` (unescaped `$` outside a class → `\Z`). (3) The path-injection test now requires the error to name the bad arg. (4) `list-role-app-targets` view gains `id`. **V14 for `groups get-apps`:** `org-config` kept; the spec says `client_secret` is only shown on create/update, and `credentials.oauthClient.client_secret` stays on the 2.7 scrub list as backstop; confirm with a live fixture in 5.x. Deferred: `q` vs `page_size` (2.10), shared spec fixture (post-v1 backlog). Second `/security-review` (low): the model's load-time pattern check used plain `re.compile`, so a pattern the `\Z` translation breaks (`[]$]`) loaded and then raised on first use; `ecma_pattern` moved to `registry/model.py` and the load check uses it | 4 new tests; 246 tests |
| 2026-11-03 | 0.6 | Project review: architecture stands. Client sign-in (V3) moves from 4.6 to a new spike step 0.6, and Phase 2–4 work runs as a thin slice to stdio dev mode (see the ordering note at the top) | V3 is the one unknown that could block Path A; T1 decisions need a real model before cursors and Phase 5 build on them |
| 2026-11-03 | 0.6 | Claude Code signs in (both test users). It requests `offline_access`, so the rule now allows it in `scripts/okta-setup.py` and `terraform/okta/` (without it: `no_matching_policy`). **Refresh tokens are an admin choice, not a server design point:** A (none) is the default; B (`refresh_tokens: {idle_minutes, lifetime_minutes}`, ≤24 h) adds the refresh grant with rotation on the client apps and bounds the rule's refresh lifetimes. Group removal and role changes take effect within one access-token lifetime under both; under B a refused refresh token survives, so permanent removal also revokes tokens. Design §8.3, §9.6, Appendix C; guide in `docs/okta-setup.md` | Spike findings (A, B, group removal and move); 11 new tests; 257 tests |
| 2026-11-03 | 0.6 | `/security-review`: no findings. `/code-review` fixes: (1) adding `offline_access` removed the accidental refresh block under A, so the A rule now caps refresh lifetime and idle window at `access_token_minutes` and `check` flags longer ones (a client app given the refresh grant by hand gains at most one access-token lifetime); (2) a missing idle window counts as unlimited; (3) B checks rotation leeway ≤30 s; (4) the docs say "untrusted" doesn't remove an app from the access policy; spike-findings dates marked UTC. Not flagged: extra hand-registered clients in the access policy (documented in Limits) | 7 new tests; 264 tests |
| 2026-11-03 | 0.6 | Okta sessions vs refresh tokens (B): clearing sessions without `oauthTokens=true` leaves the refresh chain working; with it, the next refresh fails `invalid_refresh_token`. So the Global Session Policy doesn't bound a refresh chain, and `lifetime_minutes` is the effective re-sign-in (and MFA) interval. Runbook in `docs/okta-setup.md` names the exact revocation | Spike findings (System Log 03:33–03:36 UTC) |
| 2026-11-04 | 2.1 | `config.py`: `load_config(environ)` → frozen `Config` (pydantic, field aliases = variable names) or `ConfigError` listing every per-variable problem; rules spanning variables run once those pass. Messages name the variable, never the value, and the pydantic error isn't chained (its text shows inputs). Rules beyond the §11.3 table: an empty variable is unset; `_FILE` for the two secrets, `MCP_CURSOR_KEY` and `OKTA_API_TOKEN` (not both forms); `MCP_PUBLIC_URL`, `MCP_ISSUER` and `MCP_ALLOWED_CLIENT_IDS` required only outside dev mode; `OKTA_CLIENT_ID` + `OKTA_PRIVATE_KEY_FILE` required unless `OKTA_API_TOKEN` (dev mode only, never both); URLs https with a host, no credentials, query, fragment, whitespace or control characters (`MCP_PUBLIC_URL` may be http on a loopback host), `OKTA_ORG_URL` an origin only; **`OKTA_SCOPES` must all end in `.read`** (read-only invariant); `*` must be the only client ID; files must be readable at startup (policy, private key, dev principal); numbers positive, finite, `MCP_DEFAULT_LIMIT ≤ MCP_MAX_ITEMS`. Config stays transport-agnostic: the HTTP app (4.2) refuses `dev_mode`, and stdio without dev mode is 4.1's check. Key contents and policy are parsed by 2.2 and 3.1 | 73 tests; 337 tests |
| 2026-11-04 | 2.1 | `/code-review` fixes (supersede the row above where they differ): (1) an empty `_FILE` secret is an error, not an empty secret; (2) every value is stripped, so whitespace-only counts as unset and a padded `MCP_REQUIRED_SCOPE` can't reject every token later; (3) the cross-variable rules are a model validator, so no `Config` instance can hold dev mode or SSWS in production; (4) `OKTA_ORG_URL` is canonicalised (lowercase host, default port dropped, empty port rejected) because the 2.3 origin check and DPoP `htu` are built from it; (5) the `os.environ` test clears inherited variables; (6) `_FILE` read errors are reported alone, without the misleading "required" errors that followed; (7) the `*`-only rule is per-variable, so it's reported with other variable errors; (8) `MCP_ALLOWED_ORIGINS` entries are validated and canonicalised like `OKTA_ORG_URL` (http allowed on loopback), so a trailing slash or `*` fails at startup instead of 403-ing every browser request; (9) the cursor key also takes line-wrapped and unpadded URL-safe base64, and `MCP_LOG_LEVEL` is case-insensitive; (10) unreachable `isinstance` branches removed | 21 new tests; 358 tests |
| 2026-11-04 | 2.1 | Second `/code-review`. Fixed: (1) `ConfigError` is raised outside the `except`, since `from None` still kept the ValidationError (inputs, i.e. secrets) as `__context__`; (2) http on loopback refused for `MCP_PUBLIC_URL` and `MCP_ALLOWED_ORIGINS` when `MCP_ENV=production`, and `::1` dropped from loopback to match `scripts/okta-setup.py`; (3) the "no invalid `Config`" guarantee is stated for validated instances only (`model_copy(update=…)`/`model_construct` skip validators); (4) hosts must be ASCII (punycode) with no trailing dot, port 0 rejected; (6) `MCP_REQUIRED_SCOPE` and `MCP_GROUPS_CLAIM` must be one word; (7) `MCP_DEV_PRINCIPAL_FILE` is checked only in dev mode. Not changed: (5) `MCP_PUBLIC_URL`/`MCP_ISSUER` are kept verbatim, since they must equal the AS's audience and issuer strings exactly and rewriting them could break a match; (8) splitting auth and credential settings into sub-models/unions waits for real consumers in 2.2 and 4.3; (9) the startup readability check stays (§11.3 asks for fail-fast on an unreadable key); (10) `*.example.com` hosts other than `example.okta.com` in tests stay, since tests need hosts that are not the org (attacker links, origins, this server); AGENTS.md's fixture rule now says so | 10 new tests; 368 tests |
| 2026-11-05 | 2.2 | `okta/token.py`: `TokenProvider.token() -> ServiceToken` (`value` hidden from repr, `scheme` `Bearer`/`DPoP`/`SSWS`, `.authorization` header value); the 2.3 client adds a proof when the scheme is `DPoP`, using the same `DPoP` instance the provider was given. `ClientCredentialsProvider` posts to the **org** AS `{OKTA_ORG_URL}/oauth2/v1/token` (Management API scopes), the only non-GET request the server sends to Okta, to that fixed URL only; a fresh assertion and proof on the nonce retry. Cache expiry uses the monotonic clock (a wall-clock step can't keep a stale token); assertion dates use wall time. Scopes sent sorted. No `kid` header when `OKTA_KEY_ID` is unset (Okta then tries the app's keys; `scripts/okta-setup.py` always prints one), rather than guessing the RFC 7638 thumbprint, which differs from a kid registered by hand. **Fail closed on scheme:** DPoP on but Okta issues `Bearer` (app without "Require DPoP") is an error naming both fixes, not a silent downgrade; DPoP off but `invalid_dpop_proof` hints to turn it on. `TokenError` carries status, OAuth `error` code (only `[a-z_]{1,64}`) and a hint; never `error_description`, bodies, tokens or the assertion, and a transport error isn't chained (the httpx error holds the request body, i.e. the assertion). Failures aren't cached. `load_private_key` takes unencrypted PEM RSA ≥ 2048 bits and raises `ConfigError` naming only the file. `okta/dpop.py`: `DPoP` holds one P-256 key and the last valid `DPoP-Nonce` seen on any response (one nonce for token and resource endpoints, as V15 found Okta accepts); `needs_retry` is true only for `use_dpop_nonce` (400 body at the token endpoint, 401 `WWW-Authenticate` at the resource) that came with a valid nonce (RFC 9449 NQCHAR, ≤512), so the caller retries at most once. The fake provider lives in `tests/okta/_fakes.py`, not `src/`. `/security-review`: no findings. Carried to 2.3: create the shared `AsyncClient` with TLS verification on and redirects off (a followed redirect would replay the assertion or a DPoP token off the org) | 53 tests; 421 tests |
| 2026-11-05 | 2.2 | `/code-review` fixes (supersede the row above where they differ): (1) expiry counts from before the first token POST, since Okta's `expires_in` starts then and the request (two with the nonce retry) would eat the refresh margin; (2) a `DPoP-Nonce` on the retry response is kept too; (3) callers queued behind a failed token request don't each send their own: a failure counter makes them share the error (the next caller after them tries again), so an outage costs one POST, not 20 in a row; (4) a failed refresh inside the 60 s margin returns the still-valid token and logs a warning, failing only once it has actually expired; (5) `expires_in` ≤ 60 s or JSON `true` is malformed (it could never be served from the cache, so every call would POST); (6) the resource `use_dpop_nonce` check also takes the unquoted token form (RFC 7235); (7) a wrong `token_type` is no longer echoed in the error; (8) design §6.5 states the nonce rule as built (a nonce from any response is kept; retry only on `use_dpop_nonce` with a nonce). Second `/security-review`: no findings. Noted: `time.monotonic` stops while a Linux host is suspended, so after a resume a token Okta has expired may be served until a 401 (availability only); 2.3 could drop the cached token on `401 invalid_token` | 8 new tests; 429 tests |
| 2026-11-07 | 2.2 | Live check against the trial org with the spike service app ("Require DPoP" on, `okta.users.read okta.groups.read`, `kid` sent). DPoP on: the first token POST gets `400 use_dpop_nonce` with a nonce, the retry gets a `DPoP` token (3600 s), the second `token()` call is served from the cache, and a DPoP-signed `GET /api/v1/users?limit=1` returns 200 with no resource-side nonce challenge. DPoP off: `400 invalid_dpop_proof` with the "requires DPoP" hint. Then with "Require DPoP" turned off on the app: DPoP on gets `200` with `token_type: Bearer` and no nonce challenge (**Okta ignores the proof and silently issues a Bearer token**, the downgrade the provider refuses), and the provider raises "token_type is not DPoP" with the fix; DPoP off gets a `Bearer` token (3600 s, cached) and the users GET returns 200. `SSWSProvider`'s header also returns 200 | live run, nothing printed beyond status codes, scheme and lifetime |
| 2026-11-07 | 2.3 | `okta/client.py`: `new_http_client()` builds the one `AsyncClient` (shared with the token provider) with `verify=True`, `follow_redirects=False`, 10 s connect / 30 s other timeouts, default pool limits; a 3xx is an `UpstreamError`, never followed. **CA bundle** (0.4 follow-up): httpcore2's default context uses `SSL_CERT_FILE`/`SSL_CERT_DIR` if set, `truststore` (OS store) on macOS/Windows, else OpenSSL's compiled-in paths or common CA files, so 7.1's image needs `ca-certificates`. `OktaClient.get(url, params)` → 2xx `Response`: the URL's (scheme, host, port, userinfo) must equal `OKTA_ORG_URL`'s, checked on the same `httpx2.URL` parse that is sent, before the token is fetched (`OriginError`, mapped to `internal_error` by 2.10); one `anyio.Semaphore` slot per call, nonce retry included; the client takes the provider's `DPoP` instance (one key, one nonce) and adds a proof only for a `DPoP` token. **Request counter:** an `on_request` callback run before every request sent (nonce retries count); the principal contextvar and limiter come with 2.4. **Errors:** `UpstreamError(status, message)`: 401/403 → "contact the MCP administrator" with no Okta text (operator log gets the status only); others carry `errorSummary` truncated to 500 characters, or just the status; transport errors are `status=None` with the exception type only, not chained (the httpx error holds the `Authorization` header). 429 is an `UpstreamError` until 2.4. **401 drops the cached token** (2.2 carry-over): `TokenProvider.invalidate(token)` clears the cache only if it still holds that token (a late 401 can't evict a newer one); SSWS no-op. Any non-nonce 401, not just `error="invalid_token"`, since Okta's 401 shape for a DPoP-bound token wasn't confirmed live; no automatic retry with the new token (the next call gets it) | 30 new tests; 459 tests |
| 2026-11-07 | 2.3 | `/code-review` fixes (supersede the row above where they differ): (1) `params` are merged into the URL's query (`copy_merge_params`; a key in both takes the `params` value), where httpx2's `build_request(params=…)` replaced it, which would have dropped a next link's `after`; (2) a 401 `use_dpop_nonce` that wasn't retried (no valid nonce, or the retry got another) doesn't drop the token, since the proof failed and a new token costs a POST per call; `invalid_dpop_proof` still drops it, because Okta's 401 for an expired DPoP-bound token is unconfirmed and keeping a dead token would recreate the post-suspend wedge. Detection reuses `dpop.use_dpop_nonce` (one `WWW-Authenticate` parser); (3) a `TokenError` passes through `get()` unchanged: 2.10 maps it to `upstream_error` with a fixed "service credentials are unavailable" message, not the provider's hint (operator-facing, already logged); (4) a `DPoP` token with no `DPoP` key on the client raises `RuntimeError` before the resource request (the token POST has already gone), instead of going out without a proof. `copy_merge_params` re-encodes an existing query when `params` is non-empty; 2.5 follows next links with no `params`, so Okta's links go out byte for byte. `/security-review` (client and `invalidate`): no findings | 10 new tests; 469 tests |
| 2026-11-07 | 2.3 | Third `/code-review` (supersedes the rows above where they differ): (1) `OktaClient.get` turns a `TokenError` into `UpstreamError(None, "Okta service credentials are unavailable; contact the MCP administrator")`, not chained, so no caller can pass the provider's hint (already logged) to a user; (2) `dpop.use_dpop_nonce` at the resource is true only when `use_dpop_nonce` is the sole `error` value in `WWW-Authenticate`, so a header that also says `invalid_token` drops the token and isn't retried. Kept: `invalid_dpop_proof` drops the token (row above); the DPoP-key check stays per request until 4.1 wires one `DPoP` into both; the token fetch inside the in-flight slot (every queued call needs the same token) | 4 new tests; 473 tests |
| 2026-11-07 | 2.4 | `okta/ratelimit.py`. **429:** `retry_wait(response, max_wait)` = `x-rate-limit-reset` − the response's `Date` (local clock only if `Date` is absent or unparseable), floored at 0; over `OKTA_RATE_LIMIT_MAX_WAIT` → `RateLimited` (cap checked before jitter, so a wait equal to the cap still retries); then + jitter U(0, 1 s); if that doesn't end before the current anyio deadline (`current_effective_deadline`) → `RateLimited` at once rather than a later `timeout`. No or non-integer `x-rate-limit-reset` → `RateLimited`, no retry (fail closed). `OktaClient.get` retries once; a second 429 → `RateLimited`. Each attempt (with its nonce retry) holds its own in-flight slot, so the slot is **free during the 429 sleep**. New required `OktaClient(rate_limit_max_wait=…)`. `RateLimited` is its own exception (not an `UpstreamError`); 2.10 maps it to `rate_limited`, message safe to return. **Limiter:** `principal: ContextVar[str | None]` (the caller's `uid`) lives in `ratelimit.py` until Phase 4 sets it; `RequestLimiter(per_minute).charge` is the client's `on_request`, a sliding 60 s log per principal (exact count, ≤ `MCP_REQUESTS_PER_MINUTE` timestamps each), rejected requests not counted, nonce and 429 retries counted; principals idle for a full window are dropped by a sweep at most once a minute. A request with no principal set raises `RuntimeError` (→ `internal_error`) rather than going unmetered. Logs: 429 retry, second 429, limiter rejection as warnings, no bodies (structured events in 6.2). Single-process only (shared limiting across replicas stays future work) | 41 new tests; 500 tests |
| 2026-11-07 | 2.4 | `/code-review` fixes (supersede the row above where they differ): (1) the limiter charges **before** the in-flight slot and the service token are taken (`OktaClient._charge` in `get`, and before the nonce retry), and a 429 retry is charged **before** the wait, so a principal at its limit fails at once instead of after holding a slot, refreshing a token or sleeping; (2) the wait must leave 1 s (`_RETRY_HEADROOM`) before the deadline for the retry itself; (3) an `x-rate-limit-reset` too large for a float is treated as missing (`OverflowError` → `RateLimited`, not `internal_error`); (4) a second 429 reports its own reset (`rate_limited(response)`); (5) "try again in N s" rounds Okta's wait without jitter. **Kept:** freeing the slot during the 429 sleep, even though concurrent callers' retries then land within the same ~1 s jitter window on an exhausted bucket; holding it would stall other users' requests to unrelated buckets. Revisit with per-bucket pausing (R6) if logged 429s show second-429 failures | 4 more tests; 504 tests |
| 2026-11-07 | 2.4 | Live check against the trial org, run twice (spike service app, DPoP on, `max_inflight=20`, `rate_limit_max_wait=10`, limiter wired with a principal set): 400 concurrent `GET /api/v1/users?limit=1` in 5 s. The bucket is **300/min** for this endpoint on this org (`x-rate-limit-limit: 300`); 301 × 200 then 123 × 429 both runs. Every 429 carried `Date` and an epoch-seconds `x-rate-limit-reset`; the first reset was 56 s after `Date`. `Date` − local clock stayed within −1.03…−0.03 s (`Date` is truncated to the second, so reset − `Date` can overstate the wait by up to 1 s, the safe direction). Over-cap 429s failed at once with an accurate countdown ("try again in 56 s" down to "11 s"); a probe with 9 s left slept and its retry got 200 (call took 10.1 s); no call got two 429s; at most 2 requests per call. No resource-side nonce challenge; the token POST did the usual `400 use_dpop_nonce` then 200. **Note for later:** `MCP_REQUESTS_PER_MINUTE` defaults to 600, above this org's 300/min users-list bucket, so one principal can exhaust that bucket for everyone (R6) | live run, nothing printed beyond statuses, rate-limit headers and timings |
| 2026-11-09 | 2.5 | `okta/paginate.py`: `paginate(client, url, params, *, mode, items_key)` yields `(item, page, index_in_page)`, where `page` (the page state) is the relative path and query that fetched the page (`response.url.raw_path`; the first page's includes `params`), ready for the 2.9 cursor's `page.rel`. Also handles `mode: none` (one page, links ignored), so list commands without pagination go through the same generator. The expected path is the first request's path (built by 2.6), not passed separately. A next link is joined to the page URL (so a relative link works), then must match scheme, host and port with no userinfo, and its path must equal the first path after `normalise_path` (upper-case escapes, decode unreserved only; `%2F` stays encoded). httpx2 removes literal dot segments when parsing but keeps `%2e%2e`, which then decodes to `..` and fails the compare. Each hop is `client.get(str(target))` with no `params`. Stops on a page with no items (even with a next link) or an empty/absent next link. A body that isn't the expected list (wrong shape, missing `items_key`, non-JSON) or a refused next link raises `PaginationError` with a fixed message; 2.10 maps it to `upstream_error`. A next link equal to the current page isn't detected: it would repeat until the 2.8 item cap or deadline | 67 new tests; 571 tests |
| 2026-11-09 | 2.5 | `/code-review` fixes (supersede the row above where they differ): (1) a next link equal to the page just fetched raises `PaginationError` ("repeats the page") instead of looping; (2) `page` stays as sent, so 2.9 compares paths with `normalise_path` (added to 2.9); (3) design §6.5 now states `mode: none`, the page-state format and the empty-page stop. Not changed: the next link's query isn't pinned (design compares path only; the link is Okta's own), `rel="next last"` isn't parsed (Okta sends `rel="next"` alone), the paginator keeps its own origin check besides `client.get`'s as a second check on a trust boundary. `/security-review`: no findings | 2 new tests; 573 tests |
| 2026-11-09 | 2.6 | `exec/params.py`. `build_request(command, args, org_url) -> (url, params)` runs `validate_args` itself (so no caller can skip the schema, and with it `pattern`), then the §6.4 character rule on every path arg, reporting every bad arg in one `InvalidArguments` that names args, never values. The rule rejects non-strings, `""`, `.`, `..`, > 256 characters, `/ \ % ? #`, `str.isspace` and all of Unicode category C (control, format such as U+200B, surrogates, private-use, unassigned; design §6.4 updated). Accepted values are encoded with `quote(safe="")`. `build_url(org_url, template, segments)` substitutes and then checks the parsed URL's origin (no userinfo) equals `org_url` and its `raw_path` equals the substituted template; a mismatch is a bug → `RuntimeError` (→ `internal_error` in 2.10). `path_segment(arg, value)` is public for the 2.10 resolver's `getUser` lookup and 2.9's re-derived URL. Query args go out under their spec name; booleans as `true`/`false`, integers as decimal; `page_size` is sent as `limit` here (2.10's `q` rule adjusts it). Array query values raise `TypeError`: no registered command has one, and Okta's encoding varies by endpoint (repeated keys vs comma-joined), so Phase 5 decides per endpoint with a recorded fixture. Non-ASCII stays allowed (encoded as UTF-8) for logins; lookalikes such as U+FF0F are not `/` after encoding. Regression suite: 21 payloads (§6.4 set plus `""`, tab, U+2028, U+200B, ID + `\n`, `None`, a list) × every path arg of every packaged command, plus unpatterned `getUser` and `listAssociatedServersByTrustedType` fixtures so the character rule is tested without a `pattern` in front; each asserts `invalid_arguments` and no request at a mock transport. `/security-review`: no findings | 323 new tests; 896 tests |
