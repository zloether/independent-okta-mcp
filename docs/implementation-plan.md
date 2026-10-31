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
| 0. Bootstrap & spikes | 0.1–0.5 | ◐ |
| 1. Spec & registry core | 1.1–1.6 | ☐ |
| 2. Okta client & executor | 2.1–2.10 | ☐ |
| 3. Policy & tool surface | 3.1–3.4 | ☐ |
| 4. MCP server & auth | 4.1–4.6 | ☐ |
| 5. Registry authoring (all domains) | 5.0–5.7 | ☐ |
| 6. Audit, limits, logging | 6.1–6.2 | ☐ |
| 7. Packaging & deployment | 7.1–7.3 | ☐ |
| 8. Hardening & release | 8.1–8.4 | ☐ |

**Ordering note vs design §15:** the MCP server (Phase 4) comes *before* bulk registry authoring (Phase 5), so two pilot domains run end to end early and every later registry entry can be smoke-tested through the real server.

**Critical path:** 0.1 → 1.x → 2.x → 3.x → 4.x. The Okta dev-org spike (0.5) runs in parallel; only live checks (2.2 live item, 4.1 manual, 4.6) wait on it.

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

### 0.5 Okta dev-org spike — Path A and service app ◐
Design: §8.2–8.5, §10, Appendix C · Depends: — · **Needs: Okta dev org admin access (user-driven)**
Helpers under `spikes/okta/` (deleted with `spikes/sdk/` at end of 4.2). Run: `uv run pytest spikes/okta`; `uv run python spikes/okta/okta_spike.py --help`.
- [x] Create dedicated custom AS, scope `okta-mcp`, `groups` access-token claim emitting **IDs** of Okta-mastered `mcp-okta-*` groups, two test groups, two test users
- [x] `scripts/okta-setup.py` (`check`/`apply`) for admins, from the setup used here, and the equivalent `terraform/okta/` module; guide in `docs/okta-setup.md`
- [ ] Register a public OIDC client (PKCE); obtain a token via a real MCP client or a local PKCE script
- [ ] Record: claims present (`uid`, `sub`, `groups` as IDs, `cid`, `scp`) — **V1, V13**
- [ ] Test `resource` param on authorize/token — **V9**
- [ ] Test metadata discovery by each target client (OIDC discovery vs RFC 8414-only) and loopback redirect ports — **V10, V11**
- [ ] Create API Services app with `private_key_jwt`; record whether "Require DPoP" is on by default and Okta's nonce behavior — **V15**; grant `okta.users.read okta.groups.read`, assign Read-only Admin; fetch a token and call `GET /api/v1/users?limit=1`
- [ ] Write `docs/design/spike-findings.md` (one section per V-item: result, evidence, design impact)

Verify: findings doc complete for V1, V9, V10, V11, V13, V15; design doc updated where results differ.

---

## Phase 1 — Spec & registry core

### 1.1 Pin Okta spec ☐
Design: §6.1 · Depends: 0.1
- [ ] `scripts/update-spec.py`: download management-minimal spec, write `specs/PINNED.json` (source URL, version, sha256, fetched date), print added/removed/changed GET operations vs. previous pin
- [ ] Commit initial spec under `src/okta_mcp/data/specs/`
- [ ] `tests/test_spec_pin.py`: file hashes to `PINNED.json`

Verify: `uv run python scripts/update-spec.py --check` is a no-op on a clean tree; hash test passes.

### 1.2 Spec index ☐
Design: §6.1, §6.2 (checks 1–3, 9) · Depends: 1.1
- [ ] `registry/spec.py`: load with `yaml.CSafeLoader`; index **GET** operations by `operationId` → path template, path/query params (with schema, enum, pattern), `security.oauth2` scopes, tags, success response schema (list vs wrapped object, `_links`)
- [ ] Tests: known operations resolve (`getUser`, `listUserGroups`, `listAuthenticatorEnrollments`); non-GET ops absent; scopes extracted; operations without `oauth2` security report empty scopes; load time under 2s

Verify: `uv run pytest tests/registry/test_spec.py`

### 1.3 Registry model & loader ☐
Design: §6.2 · Depends: 1.2
- [ ] `registry/model.py`: pydantic models for domain file, command (simple/resolved; `handler` reserved for post-v1), args (`path_param`, `query`, `resolve: user_id`, `pattern`, `allowed_values`, `arg_rule`, `type`, `maxItems`), `paginate` (`link | body_links | link_or_body | none`), `items_key`, `page_size`, `data_classes`, `resumable`, `okta_scopes_override`
- [ ] Data-class → sensitivity table (reviewed config); sensitivity derived, never declared
- [ ] `registry/loader.py`: load all `registry/*.yaml`, resolve against spec index, run **checks 1–9** from design §6.2 (empty derived scopes is an error without override), produce immutable `Registry`
- [ ] Tests: one fixture registry per failure mode (non-GET op, missing path param, unknown query, empty scopes without override, missing/unknown data class, same-operationId sensitivity mismatch, widening arg without rule, unknown operation, wrapped response without `items_key`)

Verify: `uv run pytest tests/registry/`; every check has a failing fixture.

### 1.4 Argument schemas & synopsis ☐
Design: §5.3, §6.3 · Depends: 1.3
- [ ] Build JSON Schema per command from spec param schemas + registry overlays (`one_of_required`, `maxItems`, `pattern`, renames, `allowed_values`); validate with `jsonschema`
- [ ] Synopsis line generator (`get-groups <user>`, `list [filter] [search]`)
- [ ] Validation function returning `invalid_arguments` details naming valid keys/values
- [ ] Tests: snapshot schemas for pilot commands; error messages list valid options

Verify: `uv run pytest tests/registry/test_schema.py`

### 1.5 Coverage inventory ☐
Design: §5.6 · Depends: 1.2
- [ ] Build the okta-skills command catalogue (minus ai-agents) by hand or one-off script run **outside** this repo's code paths (reference only); save as `docs/coverage/catalogue.yaml`: domain, command, operationId(s), kind (simple/resolved/composite/excluded), pagination style and `items_key`, notes on gotchas, exclusion reason (e.g. `getAerialConsent`, `listSupportedSecurityQuestions`)
- [ ] `scripts/coverage-report.py`: catalogue vs registry vs spec GET ops → `docs/coverage/report.md`
- [ ] Count commands per kind; **re-estimate M3** in design §15 from the counts and the share of gotcha endpoints that need recorded fixtures

Verify: report generated; every catalogue entry has a kind; Decisions log records the counts and the new estimate.

### 1.6 Pilot registries ☐
Design: §6.2 · Depends: 1.3, 1.4
- [ ] `registry/network-zones.yaml` and `registry/groups.yaml`, fully classified, `pattern` on every ID path param
- [ ] Loader + schema tests pass with real files

Verify: `uv run pytest`; coverage report shows both domains complete.

---

## Phase 2 — Okta client & executor

### 2.1 Configuration ☐
Design: §11.3 · Depends: 0.1
- [ ] `config.py`: a pydantic model populated from `os.environ` for every variable in §11.3; `_FILE` variants; fail-fast messages; `MCP_ENV` handling (no `pydantic-settings` dependency)
- [ ] Tests: missing required vars, bad URLs, `*` client IDs warning, SSWS and dev mode refused in production, short cursor key rejected

Verify: `uv run pytest tests/test_config.py`

### 2.2 Token providers & DPoP 🔒 ☐
Design: §6.5, §10 · Depends: 2.1
- [ ] `okta/token.py`: `TokenProvider` interface; `private_key_jwt` provider (RS256, `kid`, 5-min, `jti`), client-credentials request, in-memory cache, refresh under `anyio.Lock` at <60s; SSWS provider (stdio dev mode only); a fake provider for tests
- [ ] `okta/dpop.py`: ephemeral EC P-256 key; proof builder (`jti`, `htm`, `htu` without query/fragment, `iat`, `ath`); nonce capture for `use_dpop_nonce` / `DPoP-Nonce`; `OKTA_DPOP=false` path
- [ ] Tests (mocked HTTP): assertion claims, refresh once under 20 concurrent callers, DPoP proof claims and nonce retry at the token endpoint, error mapping, key never logged
- [ ] Live check after 0.5: fetch a real token against the dev org (DPoP on and off as the app allows)

Verify: `uv run pytest tests/okta/test_token.py tests/okta/test_dpop.py`; `/security-review`.

### 2.3 HTTP client core ☐
Design: §6.5 · Depends: 2.2 (interface and fake only)
- [ ] `okta/client.py`: async HTTP client (`httpx2`, per 0.4; tests use `httpx2.MockTransport`), GET-only public API, global in-flight semaphore, timeouts, origin assertion on every request, per-request DPoP proof + nonce retry at the resource server, request counter hook (principal contextvar), error → `upstream_error` mapping with sanitized 401/403 text
- [ ] Tests: semaphore caps concurrency, non-origin URL refused, fresh DPoP `jti` per request, deadline cancellation aborts in-flight request

Verify: `uv run pytest tests/okta/test_client.py`

### 2.4 Rate limiting ☐
Design: §6.5 · Depends: 2.3
- [ ] `okta/ratelimit.py`: on 429, wait = `x-rate-limit-reset` − `Date` header (local clock if absent) + jitter; retry once if ≤ `OKTA_RATE_LIMIT_MAX_WAIT` and within the deadline, else `rate_limited`; per-principal Okta-request limiter (`MCP_REQUESTS_PER_MINUTE`)
- [ ] Tests: skewed local clock doesn't change the wait; wait over cap raises; retry once only; limiter window

Verify: `uv run pytest tests/okta/test_ratelimit.py`

### 2.5 Pagination 🔒 ☐
Design: §6.5, §7.2 · Depends: 2.3
- [ ] `okta/paginate.py`: async generator yielding `(item, page_state, index_in_page)`; modes `link`, `body_links`, `link_or_body`; `items_key`; next link must match origin **and** expanded path after RFC 3986 normalisation
- [ ] Tests: multi-page fixtures for each mode and a wrapped response; cross-origin / cross-path / encoding-variant next link raises; empty page stops; each hop goes through `client.get` (fresh DPoP proof)

Verify: `uv run pytest tests/okta/test_paginate.py`; `/security-review`.

### 2.6 URL builder & path-injection controls 🔒 ☐
Design: §6.4 · Depends: 1.4, 2.3
- [ ] `exec/params.py`: map validated args → path params (reject empty, `.`, `..`, >256 chars, and any `/ \ % ? #`, whitespace or control character; enforce registry/spec `pattern`; then encode with no safe chars) and query params mapping
- [ ] Injection regression suite generated over **every path param of every registry command** with the design §6.4 payload set (incl. `a/../b`, `a%2F..%2Fb`, `a\..\b`)
- [ ] Assert rejected payloads produce `invalid_arguments` and **no recorded request**; accepted values produce a URL whose origin == `OKTA_ORG_URL` and whose path matches the template

Verify: `uv run pytest tests/exec/test_params.py`; `/security-review`.

### 2.7 Output options & scrubbing ☐
Design: §9.2, §7.2 · Depends: 0.1
- [ ] `scrub.yaml` initial paths (design §9.2); `exec/output.py`: scrub → strip_links → select, per item
- [ ] Tests: fixture per scrub path; `select` dotted paths and arrays; `strip_links` nested

Verify: `uv run pytest tests/exec/test_output.py`

### 2.8 Envelope & budgets ☐
Design: §7.1, §7.2 · Depends: 2.5, 2.7
- [ ] `exec/envelope.py`: consume paginator item-by-item; stop on items / post-select bytes / deadline; `truncated`, `truncation_reason`, `untrusted: true`; single-resource shape; `result_too_large`
- [ ] Tests: cap mid-page, byte cap, deadline, non-list oversize

Verify: `uv run pytest tests/exec/test_envelope.py`

### 2.9 Cursors 🔒 ☐
Design: §7.3 · Depends: 2.8
- [ ] `exec/cursor.py`: HMAC-signed payload (single key), `uid`/tool/cmd/`args_sha256` (original args) binding, resolved `path_params`, relative `page.rel` only (first page = initial request), 15-min expiry; resume requires resent args matching the hash, re-derives the URL from `path_params` and checks the path against the template
- [ ] Tests: tamper, wrong uid, wrong args, expired, wrong key, absolute URL in payload rejected, first-page truncation, **resume yields every item exactly once on an unchanged list** across item and byte caps

Verify: `uv run pytest tests/exec/test_cursor.py`; `/security-review`.

### 2.10 Executor & resolver 🔒 ☐
Design: §5.5, §5.6 · Depends: 2.4, 2.6, 2.9
- [ ] `exec/executor.py`: (principal, tool, command, args, select, strip_links, limit, cursor) → envelope or structured error; policy check (incl. `arg_rules`) before any resolver or Okta request; deadline wrapper; maps exceptions to §5.5 codes
- [ ] `exec/resolve.py`: `user_id` only — `00u…` ID short-circuit, else exact `getUser` lookup, `not_found` otherwise; cached per call
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

Verify: refusal tests pass; pilot commands return real data from the dev org; `/security-review`.

### 4.2 HTTP app ☐
Design: §4, §5.2, §11.4 · Depends: 4.1, 0.4
- [ ] `app.py`: stateless Streamable HTTP at `/mcp`, `/healthz`, `/readyz`; per-principal list results with `cacheScope: "private"` + `ttlMs`; `Origin` validation (reject a present `Origin` not in `MCP_ALLOWED_ORIGINS`); `MCP_TRUST_PROXY`
- [ ] Delete `spikes/sdk/`
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
Design: §8.3 · Depends: 4.5, 0.5
- [ ] Run locally behind a TLS proxy (e.g. Caddy) or tunnel; connect each target MCP client via Path A (auth is always on, so exposure is safe)
- [ ] Start `docs/compatibility-matrix.md` (client × discovery × registration × works/limitations)

Verify: at least one real client completes OAuth and calls a pilot command; matrix started.

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

Verify: someone (or a fresh Claude session) follows the runbook on a clean machine to a working `/readyz`.

---

## Phase 8 — Hardening & release

### 8.1 Security review sweep ☐
- [ ] `/security-review` over all 🔒 paths together (cross-cutting issues)
- [ ] Resolve or ticket every finding

### 8.2 Compatibility matrix & E2E ☐
- [ ] Complete `docs/compatibility-matrix.md` for all target clients (Path A)
- [ ] E2E checklist: groups claim; per-role tool lists; revocation after token expiry; 429 behavior under load

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

---

## Open questions (blocking step → design §16 ID)

| ID | Question | Blocks | Resolved in |
|---|---|---|---|
| V1 | `groups` claim (IDs) on access tokens; >100 groups | 3.2, 4.3 | 0.5 |
| V3 | Client registration: pre-registered vs DCR vs CIMD | 4.6 | 0.5 / 4.6 |
| V4 | `.manage ⇒ .read` implication | 3.2 | 3.2 (Okta docs) |
| V5 | SDK v2 / 2026-07-28: stateless per-request principal, `cacheScope`, back-compat, auth helpers, `httpx` vs `httpx2` | 0.1 deps, 2.3, 4.2 | 0.4 ☑ (see Decisions log) |
| V6 | Read-only Admin sufficiency per domain | 5.x | 5.x |
| V8 | Spec accuracy (scopes, operationIds, params) | 1.3, 5.x | 1.5 / 5.x |
| V9–V11 | `resource` param, discovery, loopback, static client IDs | 4.4, 4.6 | 0.5 |
| V13 | `uid` vs `sub`; ID-emitting groups expression | 4.3 | 0.5 |
| V14 | Secrets in "normal" endpoints | 5.x | 5.x |
| V15 | DPoP default and nonce behavior | 2.2 live check | 0.5 |

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
