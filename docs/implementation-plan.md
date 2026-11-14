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
5. Run `/code-review` before opening a PR, on every step; fix the findings or record why not. Steps marked **🔒 trust boundary** (design §12.2) must also pass `/security-review` before merge. Neither replaces the other. Both outcomes go in the [decisions log](decisions-log.md).
6. Record anything learned that changes later steps in the [decisions log](decisions-log.md). Resolve **Open questions** when their blocking step arrives.
7. Update the step's status in the table below.

Status key: ☐ todo · ◐ in progress · ☑ done · ⏸ blocked

## Status

| Phase | Steps | Status |
|---|---|---|
| 0. Bootstrap & spikes | 0.1–0.6 | ◐ |
| 1. Spec & registry core | 1.1–1.6 | ☑ |
| 2. Okta client & executor | 2.1–2.10 | ☑ |
| 3. Policy & tool surface | 3.1–3.4 | ☑ |
| 4. MCP server & auth | 4.1–4.6 | ◐ |
| 5. Registry authoring (all domains) | 5.0–5.7 | ◐ |
| 6. Audit, limits, logging | 6.1–6.2 | ◐ |
| 7. Packaging & deployment | 7.1–7.3 | ◐ |
| 8. Hardening & release | 8.1–8.4 | ◐ |

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
Throwaway code under `spikes/sdk/` (deleted in 4.2; its tests live on in `tests/test_app.py`).
- [x] Choose and exact-pin `mcp` v2; confirm current protocol revision (2026-07-28 expected) and 2025-11-25 back-compat
- [x] Add a Dependabot `ignore` for `mcp` in `.github/dependabot.yml` (removed in 4.5; `mcp` now gets its own PR, outside the grouped one)
- [x] Low-level server (`on_*` handlers) over stateless Streamable HTTP
- [x] Per-request principal from a fake `Authorization` header (SDK auth hooks or ASGI middleware + contextvar)
- [x] `tools/list` returns different tools for two fake principals, with `cacheScope: "private"` and `ttlMs`
- [x] Return `structuredContent` + text fallback; tool `annotations`
- [x] Evaluate the SDK's resource-server helpers (`token_verifier`/`auth`, `get_access_token()`): do they cover PRM at both URLs and the design §8.5 checks?
- [x] Decide `httpx` vs `httpx2` for the Okta client, and the matching HTTP mock for tests (`respx` mocks `httpx` only)

Verify: SDK client (both revisions) shows different tool lists for the two principals. Findings and choices recorded in the [decisions log](decisions-log.md).

### 0.5 Okta dev-org spike — Path A and service app ☑
Design: §8.2–8.5, §10, Appendix C · Depends: — · **Needs: Okta dev org admin access (user-driven)**
Helpers under `spikes/okta/` (kept past 4.2 for the 4.1 manual run and 0.6; deleted with `spikes/oauth/` and the `spikes/**` ruff ignore once 0.6 and 4.6 are done). Run: `uv run pytest spikes/okta`; `uv run python spikes/okta/okta_spike.py --help`.
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
Pulled forward from 4.6: if a target client can't sign in with a pre-registered `client_id` and a fixed redirect URI (V11), Path A doesn't work for it, and that is cheaper to learn before Phases 2–4. `spikes/oauth/client_check.py` (kept until 0.6 and 4.6 are done; see 4.2) serves 401 + PRM at both URLs, validates real tokens from the spike AS, and exposes one `whoami` tool. Run: `uv run pytest spikes/oauth`.
- [x] Check server and tests (mock JWKS: valid token, wrong `aud`/`iss`, expired, missing `uid`, disallowed `cid`, missing scope → 403, `HS256`/`none`)
- [ ] For each target client: register its redirect URI on the spike public client, connect to `http://127.0.0.1:8000/mcp`, sign in as each test user, call `whoami` (Claude Code done)
- [x] Refresh tokens tested both ways (A: none; B: rotating); both supported by `scripts/okta-setup.py` and `terraform/okta/` via `refresh_tokens`, A the default; `offline_access` added to the rule in both
- [ ] Fill the compatibility matrix in [`design/spike-findings.md`](design/spike-findings.md) (discovery URLs from the server log, client-ID and redirect configuration, scopes requested, result)

Verify: at least Claude Code completes sign-in and `whoami` shows the user's `uid` and group ID; every target client has a matrix row. A client that can't connect is a design decision (drop it, or revisit §8.3), recorded in the [decisions log](decisions-log.md).

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

Verify: report generated; every catalogue entry has a kind; the [decisions log](decisions-log.md) records the counts and the new estimate.

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

### 2.7 Output options & scrubbing ☑
Design: §9.2, §7.2, [T1](design/t1-tool-surface.md) D4–D6 · Depends: 0.1
- [x] `scrub.yaml` initial paths (design §9.2); `exec/output.py`: scrub → `links` (T1 D4) → `select`/view or prune (D5, D6), per item
- [x] Tests: fixture per scrub path; `select` dotted paths and arrays; `_links` stripped nested; `"[redacted]"` survives pruning

Verify: `uv run pytest tests/exec/test_output.py`

### 2.8 Envelope & budgets ☑
Design: §7.1, §7.2, [T1](design/t1-tool-surface.md) D7, D8 · Depends: 2.5, 2.7
- [x] **(slice)** `exec/envelope.py`: consume paginator item-by-item; stop on items / post-select bytes / deadline; `truncated` (holds the reason, T1 D8), `untrusted: true`; table encoding and sparse envelope; single-resource shape; `result_too_large`. No `next_cursor` until 2.9
- [x] **(slice)** Tests: cap mid-page, byte cap, deadline, non-list oversize
- [x] Cursor resume: emit `next_cursor` (page state + in-page index of the last delivered item) and reserve its size in the byte budget; `warnings` on resumed responses (with 2.9)

Verify: `uv run pytest tests/exec/test_envelope.py`

### 2.9 Cursors 🔒 ☑
Design: §7.3 · Depends: 2.8
- [x] `exec/cursor.py`: compact HMAC-signed payload (T1 D10; single key, 128-bit tag), `u`/`t`/`c`/`a` (caller, tool, command, hash of the original args) binding, resolved path params `p`, the page's query string `q` only (first page = initial request's query), 15-min expiry; resume requires resent args matching the hash and re-derives the URL from the template and `p`. No path is stored, so the 2.5 review's "compare with `normalise_path`" item no longer applies: an equivalent-encoding next link's path is dropped and the template's is used
- [x] Tests: tamper, wrong uid, wrong args, expired, wrong key, absolute URL in payload rejected, first-page truncation, **resume yields every item exactly once on an unchanged list** across item and byte caps

Verify: `uv run pytest tests/exec/test_cursor.py`; `/security-review`.

### 2.10 Executor & resolver 🔒 ☑
Design: §5.5, §5.6 · Depends: 2.4, 2.6, 2.9
- [x] **(slice)** `exec/executor.py`: (principal, tool, command, args, select, links, limit, cursor) → envelope or structured error; policy check (incl. `arg_rules`) before any resolver or Okta request; deadline wrapper; maps exceptions to §5.5 codes
- [x] Order with the 3.2 engine: `(domain, command) in engine.permitted(principal)` first (else `forbidden_by_policy`, before schema validation, so a forbidden command's arg names don't leak through `invalid_arguments`), then validate args, then `engine.check(...)` on the validated args → `FORBIDDEN` / `INVALID` (→ `invalid_arguments`; an unreadable search or sort expression must never reach Okta) / `UNAVAILABLE` / `ALLOWED`. Proceed only on `ALLOWED`: match on it, don't treat "not refused" as allowed. `check` returns `FORBIDDEN` for an unknown arg name, so calling it before validation would turn a typo into `forbidden_by_policy`
- [x] Cursor wiring (2.9 built the parts; `call` in `tests/exec/test_cursor.py` shows the order): one `Cursors(config.cursor_key)` at startup; `resumable(command, args)` decides whether `list_result` gets `next_cursor`; with a cursor: validate the resent args, `Cursors.open`, **policy check on those args**, then `resume_url` → `paginate(client, url)` with no `params` → `after(items, skip)`, `warnings=(RESUMED_WARNING,)`, and no resolver call (the cursor's `p` is already resolved); a cursor on a non-list or non-resumable call and `CursorError` → `invalid_arguments`; `Cursors.issuer(...)` once per call with `cursor.path_params(command, resolved_args)`. Test that a role change between pages is enforced on the resumed call
- [x] `exec/resolve.py`: `user_id` only — `00u…` ID short-circuit, else exact `getUser` lookup, `not_found` otherwise; cached per call
- [x] `groups list` with `q`: Okta doesn't page `q`, so the forced `limit=200` (`page_size`) cuts results with no next link and no sign of truncation (1.6 review). Don't send `limit` when `q` is passed (or mark the result truncated); needs a registry field or executor rule, test with a mocked 250-item response
- [x] The resolver refuses `me`: `/api/v1/users/me` is Okta's alias for the token's own user (the SSWS token's owner in dev mode), and it is not a spec path, so `Operation.reserved` doesn't list it (2026-11-10 review)
- [x] Map `RuntimeError` from `OktaClient.get` (DPoP token with no DPoP key on the client) to `internal_error` (2.3)
- [x] One origin check shared by `okta/client.py`, `okta/paginate.py`, `exec/params.build_url` and `exec/cursor.resume_url` (four forms today; 2.6 and 2.9 reviews)
- [x] Tests: pilot commands end to end against mocked Okta; each error code reachable; forbidden call records no Okta request (no resolver oracle)
- [x] Dev-org check (2026-11-13, see [decisions log](decisions-log.md)): how Okta routes `/api/v1/users/me.json`, `/api/v1/users/me;x`, `/api/v1/groups/rules.json` and the like. **Matrix parameters are stripped** (`me;x` routes to `me`, `00u…;x` returns that user), so the `;` refusal is load-bearing; **suffixes are not** (`me.json`, `00u….json` are looked up as literals, `rules.json` is `E0000008`), so the `.` rule could be narrowed so logins such as `me.smith@…` resolve again (not done: a 🔒 change of its own)
Verify: `uv run pytest tests/exec/`; `/security-review` (resolver).

---

## Phase 3 — Policy & tool surface

### 3.1 Policy model & loader 🔒 ☑
Design: §9.3 · Depends: 1.3
- [x] `policy/model.py`, `policy/loader.py`: schema, load-time validations (group entries must be `00g…` IDs; domains/commands exist; no empty roles; duplicates), warnings
- [x] `tests/policy/fixtures/pilot.yaml`: example policy restricted to the pilot domains (network-zones, groups); test that it loads clean. The full `docker/policy.example.yaml` lands in 5.7
- [x] Tests: each validation failure

Verify: `uv run pytest tests/policy/test_loader.py`; `/security-review`.

### 3.2 Policy engine 🔒 ☑
Design: §9.1, §9.4 · Depends: 3.1
- [x] `policy/engine.py`: `permitted(principal) -> frozenset[(domain, command)]`, memoized by matched-role set, from the compiled `Role.allow`/`deny` sets (3.1; the loader already applied wildcard-vs-sensitive, so the engine must not re-expand patterns); a call whose args raise it to sensitive needs the grant in a matched role's `allow_raised`; wildcard excludes sensitive unless `include_sensitive`; deny wins; per-call check applies `arg_rules`; capability gate vs `OKTA_SCOPES` (V4: no `.manage ⇒ .read` table, see [decisions log](decisions-log.md))
- [x] Free-form `filter`/`search`/`q` rule, in three parts (2026-11-11, user decision on the last): `{reviewed: "<reason>"}` for filters over a closed set of returned fields (four pilot filters); `raises_sensitivity_to` where a filter adds rows (`get-owners filter`); `{attribute_expression: true}` for profile `search` and `sortBy`, checked per call against `scrub.yaml` (no role) and the role's `search_attributes` in the policy file
- [x] `policy/expression.py`: attribute names in a filter expression, failing closed; `scrubbed(attribute, rules)`
- [x] Dev-org check (2026-11-13, see [decisions log](decisions-log.md)): nothing the tokenizer accepts makes Okta match on an attribute it didn't list. Okta takes operators in any case and **folds attribute-name case** (`PROFILE.LOGIN` searches `profile.login`); the allowlist compares exactly (refuses the variant) and the redaction test lower-cases, so both fail closed. `TRUE` is a literal to Okta; an attribute on the right of a comparison, `eq null` and `not (…)` are 400s

Verify: `uv run pytest tests/policy/test_engine.py`; `/security-review`.

### 3.3 Tool definitions ☑
Design: §5.1–5.3 · Depends: 1.4, 3.2
- [x] `tools.py`: per-principal tool list (filtered enum + synopsis), `okta_help`, `okta_status`; annotations
- [x] Tests: two principals → different tools; `okta_help` on forbidden command → `forbidden_by_policy`; `okta_status` reveals nothing about other users/roles

Verify: `uv run pytest tests/test_tools.py`

### 3.4 Resources ☑
Design: §5.4, §3 · Depends: 3.2
- [x] `resources/filters.md`, `resources/expression-language.md`, guides for the two pilot domains (original text: okta-skills was not available, so nothing is copied and no attribution is needed)
- [x] `resources.py`: visibility per principal
- [x] Test: every command named in a guide exists in the registry

Verify: `uv run pytest tests/test_resources.py`

---

## Phase 4 — MCP server & auth

### 4.1 Dev mode over stdio 🔒 ✅
Design: §8.6 · Depends: 2.10, 3.3, 0.4
- [x] `auth/devmode.py`: `MCP_DEV_MODE` + principal file; refuse when `MCP_ENV=production`
- [x] `okta-mcp --stdio` entrypoint wiring executor + tools + policy; HTTP entrypoint refuses to start when `MCP_DEV_MODE` is set (`server.py` holds the wiring and the SDK handlers, for 4.2 to reuse)
- [x] Manual (after 0.5): connect Claude Code (or Inspector) to the dev org; run every pilot command (SDK stdio client, both role principals, 2026-11-12; `get-owners` not available on the org, see [decisions log](decisions-log.md))
- [x] `okta/client.py` drops the service token on every 401 that isn't a nonce challenge, but Okta's `E0000015` (feature not enabled, e.g. `get-owners` on an org without group owners) is a 401 too: each such call discarded a good token and cost a token request the limiter doesn't charge. The token is now kept for `E0000015` (see [decisions log](decisions-log.md))
- [x] Map `E0000015` to its own message ("this Okta feature isn't enabled on the org") instead of "contact the MCP administrator"; the `errorCode` is a fixed Okta code, not result data
- [x] T1 check (2026-11-12, recorded in [T1 §0](design/t1-tool-surface.md); D1–D11 unchanged): give the model a few real helpdesk-style tasks on the pilot domains; record tokens per call and whether it reads tables, uses `okta_help` and `select` correctly; revise T1 decisions in the [decisions log](decisions-log.md) before Phase 5 builds on them (2.9 was built first, 2026-11-10: if the check changes D8 or D10, `exec/cursor.py` and the envelope's `next_cursor`/`warnings` fields change with it)

Verify: refusal tests pass; pilot commands return real data from the dev org; T1 check recorded; `/security-review`.

### 4.2 HTTP app ☑
Design: §4, §5.2, §11.4 · Depends: 4.1, 0.4
- [x] `app.py`: stateless Streamable HTTP at `/mcp`, `/healthz`, `/readyz`; per-principal list results with `cacheScope: "private"` + `ttlMs`; `Origin` validation (reject a present `Origin` not in `MCP_ALLOWED_ORIGINS`); `MCP_TRUST_PROXY`
- [x] Delete `spikes/sdk/`; `spikes/oauth/` kept (0.6 is still open and `client_check.py` is the only 401 + PRM server until 4.4; see [decisions log](decisions-log.md))
- [x] Tests: health endpoints; bad Origin rejected, missing Origin allowed; `cacheScope` present

Verify: `uv run pytest tests/test_app.py`

### 4.3 Token verifier 🔒 ☑
Design: §8.5 · Depends: 4.2
- [x] `auth/verifier.py` (on top of SDK auth helpers where 0.4 found them sufficient): JWKS discovery + cache + rate-limited refetch; all §8.5 checks; returns `VerifiedToken` (4.2: `subject` = `uid`, `client_id` = the principal's, `claims["iss"]` set; all enforced), which `app.http_principal` reads; JWKS not loaded → 503 and `/readyz` not ready, with background retry (startup does not require the issuer)
- [x] 4.2 carry-overs ([decisions log](decisions-log.md), final 4.2 pass): gate readiness at the SDK's `/mcp` endpoint instead of by path; `ready()` errors logged once or rate-limited; `okta-setup.py` URL messages fixed and tested; §11.3 wording
- [x] `Verifier.ready()` false until the JWKS loads: 4.2's `ReadyGate` already answers `/mcp` with 503 + `Retry-After` from it, before the SDK's auth; the verifier itself returns `None` for any bad token and never raises (`app._FailClosed` logs a raise at ERROR, as a bug)
- [x] `/readyz` also reports the service token (§11.4: obtained within the last refresh cycle, read from state, not fetched per probe); 4.2's `/readyz` asks only `Verifier.ready()`
- [x] Tests with a local signing key: forged sig, `alg=none`, HS256, wrong iss/aud, expired, nbf, missing scope, cid not allowed, missing `uid`, malformed groups, unknown kid refetch limit, issuer down at startup

Verify: `uv run pytest tests/auth/test_verifier.py`; `/security-review`.

### 4.4 Protected Resource Metadata & challenges 🔒 ☑
Design: §8.1 · Depends: 4.3
- [x] `auth/metadata.py` (only what the SDK doesn't provide): PRM at path-specific and root URLs; `401` with `resource_metadata`; `403 insufficient_scope`; header-only bearer (see [decisions log](decisions-log.md))
- [x] `/code-review`, `/security-review` (see [decisions log](decisions-log.md))

Verify: `uv run pytest tests/auth/test_metadata.py`; `/security-review`.

### 4.5 Integration tests ☑
Design: §14 (Integration, Protocol) · Depends: 4.4
- [x] Full ASGI app + mock AS (local JWKS) + mocked Okta: 401 → token → per-principal `tools/list` → call → denial
- [x] SDK-client protocol smoke over Streamable HTTP at 2026-07-28 and 2025-11-25; `structuredContent` + annotations present
- [x] Remove the Dependabot `ignore` for `mcp` (0.4)

Verify: `uv run pytest tests/integration/`

### 4.6 Real-client check (Path A) ☐
Design: §8.3 · Depends: 4.5, 0.5, 0.6
- [ ] Run locally behind a TLS proxy (e.g. Caddy) or tunnel; connect each target MCP client via Path A (auth is always on, so exposure is safe)
- [ ] Move the 0.6 matrix from `design/spike-findings.md` to `docs/compatibility-matrix.md` (client × discovery × registration × works/limitations) and re-run each client against the real server
- [ ] Under option B, the server accepts refreshed tokens with no new sign-in (Claude Code)
- [ ] 4.4 added `scope="okta-mcp"` to every challenge, and MCP clients prefer it over `scopes_supported`. Re-check that Claude Code still asks for `offline_access` (0.6 saw `okta-mcp offline_access` without the challenge scope); if it doesn't, option B loses its refresh token, and the `scope` parameter comes out of the 401

Verify: at least one real client completes OAuth and calls a pilot command; matrix moved and re-run.

---

## Phase 5 — Registry authoring (all domains)

### 5.0 Fixture tooling ☑
Design: §14 (Fixtures) · Depends: 1.3
- [x] `scripts/gen-fixtures.py`: default per-command fixture from the spec's response schema/examples (realistic IDs, `example.com` emails, `example.okta.com` links)
- [x] `scripts/sanitize-fixture.py`: rewrite recorded dev-org responses (org hostname, emails, names, IDs consistently remapped)
- [x] `tests/test_fixture_hygiene.py`: fails on non-`example.com` email domains or org hostnames other than `example.okta.com` under `tests/fixtures/`
- [x] `tests/fixtures/test_fixtures.py`: every registry command has a fixture of the command's shape; generated ones match `gen-fixtures.py --check`. Pilot fixtures (groups, network-zones) committed

Each domain batch below runs `uv run python scripts/gen-fixtures.py` and commits `tests/fixtures/<domain>/`; gotcha endpoints are recorded and passed through `sanitize-fixture.py` instead.

Verify: `uv run pytest tests/test_fixture_hygiene.py`; a sanitized real recording passes, an unsanitized one fails.

### Domain batches

Each batch: write registry entries, classify (`data_classes`, `arg_rules`, `pattern`), extend `scrub.yaml`, generate fixtures (record + sanitize only for endpoints with known gotchas), write the domain guide in `resources/`, and smoke-test through the stdio dev-mode server.

Verify (every batch):
```
uv run pytest tests/registry tests/fixtures && uv run python scripts/coverage-report.py
```
plus manual dev-org smoke of each new command; V14 review (does any "normal" command return secrets?) noted in the [decisions log](decisions-log.md).

| Step | Domains | Notes | Status |
|---|---|---|---|
| 5.1 | users, apps | Largest; `user_id` resolver; `get-factors`/`get-enrollments` simple; `expand` rules. Registry, fixtures, guides done; **open:** dev-org smoke, V14 review, V6 role for `okta.userRisk.read` (not offered by the trial org; the other new scopes are in `SCOPE_ROLES`, 2026-11-13), `apps list-jwks` (5.4 added `response_override: wrapped`, but the spec example shows `{"jwks": {"keys": …}}` and okta-skills `{"keys": …}`: record it live first), whether users/groups `search` on an object (`profile co "x"`) matches inside it (5.3 review) | ◐ |
| 5.2 | policies, authenticators, network-zones (done in 1.6), behaviors, attack-protection | Security-analyst role coverage. Registry, fixtures, guides done; **open:** dev-org smoke, V14 review, live shape of the two attack-protection settings (object or one-item list), whether Okta pages policies `q` and policy rules | ◐ |
| 5.3 | logs (simple commands only), sessions, security | Mostly `sensitive`; free-form `filter` rules; SSF stream secret. Registry, fixtures, guides done; SSF stream commands excluded; **open:** dev-org smoke, V14 review, V6 role for `okta.sessions.read` (`sessions get` fails DPoP `htu` validation) and `okta.botProtection.read` (not offered by the trial org), whether `debugContext.debugData` string values (`url`, `requestUri`) carry tokens (V14: key-based scrubbing can't see them; `filter` can't name them), whether session IDs are ever under 20 characters | ◐ |
| 5.4 | iam, oauth-client-roles, api-tokens, authorization-servers | Admin roles / credential material; wrapped lists (`items_key`, `link_or_body`). Registry, fixtures, guides done; `response_override: wrapped` for `list-resource-server-keys`; **open:** dev-org smoke, V14 review, `authorization-servers list-associated` needs `trusted` (400 without it), live shape of `list-resource-server-keys` (`{"keys": …}`), `list-scopes` and `list-bundles` page sizes (200 and 20, no spec maximum), whether `list-tokens` is empty for a missing permission | ◐ |
| 5.5 | identity-providers, schemas, org-settings, realms | IdP `client_secret` scrub. Registry, fixtures, guides done; **open:** dev-org smoke, V14 review, V6 role for `okta.realms.read`, `okta.realmAssignments.read` (not offered by the trial org), live shape and role of `list-support-cases` (spec schema wraps in `supportCases`, spec example is a bare array; 403 on an org without a support contract), whether realm `search` takes more than `profile.name co`, whether Read-only Admin reads YubiKey tokens (`okta.users.read`, already in `SCOPE_ROLES`), a view path for fields the spec omits (`list-log-stream-schemas` items carry `$id`, so its view lost `id`, 2026-11-13) | ◐ |
| 5.6 | devices, device-assurance, device-posture, device-integrations | Registry, fixtures, guides done; **open:** dev-org smoke, V14 review, V6 role for `okta.deviceIntegrations.read` (not offered by the trial org), the ID prefixes taken from spec examples (`guo`, `dao`, `dae`, `din`), whether Okta pages the six lists the spec declares unpaged (assurance, integrations, posture `list`, `devices get-users`, `get-os-accounts`; posture `list-defaults` does, at 50, 2026-11-13, and now follows next links), a recorded `list-defaults` fixture in place of the spec-generated one (whose built-in check has an `id`) | ◐ |

### 5.7 Full example policy ☑
Design: §9.3 · Depends: 5.1–5.6
- [x] `docker/policy.example.yaml` = design §9.3 example; test that it loads clean against the full registry

Done when (phase): coverage report shows every simple/resolved catalogue entry implemented; V6 (Read-only Admin sufficiency) recorded per domain; example policy loads.

---

## Phase 6 — Audit, limits, logging

### 6.1 Audit log ☑
Design: §12.3 · Depends: 4.5
- [x] `audit.py`: one JSON line per call/denial; `MCP_AUDIT_ARGS=hash`; arg redaction; never result bodies
- [x] Tests: fields present; hash mode; no secrets/tokens in output

### 6.2 Limiter & operational logs ◐
Design: §6.5, §13 · Depends: 2.4, 4.5
- [x] Per-principal Okta-request limiter enforced in the HTTP path; `rate_limited` errors
- [x] Per-principal share of the in-flight slots (e.g. at most half of `MCP_OKTA_MAX_INFLIGHT`): ten slow System Log calls from one user fit inside `MCP_REQUESTS_PER_MINUTE` and hold every slot (2026-11-10 review)
- [x] Back off after a failed service-token request (a few seconds, served from the stored error): today every tool call during an outage or a bad key sends its own token POST, and those aren't charged to the per-principal limiter
- [x] Log Okta's `errorCode` on an upstream 401/403 (a fixed Okta string, not result data), so an operator can tell a missing admin role (`E0000006`) from a missing feature (`E0000015`); today every 403 gets one fixed message and no code (2026-11-13 V6 sweep)
- [ ] V16: cap the service app's rate-limit share in the dev org and confirm 429s arrive at the cap; record the value for the runbook (needs the dev org)
- [x] Structured operational logs with `request_id`; 429/retry/limiter/truncation/JWKS events
- [x] Tests: integration test trips the limiter; log events emitted

Verify (phase): `uv run pytest tests/test_audit.py tests/integration/test_limits.py`

---

## Phase 7 — Packaging & deployment

### 7.1 Container 🔒 ☑
Design: §11.2 · Depends: 4.5
- [x] `Dockerfile`, `.dockerignore` per design (allow-list includes `LICENSE`, `README.md`; `uv sync --no-editable`); non-root; `MCP_ENV=production`
- [x] CI job: build image, run container tests (non-root, read-only FS, health endpoints, no tests/docs/keys in image), image scan

Verify: `docker build . && docker run --read-only …` health checks pass; CI container job green; `/security-review`.

### 7.2 Compose example 🔒 ◐
Design: §11.4 · Depends: 7.1
- [x] `docker/compose.example.yaml`: secrets as files, read-only policy file mount, read-only root FS, `cap_drop: [ALL]`, `no-new-privileges`, loopback port binding (or no published port, proxy on a shared network), with a comment saying why: `MCP_TRUST_PROXY` trusts any peer (design §11.4)
- [x] `tests/test_compose_example.py`: hardening, loopback-only ports, no inline secrets, no `MCP_ENV`/dev-mode override, read-only policy mount that must exist, example values pass `load_config`
- [x] CI brings the example up with the built image: `tests/container/test_compose.py` in the `container` job
- [ ] Bring-up with dev-org values (needs the dev org; done with placeholder values, see the [decisions log](decisions-log.md))

Verify: `docker compose -f docker/compose.example.yaml config` validates; bring-up with dev-org values works.

### 7.3 Runbook ◐
Design: §11.4, Appendix C · Depends: 7.2, 0.5
- [x] `docs/runbook.md`: Okta setup (from spike findings), exposure decision (only the proxy reaches the port; check with a request from another host before turning on `MCP_TRUST_PROXY`), deploy, policy changes (restart), key rotation, kill switch, audit log handling
- [x] Okta-side controls the server can't check (design §8.2, §10, R7): who can manage membership of each role group (resource sets, group rules) with a System Log alert on `group.user_membership.add` for the role-group IDs; an MFA authentication policy on the client apps; the service app's rate-limit share (V16)
- [x] Audit log handling (6.1): restrict read access (the file is created 0600), retention, SIEM shipping; rotate a file sink with `copytruncate`, since the server doesn't reopen it
- [x] Refresh tokens and user removal (spike 0.6): choosing A or B (link [`okta-setup.md`](okta-setup.md#refresh-tokens-option-a-or-b)); removing a user is group removal under A, plus clearing sessions with `oauthTokens=true` (or deactivating the user) under B; under B the Global Session Policy doesn't bound refresh chains, so `lifetime_minutes` is the re-sign-in and MFA interval; failed refreshes have no `User` target in the System Log, so find them by client ID
- [ ] Clean-machine walkthrough to a working `/readyz` (needs the dev org; the Verify below)
- [ ] Settle the runbook's **unverified** items against the dev org: whether the console keeps a pasted JWK's `kid`, a gap-free Terraform key rotation, whether `okta-setup.py check` works with a token narrower than Super Administrator, the rate-limit share (V16)
- [x] `okta-mcp --check`: load config, registry, scrub rules and policy, print warnings, exit 0 or 2 without serving, so a policy change can be checked before the restart that would otherwise be an outage (runbook §4.2)

Verify: someone (or a fresh Claude session) follows the runbook on a clean machine to a working `/readyz`.

---

## Phase 8 — Hardening & release

### 8.1 Security review sweep ☑
- [x] `/security-review` over all 🔒 paths together (cross-cutting issues): four parallel reviewers by theme (identity → authorization, request building and URL following, data egress, credentials and deployment), 2026-11-14
- [x] Resolve or ticket every finding (see the [decisions log](decisions-log.md))
- [x] Narrow the `.` half of the reserved-literal rule in `exec/params.py` so logins such as `me.smith@…` resolve again: Okta doesn't strip suffixes (`me.json` is a literal), but does strip matrix parameters, so `;` stays refused (2.10 dev-org check, 2026-11-13) 🔒

### 8.2 Compatibility matrix & E2E ☐
- [ ] Complete `docs/compatibility-matrix.md` for all target clients (Path A)
- [ ] E2E checklist: groups claim; per-role tool lists; revocation (A: group removal takes effect within one access-token lifetime; B: group removal and role changes at the next refresh, token revocation ends the chain, an expired Okta session doesn't); 429 behavior under load

### 8.2.1 Live-org CI 🔒 ☐
Design: §14, §6.4, §12.1 · Depends: 5.x, 7.2, 0.5 · Decided 2026-11-14 (see the [decisions log](decisions-log.md))

Live checks of what only Okta decides: the service token, routing, response shapes, roles and paging. The user side stays on the local test issuer: automating a real Okta sign-in needs a user that gets tokens unattended (password grant, or MFA off), which weakens the org being tested.

- [ ] **Org and service app:** a long-lived developer org (the trial org expires); a CI-only service app made by `scripts/okta-setup.py` (DPoP on, its own key, the roles `SCOPE_ROLES` requires). **Key:** an `okta-dev` **Environment** secret, not a repository secret, with the Environment's deployment branches limited to `main`: a repository secret is readable by a workflow pushed on any branch by anyone with write access. The job writes it to a `0600` file under `$RUNNER_TEMP` and never echoes it. Rotate it on a schedule (runbook, 7.3) and whenever a collaborator with admin on the repo leaves
- [ ] **Seed data** by Terraform or the setup script, never by CI: a known user, group, app and policy, and a group large enough to page. Tests find IDs by name or from a checked-in map of non-secret IDs
- [ ] **Workflow** `live.yml`: `schedule` (nightly), `workflow_dispatch`, `push` to `main`; **never `pull_request`**. Environment `okta-dev`, `concurrency: okta-live`, `permissions: contents: read`, a low `MCP_REQUESTS_PER_MINUTE`. A failure opens an issue; it does not gate merges (Okta releases and org drift fail it as often as code does)
- [ ] **Output hygiene:** `tests/live/` asserts only on derived values (status codes, error codes, key sets, lengths), never on body values, since pytest prints both sides of a failed `assert`; run with `--tb=line`. A test fails if a known secret-like value appears in captured output
- [ ] **Checks:**
  1. Service token: nonce retry, `DPoP` token type (a `Bearer` downgrade fails), second call served from the cache
  2. Every registry command once through the executor: no `E0000006` (keeps V6 current), every view field present, paged lists follow `next`
  3. Schema drift and secret canary: live keys vs the pinned spec's schema; fail on a new key that looks secret- or credential-like or is not covered by `scrub.yaml` (keeps V14 current); report other new keys
  4. Path-routing probes from the 2.10 dev-org check (`me;x`, `.json` suffixes, `groups/rules`), plus what the 8.1 change allowed or still refuses untested: `me.smith@<a test login domain>`, other reserved names with a suffix (`apps/export.csv`, `policies/simulate.json`: if Okta routes them as literals, `_SUFFIX_IS_LITERAL` in `exec/params.py` can become a rule for all names), a trailing dot (`me.`, `groups/rules.`), and a leading dot on `users get` (`/users/.json`; 8.1 sweep). The 8.1 change merged before these ran (user decision, 2026-11-14)
  5. The image with the live service app and a policy, user tokens from the local test issuer: one `tools/call` per role
- [ ] **Not in CI:** 429 behavior and V16 (a shared bucket), Okta sign-in / MFA / refresh (4.6, 8.2 manual), anything that writes

Verify: a manual `workflow_dispatch` run is green; a planted failure (a command whose role is removed, a view naming a missing field) fails it with no response body in the log; `/security-review` of the workflow and `tests/live/`.

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
| V4 | `.manage ⇒ .read` implication | 3.2 | 3.2 ☑ (not needed: `OKTA_SCOPES` is `.read` only) |
| V5 | SDK v2 / 2026-07-28: stateless per-request principal, `cacheScope`, back-compat, auth helpers, `httpx` vs `httpx2` | 0.1 deps, 2.3, 4.2 | 0.4 ☑ (see [decisions log](decisions-log.md)) |
| V6 | Read-only Admin sufficiency per domain | 5.x | 5.x ◐ (2026-11-13: role known for the 27 scopes in `SCOPE_ROLES`, 7 of which need more than Read-only Admin; 6 still unverified) |
| V8 | Spec accuracy (scopes, operationIds, params) | 1.3, 5.x | 1.5 ◐ (5 gotchas catalogued) / 5.x |
| V9–V11 | `resource` param, discovery, loopback, static client IDs | 4.4, 4.6 | 0.5 ☑; per-client results in 4.6 |
| V13 | `uid` vs `sub`; ID-emitting groups expression | 4.3 | 0.5 ☑ |
| V14 | Secrets in "normal" endpoints | 5.x | 5.x |
| V16 | Service app rate-limit share can be capped in Okta | 7.3 | 6.2 |
| V15 | DPoP default and nonce behavior | 2.2 live check | 0.5 ☑ |
| T1 | **Discuss with the user (not a design §16 item; proposal: [`design/t1-tool-surface.md`](design/t1-tool-surface.md)):** which tools and commands to expose over MCP, and what their responses look like. Goal: be token-conscious. Do as much as possible in code (filtering, projection, summarising, defaults for `select`/`strip_links`, compact envelopes and errors, short synopses) so results stay small in the model's context. Revisit §5.1–5.3, §7.1–7.2 | 1.4, 2.7, 2.8, 3.3 | 2026-11-02 ☑ (D1–D11 accepted) |
