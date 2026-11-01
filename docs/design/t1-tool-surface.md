# T1 — Tool surface and response shapes (proposal)

Status: **draft for discussion**. Resolves open question T1; blocks 1.4, 2.7, 2.8, 3.3. Revisits design §5.1–5.3 and §7.1–7.3. Nothing here weakens a security control; the two items that touch trust boundaries (cursor format, null pruning near scrubbing) are marked 🔒.

Goal: keep what lands in the model's context small, and do the work in code (projection, pruning, encoding, defaults) instead of asking the model to do it.

## 0. Measurements

Source: the 200-response examples in the pinned spec (2026.42.1). Sizes are compact-JSON bytes per item. Tokens ≈ bytes / 4. IDs, base64 and JSON punctuation tokenize worse than prose, so real counts run higher, but the ratios hold. Measured with a one-off script that is not committed; the budget tests in §6 replace it.

| Example | raw | no `_links`, no nulls | default view (§2.2) | view as table (§3.1) |
|---|---:|---:|---:|---:|
| `listUsers` (q) | 715 | 558 | 149 | 91 |
| `listGroups` | 907 | 462 | 143 | 104 |
| `listNetworkZones` | 545 | 254 | 104 | 71 |
| `listFactors` | 681 | 245 | 133 | 92 |
| `listAuthenticatorEnrollments` | 621 | 216 | 163 | 118 |
| `listLogEvents` | 2206 | 1920 | 231 | 148 |
| `listApplications` | 1542 | 688 | 115 | 80 |
| `listDevices` | 1872 | 480 | 165 | 106 |
| `listIdentityProviders` | 1372 | 921 | 111 | 70 |
| `listAssignedRolesForUser` (custom) | 471 | 229 | 128 | 85 |

Findings:

1. **`_links` is 40–75 % of raw bytes** for groups, apps, factors, zones, devices and auth servers. The model never needs them: it can't follow them, and the server builds its own URLs.
2. **A 5–8 field default view cuts lists 4–15×** compared with raw. Logs are the extreme case: 2.2 KB → 0.15 KB per event.
3. **Repeated keys** cost a further 30–40 %. A column/row table removes them.
4. **Pretty-printing** costs 25–55 % more than compact JSON (`getUser` 1381 → 1118 B; zones 5159 → 3275 B).
5. With today's defaults (`limit` 100, links kept, no `select`), **100 users ≈ 18k tokens and 100 log events ≈ 55k tokens**, the latter close to `MCP_MAX_BYTES` (256 KB). Under this proposal: ≈ 2.3k and ≈ 3.7k.

Tool list: the okta-skills catalogue has ~324 commands outside ai-agents. Dropping the reference-only filters, expression-language and terraform skills leaves ~296. Estimates for `tools/list`:

| Surface | Full access | Helpdesk (users + groups, ~25 commands) |
|---|---:|---:|
| A. Domain tools, design §5.1 (synopsis + enum + per-tool schema) | ~8–9k tokens | ~0.7k |
| B. Gateway: `okta_commands` / `okta_help` / `okta_call` | ~0.6k fixed, plus ~0.3–1.5k per domain discovered | same |
| C. Domain tools, enum only (synopses moved to `okta_help`) | ~4–5k | ~0.4k |

## 1. Tool surface

**D1 — Keep domain tools (A), with the trims below.** *Decision needed.* Recommended.

- Filtering per principal already bounds the cost for real roles. Only full-access admins pay ~8k tokens, and a client with deferred tool loading pays less.
- Domain tools let clients allow or deny tools per domain and give better tool selection than a single `okta_call`. B saves tokens up front but costs a discovery round trip in most sessions and pushes argument shapes out of the schema.
- Trims: one-sentence descriptions on the shared output parameters (they repeat on all 23 tools); synopsis lines ≤ 60 characters; no examples in tool descriptions (they go in `okta_help`).
- **Guard with a budget test** (3.3): for a full-access principal on the real registries, assert `tools/list` stays under a fixed byte budget (start at 40 KB ≈ 10k tokens and ratchet down). If the full registry (Phase 5) exceeds it, switch to C rather than raising the budget.

**D2 — Merge `okta_status` into `okta_help`.** *Decision needed.* `okta_help()` with no arguments returns the caller's roles, domains and unavailable commands (today's `okta_status`). `okta_help(tool, command)` returns command help. One fewer tool, same information, same rule that it reveals nothing about other users or roles.

**D3 — One command per operation; variants are arguments.** *Decision needed.* okta-skills has `users list` and `users search`, both `listUsers`. Every alias adds a synopsis and an enum line for every principal who can see it. A second command on the same `operationId` is allowed only when classification differs (design §6.2 check 5 already forces those to agree). The coverage inventory (1.5) maps catalogue aliases to the one command.

Which commands to expose stays as the design has it: the catalogue minus exclusions, decided per entry in 1.5. Filters, expression language and terraform are resources (`okta://reference/*`), not tools.

## 2. Inputs

```jsonc
{
  "command": "get-groups",
  "args":   { "user": "jane@example.com" },
  "select": "id,profile.name",  // optional. Omitted → the command's default view; "*" → whole object
  "links":  false,              // optional, default false. Replaces strip_links (default was keep)
  "limit":  50,                 // optional, default 50 (was 100)
  "cursor": "…"
}
```

**D4 — `links` (default `false`) replaces `strip_links`.** *Decision needed.* `_links` is dropped unless asked for. `_embedded` is kept, since it carries `expand` results.

**D5 — Default views in the registry.** *Decision needed.* A new registry field, `view: [dotted paths]`, applies when `select` is omitted:

- Required on every list command (new loader check). Optional on single-resource commands, which default to the whole object, without links and with nulls pruned.
- Each path must exist in the operation's success-response schema (new loader check, so `registry/spec.py` must also keep response property paths).
- `select: "*"` returns the whole scrubbed object. `select` with explicit paths overrides the view.
- Scrubbing still runs first on the full item (design §7.2 order: scrub → links → select/view), so a view never exposes a field that scrubbing would remove, and `select: "*"` is no wider than today's default.

Example views from the measurements: users `id,status,profile.login,profile.firstName,profile.lastName,lastLogin`; logs `published,eventType,displayMessage,outcome.result,outcome.reason,actor.alternateId,client.ipAddress,severity`.

**D6 — Prune nulls and empties from objects.** *Decision needed.* Applies to whole-object output (single resources, `select: "*"`). Table cells keep `null`, so a column never shifts. Tradeoff: a whole object no longer shows explicit `null` against an absent field (e.g. `lastLogin: null` = never logged in). The tool description says "absent = null". 🔒 Pruning runs after scrubbing and must not turn a scrubbed field's placeholder into something that looks absent. The scrubber sets `"[redacted]"` (design §9.2), which is not empty, so it survives pruning. A test pins this.

**D7 — Smaller default budgets.** *Decision needed.* `MCP_DEFAULT_LIMIT` 100 → **50**. `MCP_MAX_BYTES` 256 KB → **64 KB** (≈ 16k tokens; measured on the serialized response, so after view and table encoding). `MCP_MAX_ITEMS` stays 1000. With views, 50 items fit in ~1–2k tokens, and paging is cheap once the cursor is small (§4).

## 3. Response shapes

All responses are **one text block of compact JSON**. Envelope fields appear only when they differ from the default.

### 3.1 Lists → table

```jsonc
{"untrusted":true,"count":2,
 "cols":["id","type","profile.name"],
 "rows":[["00g1…","OKTA_GROUP","Sales"],["00g2…","APP_GROUP","Okta Admins"]],
 "next_cursor":"…","truncated":"max_items"}
```

- `cols`/`rows` whenever the columns are fixed (default view or explicit `select`). `items: [ {…} ]` (pruned objects) for `select: "*"`.
- Cells can hold arrays or objects when a selected path names one (e.g. a zone's `gateways`).
- `count` is kept: 3 tokens, and models miscount long row lists.
- `truncated` holds the reason (`max_items | max_bytes | deadline | non_resumable`) and is absent when the list is complete. `resumable` is gone: the presence of `next_cursor` means resumable. `warnings` appears only when non-empty.

**D8 — Table encoding for lists.** *Decision needed.* Recommended. Tradeoff: one more shape for clients and tests, in exchange for 30–40 % on every list. Models read column/row JSON reliably. The alternative is objects-with-view only (still the 4–15× win from D5).

### 3.2 Single resource

```jsonc
{"untrusted":true,"item":{"id":"00ub0…","status":"ACTIVE","profile":{"login":"isaac.brock@example.com",…}}}
```

Same as design §7.1, plus D4 and D6.

### 3.3 No `structuredContent`

**D9 — Return one text block. No `outputSchema` and no `structuredContent`.** *Decision needed.* Design §5.2 returns both: the envelope as `structuredContent` and a JSON text block as fallback. A client that passes both to the model pays twice. Clients differ in which one they forward, so the only shape that guarantees a single copy is text-only. The envelope is small and self-describing, so nothing depends on a declared output schema. Verify in 4.x with Claude Code, Claude Desktop and one other client. If some client forwards *only* `structuredContent`, revisit.

### 3.4 Errors

```jsonc
{"error":{"code":"invalid_arguments","message":"unknown arg 'usr'; valid: user","request_id":"a1b2c3d4"}}
```

- Lists of valid options in messages are capped at 20, then `… (+N; see okta_help)`.
- `upstream_error` carries the status and `errorSummary` only. `errorCauses` is included only when it is short (≤ 200 B).
- `request_id`: 8 hex characters in the response. The full ID stays in the audit log, so correlation still works.
- `forbidden_by_policy`: one fixed sentence, unchanged (reveals nothing).

## 4. Cursor size 🔒

A cursor is emitted and then **echoed by the model as output tokens**, which are slower and dearer than input tokens. The design §7.3 payload for the `get-groups` example encodes to **516 characters** (≈ 150–200 tokens, as base64 tokenizes poorly).

**D10 — Compact cursor format** (same bindings, same checks). *Decision needed.*

- short keys (`v,u,t,c,a,p,q,s,e`); `iat` dropped (only `exp` is checked);
- `args_sha256` → first 128 bits, base64url;
- HMAC-SHA256 tag truncated to 128 bits (RFC 2104 §5 permits truncation; 128 bits leaves ample forgery margin);
- `page.rel` → **query string only** (`after=00g9…&limit=200`). The path is always the template expanded with `p` (resolved path params), so a cursor can no longer carry a path at all. This removes the design §7.3 path-equality check by making it structurally impossible to fail, and it is easier to review than the check.

Measured: 516 → ~290 characters. Needs `/security-review` in 2.9 as already planned. Okta's `after` tokens are opaque and can be long, so this is a floor, not a guarantee.

## 5. `okta_help` output

**D11 — Help as compact text, not raw JSON Schema.** *Decision needed.*

```
okta_users get-groups <user>
Groups the user belongs to. List, paginated.
  user  string, required — user ID (00u…) or exact login
Default view: id,type,profile.name
```

≈ 50 tokens, against ~200 for the generated JSON Schema. Text still states every constraint exactly (type, required, enum values, pattern, maxItems), so the model loses nothing it needs; validation stays server-side on the real schema. `okta_help(tool)` without a command is not offered, since the tool description already lists the synopses.

## 6. Budget tests (CI)

Token cost regresses silently, so guard it the same way as behavior:

- `tools/list` for a full-access principal on the real registries ≤ budget (D1).
- For every list command with a spec example: default-view bytes per item ≤ 300, after scrub.
- `okta_help` output for every command ≤ 1 KB.
- Each resource guide ≤ 8 KB.

## 7. Deferred (not v1)

- Server-side `count_only` / `group_by` (e.g. "how many users per status"): needs full pagination and its own caps; composite-handler territory (design §5.6).
- Per-command `default_limit` (e.g. logs 25): only if D7's global defaults prove wrong for one domain.
- Gateway mode (B) as a config switch: only if the D1 budget test fails and C isn't enough.

## 8. Changes if accepted

| Where | Change |
|---|---|
| Design §5.1 | `okta_status` folded into `okta_help` (D2) |
| Design §5.2 | `links` replaces `strip_links`; `select: "*"`; default view; text-only results (D4, D5, D9) |
| Design §5.3 | Synopsis length cap, budget test, help as text (D1, D11) |
| Design §6.2 | `view` field; loader checks: views on list commands, view paths exist in the response schema; one command per operation (D3, D5) |
| Design §7.1 | Table encoding, sparse envelope, `truncated` holds the reason (D8) |
| Design §7.2 | Null pruning step after links (D6) |
| Design §7.3 | Compact cursor, query-only `page` (D10) |
| Design §11.3 | `MCP_DEFAULT_LIMIT=50`, `MCP_MAX_BYTES=65536` (D7) |
| Plan 1.2/1.3 | Spec index keeps response property paths; registry model and loader get `view` |
| Plan 1.4 | Synopsis cap; text help renderer |
| Plan 2.7 | `links`, view, pruning |
| Plan 2.8 | Table encoding, sparse envelope |
| Plan 2.9 | Compact cursor |
| Plan 3.3 | Merged `okta_help`; budget tests |
| Plan 4.x | Verify single-copy results across clients (D9) |

## Decisions to make

| ID | Proposal | Recommendation | Status |
|---|---|---|---|
| D1 | Domain tools + `tools/list` budget test; C as fallback | Yes | Decision needed |
| D2 | Merge `okta_status` into `okta_help()` | Yes | Decision needed |
| D3 | One command per operation | Yes | Decision needed |
| D4 | `links` default false | Yes | Decision needed |
| D5 | Registry default views; `select: "*"` | Yes | Decision needed |
| D6 | Prune nulls in whole-object output | Yes, with "absent = null" in descriptions | Decision needed |
| D7 | Default limit 50, max bytes 64 KB | Yes | Decision needed |
| D8 | Table encoding for lists | Yes; the main judgment call | Decision needed |
| D9 | Text-only results, no `structuredContent` | Yes, pending client check in 4.x | Decision needed |
| D10 | Compact cursor, query-only page | Yes, via `/security-review` in 2.9 | Decision needed |
| D11 | Help as text | Yes | Decision needed |
