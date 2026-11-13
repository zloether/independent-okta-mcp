# T1 — Tool surface and response shapes (proposal)

Status: **accepted 2026-11-02** (all of D1–D11; D5 and D6 refined below). Resolves open question T1; blocks 1.4, 2.7, 2.8, 3.3. Revisits design §5.1–5.3 and §7.1–7.3. Nothing here weakens a security control; the two items that touch trust boundaries (cursor format, null pruning near scrubbing) are marked 🔒.

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

**Live check (plan 4.1, 2026-11-12).** A fresh Claude Code session ran 8 help-desk tasks against the dev org through `okta-mcp --stdio`, as the helpdesk principal (`groups` and `network-zones`, 11 commands). It started with this repo's `CLAUDE.md` in context but no knowledge of the tools. The brief said "okta-dev tools only".
- **Tool list:** `/context` reported 1399 tokens (`okta_groups` 698, `okta_network_zones` 459, `okta_help` 139, `okta_status` 103) for 3354 bytes of definitions. That is ≈ 2.4 bytes per token, not the 4 assumed above, so the estimates in this section are about 1.7× low. D1's 40 KB budget is about 17k tokens, not 10k.
- **Results:** 19 calls, 6133 bytes in all, replayed afterwards for exact sizes. That is ≈ 2.5k tokens at the same ratio, and no single result went over 906 bytes. `okta_help` accounted for 3 of the calls and 1858 of the bytes.
- **Behaviour:** the model read the tables correctly in every task. Before the first per-group call it read `okta_help` for `list` and `get-members`. When the default view lacked what it needed, it read `okta_help` for `list-roles`, where it found `expand`. It used `select` correctly (`profile.login`, `profile.name,id`, `*`). It chose `search ... eq`/`sw` over `q`, and it reported the `forbidden`/`upstream_error` messages accurately. It used `links: true` once, while trying to find role targets.
- **Cost points:**
  - Every per-group command needs an ID, and group-name resolution is out of v1 (design §5.6). That cost an extra lookup in 3 of the 8 tasks.
  - `list-rules`' default view leaves out the rule's target groups, so the model needed a follow-up `get-rule`.
  - On an empty `expand` result, the model couldn't tell whether the server had kept `_embedded`. It does (D5/D6); Okta sends none for an untargeted role.
- **Not exercised:** pagination and cursors (no list was longer than one page), and the `okta://guide/*` resources (the brief's "tools only" kept the model from reading them).
- **Outcome:** D1–D11 stand.

## 1. Tool surface

**D1 — Keep domain tools (A), with the trims below.** *Accepted.*

- Filtering per principal already bounds the cost for real roles. Only full-access admins pay ~8k tokens, and a client with deferred tool loading pays less.
- Domain tools let clients allow or deny tools per domain and give better tool selection than a single `okta_call`. B saves tokens up front but costs a discovery round trip in most sessions and pushes argument shapes out of the schema.
- Trims: one-sentence descriptions on the shared output parameters (they repeat on all 23 tools); synopsis lines ≤ 60 characters; no examples in tool descriptions (they go in `okta_help`).
- **Guard with a budget test** (3.3): for a full-access principal on the real registries, assert `tools/list` stays under a fixed byte budget (start at 40 KB ≈ 10k tokens and ratchet down). If the full registry (Phase 5) exceeds it, switch to C rather than raising the budget.

**D2 — Merge `okta_status` into `okta_help`.** *Accepted.* `okta_help()` with no arguments returns the caller's roles, domains and unavailable commands (today's `okta_status`). `okta_help(tool, command)` returns command help. One fewer tool, same information, same rule that it reveals nothing about other users or roles.

**D3 — One command per operation; variants are arguments.** *Accepted.* okta-skills has `users list` and `users search`, both `listUsers`. Every alias adds a synopsis and an enum line for every principal who can see it. A second command on the same `operationId` is allowed only when classification differs (design §6.2 check 5 already forces those to agree). The coverage inventory (1.5) maps catalogue aliases to the one command.

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

**D4 — `links` (default `false`) replaces `strip_links`.** *Accepted.* `_links` is dropped unless asked for. `_embedded` is kept, since it carries `expand` results.

**D5 — Default views in the registry.** *Accepted.* A new registry field, `view: [dotted paths]`, applies when `select` is omitted:

- Required on every list command (new loader check). Optional on single-resource commands, which default to the whole object, without links and with nulls pruned.
- Each path must exist in the operation's success-response schema (new loader check, so `registry/spec.py` must also keep response property paths). For polymorphic items (discriminator, `oneOf`/`anyOf`; 20 of the 133 list operations, e.g. `listApplications`, `listPolicies`, `listFactors`), the path must exist in the **base schema** shared by every variant, so a view never names a field that some items can't have.
- An explicit `select` is **not** checked against the schema: custom profile attributes (`additionalProperties`) must stay selectable. Unknown paths yield `null` cells.
- `select: "*"` returns the whole scrubbed object. `select` with explicit paths overrides the view.
- Scrubbing still runs first on the full item (design §7.2 order: scrub → links → select/view), so a view never exposes a field that scrubbing would remove, and `select: "*"` is no wider than today's default.

Example views from the measurements: users `id,status,profile.login,profile.firstName,profile.lastName,lastLogin`; logs `published,eventType,displayMessage,outcome.result,outcome.reason,actor.alternateId,client.ipAddress,severity`.

**D6 — Prune nulls and empties from objects.** *Accepted.* "Empty" means `null`, `{}` and `[]`; empty strings are kept. Applies to whole-object output (single resources, `select: "*"`). Table cells keep `null`, so a column never shifts. Tradeoff: a whole object no longer shows explicit `null` against an absent field (e.g. `lastLogin: null` = never logged in). The tool description says "absent = null". 🔒 Pruning runs after scrubbing and must not turn a scrubbed field's placeholder into something that looks absent. The scrubber sets `"[redacted]"` (design §9.2), which is not empty, so it survives pruning. A test pins this.

**D7 — Smaller default budgets.** *Accepted.* `MCP_DEFAULT_LIMIT` 100 → **50**. `MCP_MAX_BYTES` 256 KB → **64 KB** (≈ 16k tokens; measured on the serialized response, so after view and table encoding). `MCP_MAX_ITEMS` stays 1000. With views, 50 items fit in ~1–2k tokens, and paging is cheap once the cursor is small (§4). Logs with `select: "*"` (~1.9 KB per event) will stop on `max_bytes` at ~33 events and resume through the in-page `skip` (design §7.2); that is expected, not a failure.

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

**D8 — Table encoding for lists.** *Accepted.* Tradeoff: one more shape for clients and tests, in exchange for 30–40 % on every list. Models read column/row JSON reliably. The alternative is objects-with-view only (still the 4–15× win from D5).

### 3.2 Single resource

```jsonc
{"untrusted":true,"item":{"id":"00ub0…","status":"ACTIVE","profile":{"login":"isaac.brock@example.com",…}}}
```

Same as design §7.1, plus D4 and D6.

### 3.3 No `structuredContent`

**D9 — Return one text block. No `outputSchema` and no `structuredContent`.** *Accepted.* Design §5.2 returns both: the envelope as `structuredContent` and a JSON text block as fallback. A client that passes both to the model pays twice. Clients differ in which one they forward, so the only shape that guarantees a single copy is text-only. The envelope is small and self-describing, so nothing depends on a declared output schema. Verify in 4.x with Claude Code, Claude Desktop and one other client. If some client forwards *only* `structuredContent`, revisit.

### 3.4 Errors

```jsonc
{"error":{"code":"invalid_arguments","message":"unknown arg 'usr'; valid: user","request_id":"a1b2c3d4"}}
```

- Lists of valid options in messages are capped at 20, then `… (+N; see okta_help)`. Exception (step 5.3): a registry closed attribute set in a `Search:` line is shown whole.
- `upstream_error` carries the status and `errorSummary` only. `errorCauses` is included only when it is short (≤ 200 B).
- `request_id`: 8 hex characters in the response. The full ID stays in the audit log, so correlation still works.
- `forbidden_by_policy`: one fixed sentence, unchanged (reveals nothing).

## 4. Cursor size 🔒

A cursor is emitted and then **echoed by the model as output tokens**, which are slower and dearer than input tokens. The design §7.3 payload for the `get-groups` example encodes to **516 characters** (≈ 150–200 tokens, as base64 tokenizes poorly).

**D10 — Compact cursor format** (same bindings, same checks). *Accepted.*

- short keys (`v,u,t,c,a,p,q,s,e`); `iat` dropped (only `exp` is checked);
- `args_sha256` → first 128 bits, base64url;
- HMAC-SHA256 tag truncated to 128 bits (RFC 2104 §5 permits truncation; 128 bits leaves ample forgery margin);
- `page.rel` → **query string only** (`after=00g9…&limit=200`). The path is always the template expanded with `p` (resolved path params), so a cursor can no longer carry a path at all. This removes the design §7.3 path-equality check by making it structurally impossible to fail, and it is easier to review than the check.

Measured: 516 → ~290 characters (285 as built in 2.9). Needs `/security-review` in 2.9 as already planned. Okta's `after` tokens are opaque and can be long, so this is a floor, not a guarantee.

## 5. `okta_help` output

**D11 — Help as compact text, not raw JSON Schema.** *Accepted.*

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

## 8. Changes (each lands with the step that implements it)

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
| Plan 1.2/1.3 | Spec index keeps response property paths (base schema for polymorphic items); registry model and loader get `view` |
| Plan 1.4 | Synopsis cap; text help renderer |
| Plan 2.7 | `links`, view, pruning |
| Plan 2.8 | Table encoding, sparse envelope |
| Plan 2.9 | Compact cursor |
| Plan 3.3 | Merged `okta_help`; budget tests |
| Plan 4.x | Verify single-copy results across clients (D9) |

## Decisions

| ID | Proposal | Status |
|---|---|---|
| D1 | Domain tools + `tools/list` budget test; C as fallback | Accepted 2026-11-02 |
| D2 | Merge `okta_status` into `okta_help()` | Accepted 2026-11-02 |
| D3 | One command per operation | Accepted 2026-11-02 |
| D4 | `links` default false | Accepted 2026-11-02 |
| D5 | Registry default views; `select: "*"` | Accepted 2026-11-02; view paths checked against the base schema of polymorphic items; explicit `select` unchecked |
| D6 | Prune nulls in whole-object output, "absent = null" in descriptions | Accepted 2026-11-02; prunes `null`, `{}`, `[]`, keeps `""` |
| D7 | Default limit 50, max bytes 64 KB | Accepted 2026-11-02 |
| D8 | Table encoding for lists | Accepted 2026-11-02 |
| D9 | Text-only results, no `structuredContent` | Accepted 2026-11-02, pending client check in 4.x |
| D10 | Compact cursor, query-only page | Accepted 2026-11-02; built in 2.9 (2026-11-10), `/security-review` done there |
| D11 | Help as text | Accepted 2026-11-02 |
