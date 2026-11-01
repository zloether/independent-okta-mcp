# Spike Findings — Okta dev org (step 0.5)

Results of the live checks for design §16 items V1, V9, V10, V11, V13, V15. Each section: **result**, **evidence**, **design impact**. Helpers: `spikes/okta/okta_spike.py` (`uv run python spikes/okta/okta_spike.py --help`). Evidence uses `example.okta.com` / `example.com` placeholders; never paste tokens, keys or Okta result bodies here.

## Setup

| Item | Value |
|---|---|
| Date | 2026-10-30 |
| Org type | Okta trial org |
| Custom AS issuer | `https://example.okta.com/oauth2/aus…` (name `okta-mcp-spike`) |
| AS audience | `http://127.0.0.1:8000/mcp` |
| Test groups | `mcp-okta-spike-admin` (`00g…`), `mcp-okta-spike-helpdesk` (`00g…`); one test user in each |
| Public client | `0oa…` (native), redirect URIs: `http://127.0.0.1:8765/callback` |
| Service app | `0oa…`, "Require DPoP" default: `false` when created via the API; console default not yet checked |

Resources were created with the Management API (SSWS token) rather than the admin console; the exact request bodies are under [Okta configuration](#okta-configuration) below.

User tokens for V1, V9, V11 and V13 came from `okta_spike.py user-token` (authorization code + PKCE over a loopback redirect, scope `openid okta-mcp`) on 2026-10-31, signing in as each test user in a browser.

## V1 — `groups` claim (IDs) on access tokens

- Result: **yes**. The access token carries `groups` as an array of group IDs, and only the user's `mcp-okta-*` groups. Each user's token held exactly the ID of their own group. `Everyone` (type `BUILT_IN`), which every user belongs to, was left out by the `OKTA_GROUP` filter.
- Evidence: admin user → `"groups": ["00g…"]` (`mcp-okta-spike-admin`); helpdesk user → `"groups": ["00g…"]` (`mcp-okta-spike-helpdesk`).
- Not tested: behavior past 100 matching groups. The prefix filter keeps a user far below that in practice.
- Design impact: none; §9's mapping of group IDs to roles stands. The service-app group lookup fallback is not needed.

## V13 — `uid` vs `sub`; ID-emitting groups expression

- Expression used: `user.getGroups({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': {'mcp-okta-'}}).![id]`
- Result: the expression evaluates to IDs (V1). `uid` is the user ID (`00u…`); `sub` is the user's **login** (`mcp-spike-admin@example.com`), which an admin can change.
- Evidence: claims present on every token: `ver`, `jti`, `iss`, `aud`, `iat`, `exp` (30 min after `iat`, per the rule), `cid` (the public client), `uid`, `scp`, `auth_time`, `sub`, `groups`. `scp` came back as `["openid", "okta-mcp"]` on some tokens and `["okta-mcp", "openid"]` on others.
- Design impact: confirms §8.5. The principal is `uid`; `sub` is display only. Compare `scp` as a set, never by position.

## V9 — RFC 8707 `resource` parameter

| Variant | Outcome | `aud` |
|---|---|---|
| no `resource` | token issued | AS audience |
| `resource` on authorize + token | token issued | AS audience |
| `resource` on authorize only | token issued | AS audience |
| `resource` ≠ AS audience (`https://other.example.com/mcp`) | token issued | AS audience |

Okta ignores `resource`: `aud` is always the authorization server's one configured audience, and a request for a different resource is neither rejected nor reflected in the token. This matches discovery metadata, which does not advertise `resource_parameter_supported` (V10).

- Design impact: a token is bound to the authorization server, not to the resource the client asked for, so a **dedicated authorization server per deployment is required** (already the rule in §8.2): any other API sharing it would accept okta-mcp tokens and the reverse. The server checks `aud` against `MCP_AUDIENCE` and must not rely on `resource`. Clients that omit `resource` still work.

## V10 — Metadata discovery

| URL | Status |
|---|---|
| OIDC (`{issuer}/.well-known/openid-configuration`) | 200 |
| RFC 8414 path insertion (`{origin}/.well-known/oauth-authorization-server/oauth2/aus…`) | 200 |
| RFC 8414 appended (`{issuer}/.well-known/oauth-authorization-server`) | 200 |

All three return the same `issuer`, `code_challenge_methods_supported: ["S256"]` and `dpop_signing_alg_values_supported` (RS256/384/512, ES256/384/512). Metadata does not advertise `resource_parameter_supported` or `authorization_response_iss_parameter_supported`. `scopes_supported` includes `okta-mcp` (scope created with `metadataPublish: ALL_CLIENTS`).

Per-client discovery behavior goes in the compatibility matrix below.

- Design impact: Okta serves the path-insertion URL itself, so a client that tries only RFC 8414 path insertion is **not** incompatible on that account. §8.3's "recorded as incompatible" rule can be dropped.

## V11 — Static client IDs, loopback redirects, DCR

- Loopback with a port other than the registered one: **rejected**. With `http://127.0.0.1:8765/callback` registered, `http://127.0.0.1:8766/callback` stops at the authorize endpoint with "The 'redirect_uri' parameter must be a Login redirect URI in the client app settings". Okta does not apply RFC 8252's any-port rule for loopback redirects.
- `localhost` vs `127.0.0.1`: **different URIs**. `http://localhost:8765/callback` is rejected with the same error.
- DCR availability: metadata advertises `registration_endpoint: {org}/oauth2/v1/clients`, but an anonymous registration POST returns `403 E0000005 Invalid session`. Registration needs an admin API credential, so there is no open DCR for MCP clients; they need a pre-registered static `client_id`.
- Design impact: every approved MCP client is a pre-registered public client with its exact redirect URIs, host and port included (already how `clients:` works in `scripts/okta-setup.py` and `terraform/okta/`). A client that picks a random loopback port per sign-in, or offers no way to set its `client_id`, cannot connect; the compatibility matrix records which clients those are.

## V15 — Service app DPoP default and nonce behavior

- "Require DPoP" on by default for new API Services apps: **no when created via `POST /api/v1/apps`** (`settings.oauthClient.dpop_bound_access_tokens: false` when omitted). Console default not yet checked.
- With DPoP off: the token endpoint ignores a DPoP header and issues `token_type: Bearer`. Presenting that token as `Authorization: DPoP …` fails with `401 invalid_token "The presented access_token is not DPoP bound."`; `Bearer` succeeds (200).
- With DPoP on (`dpop_bound_access_tokens: true`): a token request without a proof fails with `400 invalid_dpop_proof "The DPoP proof JWT header is missing."`.
- Token endpoint nonce: **yes**. The first proof, sent without a nonce, is rejected with a `DPoP-Nonce` header; the retry with that nonce returns `token_type: DPoP`.
- Resource endpoint nonce (`GET /api/v1/users`): 200 on the first attempt with a proof carrying the token-endpoint nonce plus `ath`; no new `DPoP-Nonce` was sent. Whether a proof *without* a nonce is accepted at the resource is untested.
- Design impact: the runbook must set "Require DPoP" explicitly (API/Terraform default is off). Keep the nonce retry at the token endpoint. At resource endpoints, reuse the last nonce and keep the one-shot retry on `use_dpop_nonce`.

## Client compatibility matrix

Moved to step 4.6: a real MCP client only starts sign-in after the server answers `401` with Protected Resource Metadata, which needs the server from Phase 4. V9 and V11 above already fix two columns: `resource` handling doesn't matter, and the redirect URI must be fixed and registered exactly.

| Client | Version | Discovery used | Static client ID | Redirect URI | `resource` sent | Result |
|---|---|---|---|---|---|---|
| | | | | | | |

## Okta configuration

The request bodies used to create the spike resources (Management API, `SSWS` token). They are the starting point for the Appendix C runbook and a later Terraform module. All of them were accepted as written unless noted.

**Groups**: `POST /api/v1/groups`, `{"profile": {"name": "mcp-okta-<role>"}}`. Users are created with `groupIds: [...]` and `activate=true`.

**Custom AS**: `POST /api/v1/authorizationServers`

```json
{"name": "okta-mcp", "audiences": ["<MCP_PUBLIC_URL>"]}
```

**Scope**: `POST /api/v1/authorizationServers/{as}/scopes`

```json
{"name": "okta-mcp", "displayName": "Okta MCP", "consent": "IMPLICIT", "metadataPublish": "ALL_CLIENTS"}
```

**Groups claim**: `POST /api/v1/authorizationServers/{as}/claims`. The expression evaluates to group IDs (V1, V13).

```json
{"name": "groups", "status": "ACTIVE", "claimType": "RESOURCE", "valueType": "EXPRESSION",
 "value": "user.getGroups({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': {'mcp-okta-'}}).![id]",
 "alwaysIncludeInToken": true, "conditions": {"scopes": []}}
```

**Public client** (one per approved MCP client): `POST /api/v1/apps`. Okta set `pkce_required: true` on its own for a native app with `token_endpoint_auth_method: none`. Users need an app assignment (here, both groups through `PUT /api/v1/apps/{app}/groups/{group}`).

```json
{"name": "oidc_client", "label": "<client name>", "signOnMode": "OPENID_CONNECT",
 "credentials": {"oauthClient": {"token_endpoint_auth_method": "none"}},
 "settings": {"oauthClient": {"application_type": "native", "grant_types": ["authorization_code"],
   "response_types": ["code"], "redirect_uris": ["http://127.0.0.1:8765/callback"], "consent_method": "TRUSTED"}}}
```

**Access policy and rule**: `POST /api/v1/authorizationServers/{as}/policies`, then `…/policies/{policy}/rules`

```json
{"type": "OAUTH_AUTHORIZATION_POLICY", "name": "okta-mcp clients", "priority": 1, "status": "ACTIVE",
 "conditions": {"clients": {"include": ["<public client_id>", "..."]}}}
```

```json
{"type": "RESOURCE_ACCESS", "name": "okta-mcp groups", "priority": 1, "status": "ACTIVE",
 "conditions": {"grantTypes": {"include": ["authorization_code"]},
   "people": {"groups": {"include": ["00g…", "00g…"]}},
   "scopes": {"include": ["openid", "profile", "email", "okta-mcp"]}},
 "actions": {"token": {"accessTokenLifetimeMinutes": 30, "refreshTokenLifetimeMinutes": 0, "refreshTokenWindowMinutes": 10080}}}
```

**Service app**: `POST /api/v1/apps`. Set `dpop_bound_access_tokens: true` explicitly, because it defaults to `false` (V15).

```json
{"name": "oidc_client", "label": "okta-mcp service", "signOnMode": "OPENID_CONNECT",
 "credentials": {"oauthClient": {"token_endpoint_auth_method": "private_key_jwt"}},
 "settings": {"oauthClient": {"application_type": "service", "grant_types": ["client_credentials"],
   "response_types": ["token"], "redirect_uris": [], "dpop_bound_access_tokens": true,
   "jwks": {"keys": [{"kty": "RSA", "kid": "<kid>", "use": "sig", "alg": "RS256", "n": "…", "e": "AQAB"}]}}}}
```

Then `POST /api/v1/apps/{app}/grants` once per scope, with `{"scopeId": "okta.users.read", "issuer": "<org URL>"}` (likewise `okta.groups.read`), and `POST /oauth2/v1/clients/{client_id}/roles` with `{"type": "READ_ONLY_ADMIN"}`.
