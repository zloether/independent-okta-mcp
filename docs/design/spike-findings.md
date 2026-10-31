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

## V1 — `groups` claim (IDs) on access tokens

- Result:
- Evidence:
- Design impact:

## V13 — `uid` vs `sub`; ID-emitting groups expression

- Expression used:
- Result:
- Evidence:
- Design impact:

## V9 — RFC 8707 `resource` parameter

| Variant | Outcome | `aud` |
|---|---|---|
| no `resource` | | |
| `resource` on authorize + token | | |
| `resource` on authorize only | | |
| `resource` ≠ AS audience | | |

- Design impact:

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

- Loopback with a port other than the registered one:
- `localhost` vs `127.0.0.1`:
- DCR availability: metadata advertises `registration_endpoint: {org}/oauth2/v1/clients`, but an anonymous registration POST returns `403 E0000005 Invalid session`. Registration needs an admin API credential, so there is no open DCR for MCP clients; they need a pre-registered static `client_id`.
- Design impact:

## V15 — Service app DPoP default and nonce behavior

- "Require DPoP" on by default for new API Services apps: **no when created via `POST /api/v1/apps`** (`settings.oauthClient.dpop_bound_access_tokens: false` when omitted). Console default not yet checked.
- With DPoP off: the token endpoint ignores a DPoP header and issues `token_type: Bearer`. Presenting that token as `Authorization: DPoP …` fails with `401 invalid_token "The presented access_token is not DPoP bound."`; `Bearer` succeeds (200).
- With DPoP on (`dpop_bound_access_tokens: true`): a token request without a proof fails with `400 invalid_dpop_proof "The DPoP proof JWT header is missing."`.
- Token endpoint nonce: **yes**. The first proof, sent without a nonce, is rejected with a `DPoP-Nonce` header; the retry with that nonce returns `token_type: DPoP`.
- Resource endpoint nonce (`GET /api/v1/users`): 200 on the first attempt with a proof carrying the token-endpoint nonce plus `ath`; no new `DPoP-Nonce` was sent. Whether a proof *without* a nonce is accepted at the resource is untested.
- Design impact: the runbook must set "Require DPoP" explicitly (API/Terraform default is off). Keep the nonce retry at the token endpoint. At resource endpoints, reuse the last nonce and keep the one-shot retry on `use_dpop_nonce`.

## Client compatibility matrix

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

**Groups claim**: `POST /api/v1/authorizationServers/{as}/claims`. Okta accepted the expression at creation; whether it evaluates to IDs is V13, pending a user token.

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
