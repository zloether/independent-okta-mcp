# Spike Findings — Okta dev org (step 0.5)

Results of the live checks for design §16 items V1, V9, V10, V11, V13, V15. Each section: **result**, **evidence**, **design impact**. Helpers: `spikes/okta/okta_spike.py` (`uv run python spikes/okta/okta_spike.py --help`). Evidence uses `example.okta.com` / `example.com` placeholders; never paste tokens, keys or Okta result bodies here.

## Setup

| Item | Value |
|---|---|
| Date | |
| Org type | |
| Custom AS issuer | `https://example.okta.com/oauth2/aus…` |
| AS audience | |
| Test groups | `mcp-okta-…` (`00g…`), `mcp-okta-…` (`00g…`) |
| Public client | `0oa…`, redirect URIs: |
| Service app | `0oa…`, "Require DPoP" default: |

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
| OIDC (`{issuer}/.well-known/openid-configuration`) | |
| RFC 8414 path insertion | |
| RFC 8414 appended | |

Per-client discovery behavior goes in the compatibility matrix below.

- Design impact:

## V11 — Static client IDs, loopback redirects, DCR

- Loopback with a port other than the registered one:
- `localhost` vs `127.0.0.1`:
- DCR availability:
- Design impact:

## V15 — Service app DPoP default and nonce behavior

- "Require DPoP" on by default for new API Services apps:
- Token endpoint without DPoP:
- Token endpoint nonce (`use_dpop_nonce` on first request?):
- Resource endpoint nonce (`GET /api/v1/users`):
- Design impact:

## Client compatibility matrix

| Client | Version | Discovery used | Static client ID | Redirect URI | `resource` sent | Result |
|---|---|---|---|---|---|---|
| | | | | | | |
