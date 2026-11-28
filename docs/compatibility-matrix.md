# MCP clients

How an MCP client connects to independent-okta-mcp, and which clients have been tried. The Okta side is in [`okta-setup.md`](okta-setup.md); the evidence behind each rule is in [`design/spike-findings.md`](design/spike-findings.md).

## What a client must support

independent-okta-mcp is an OAuth resource server; Okta is the authorization server (design §8.3). A client connects if it can do all of these:

- **Streamable HTTP** to `MCP_PUBLIC_URL`, with `Authorization: Bearer`.
- **Discovery from the 401.** The server answers an unauthenticated request with `WWW-Authenticate: Bearer resource_metadata=…`; the client reads that document, then Okta's metadata (OIDC discovery or RFC 8414; Okta serves both).
- **Authorization code with PKCE (S256)**, as a public client.
- **A client ID you set.** Okta has no open dynamic client registration, so each client is an app an admin registered (`clients:` in the setup config), and the client must let you enter that app's client ID.
- **A fixed redirect URI.** Okta matches the redirect URI exactly, host and port included: `localhost` is not `127.0.0.1`, and a client that picks a new loopback port for each sign-in can't connect.

The client's requested scopes must be allowed by the authorization server's rule. The setup tools allow `openid profile email offline_access okta-mcp`.

## Claude Code

Register `http://localhost:8765/callback` as the client app's redirect URI (the host is not configurable in Claude Code; the port is), then:

```sh
claude mcp add --transport http okta https://mcp.example.com/mcp \
  --client-id 0oa1client0000000000 --callback-port 8765
```

Start sign-in from `/mcp` in a session. Claude Code requests `okta-mcp offline_access`, so the rule must allow `offline_access` even without refresh tokens (the setup tools do this). With refresh tokens on ([option B](okta-setup.md#refresh-tokens-option-a-or-b)), keep access tokens well above 5 minutes: Claude Code refreshes a token that is close to expiry.

## Matrix

| Client | Version | Discovery used | Client ID | Redirect URI | Scopes requested | Result | Tested against |
|---|---|---|---|---|---|---|---|
| Claude Code | 2.1.311 | The 401, then the path-specific metadata URL (`/.well-known/oauth-protected-resource/mcp`); never the root URL. Okta's metadata fetched directly | `--client-id` | `http://localhost:8765/callback` (`--callback-port`) | `okta-mcp offline_access` | ✅ Both test users signed in with the right `uid` and group ID; silent refresh works under option B | The spike check server, 2026-11-04. This server over loopback `http`, 2026-11-15: both users signed in, each saw only its role's tools; refresh token granted (refresh against this server: the 2.1.326 row). Behind Caddy with a public TLS certificate, 2026-11-16 (a Claude Code cloud session; its version wasn't recorded, so `2.1.311` covers only the runs before it): the helpdesk user signed in and ran commands from each of its four tools |
| Claude Code | 2.1.326 | As above | `--client-id` | `http://localhost:8765/callback` (`--callback-port`) | `okta-mcp offline_access` | ✅ Signed in, each user saw only its role's callable tools, and a call after the access token expired refreshed with no new sign-in (option B) | This server's `0.1.1` image behind Caddy on `localhost` with its local CA (`NODE_EXTRA_CA_CERTS`), deployed from the runbook on a clean Mac, 2026-11-28 (plan 7.3, 4.6) |

No other client has been tried. A row is added when one is ([plan](implementation-plan.md) steps 0.6, 4.6 and 8.2); if you try one, an issue with the result is welcome.
