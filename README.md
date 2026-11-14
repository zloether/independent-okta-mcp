# independent-okta-mcp

A self-hosted, read-only [MCP](https://modelcontextprotocol.io) server for the Okta Management API. Users sign in with OAuth against an Okta custom authorization server (needs Okta's API Access Management add-on in production orgs; see [Prerequisites](docs/okta-setup.md#prerequisites)); their Okta group memberships map to roles in a version-controlled policy that decides which tools and commands each user may call. The server calls Okta with a read-only service app and caps every result by items, bytes and time. It ships as a single stateless container.

**Status:** pre-alpha. Not usable yet; under active development.

- [Design](docs/design/mcp-server.md)
- [Implementation plan](docs/implementation-plan.md)
- [Okta setup](docs/okta-setup.md)
- [Runbook](docs/runbook.md): deploy, operate, rotate, kill switch

## Local dev mode (stdio)

For trying the pilot domains against a dev org from an MCP client on your own machine. There is no authentication: the caller is the principal in a file, checked by the normal policy. Refused when `MCP_ENV=production`; the HTTP app never runs this way.

```yaml
# principal.yaml: who you are to the policy
uid: 00u1abcdEFGH2ijkl345        # your Okta user ID
sub: you@example.com
groups: [00g1readers000000000]   # group IDs your policy maps to roles
```

```
MCP_DEV_MODE=1 MCP_DEV_PRINCIPAL_FILE=principal.yaml \
MCP_POLICY_FILE=tests/policy/fixtures/pilot.yaml \
MCP_CURSOR_KEY="$(openssl rand -base64 32)" \
OKTA_ORG_URL=https://your-org.okta.com OKTA_SCOPES="okta.groups.read okta.networkZones.read" \
OKTA_API_TOKEN_FILE=okta-token.txt \
uv run okta-mcp --stdio
```

Add `--check` to validate the configuration and policy without serving (exit `0` or `2`).

Use a read-only admin's API token, or the service app (`OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY_FILE`) instead of `OKTA_API_TOKEN_FILE`. In a client config, pass the same variables as the server's environment; set `MCP_CURSOR_KEY` to a fixed value there, or cursors stop working at each restart.

## License

Apache-2.0 with the Commons Clause: free to use and modify, not to sell. See [LICENSE](LICENSE).
