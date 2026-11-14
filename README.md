# independent-okta-mcp

A self-hosted, read-only [MCP](https://modelcontextprotocol.io) server for the Okta Management API. Users sign in with Okta OAuth; their groups map to roles in a version-controlled policy that decides what each may call. Ships as one stateless container.

**Status:** pre-alpha. Not usable yet; under active development.

- [Okta setup](docs/okta-setup.md): prerequisites (API Access Management), clients, service app
- [Runbook](docs/runbook.md): deploy, operate, rotate, kill switch
- [Design](docs/design/mcp-server.md) · [Plan](docs/implementation-plan.md)

## Local dev mode (stdio)

Try it against a dev org from a local MCP client. No authentication: the caller is the principal in a file, checked by the normal policy. Refused when `MCP_ENV=production`.

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

Use a read-only admin's API token, or the service app (`OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY_FILE`). In a client config, pass the same variables as the server's environment, with a fixed `MCP_CURSOR_KEY` (cursors break on each restart otherwise).

## License

Apache-2.0 with the Commons Clause: free to use and modify, not to sell. See [LICENSE](LICENSE).
