# independent-okta-mcp

A self-hosted, read-only [MCP](https://modelcontextprotocol.io) server for the Okta Management API. Users sign in with OAuth against an Okta custom authorization server; their Okta group memberships map to roles in a version-controlled policy that decides which tools and commands each user may call. The server calls Okta with a read-only service app and caps every result by items, bytes and time. It ships as a single stateless container.

**Status:** pre-alpha. Not usable yet; under active development.

- [Design](docs/design/mcp-server.md)
- [Implementation plan](docs/implementation-plan.md)

## License

Apache-2.0 with the Commons Clause: free to use and modify, not to sell. See [LICENSE](LICENSE).
