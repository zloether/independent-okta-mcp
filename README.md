# independent-okta-mcp

A self-hosted, read-only [MCP](https://modelcontextprotocol.io) server for the Okta Management API. Users sign in with Okta OAuth; their groups map to roles in a version-controlled policy that decides what each may call. Runs as one stateless container.

An independent project: not affiliated with, endorsed by or supported by Okta, Inc.

## Status

**Under active development. Don't point it at a production org yet.** There is no release yet; release candidates (`rcN` tags) only test the publishing pipeline and are not for use. It builds from a checkout.

| | |
|---|---|
| Done | The server, policy engine, 24 command domains, container and setup tools, tested against mocked Okta in CI |
| Checked against an Okta dev org | The setup script; most commands through stdio dev mode; OAuth sign-in from Claude Code to this server over loopback HTTP and through a TLS proxy (Caddy), with tool calls; the compose example up to a ready container; the service app's rate-limit share capping its requests; `diagnostics login-failures` against real sign-in failures (lockout, unassigned app, policy DENY, MFA, device assurance and posture). The Kubernetes example ran on a local cluster |
| Checked nightly in CI against an Okta org | The service token with DPoP; every registry command but eight the CI org can't serve; each example role's allowed and refused calls; paging; path routing; `diagnostics login-failures` on four sign-in failures the job causes ([plan 8.2.1](docs/implementation-plan.md)) |
| Not yet done | Token refresh against this server; clients other than Claude Code; a deployment from the [runbook](docs/runbook.md) on a clean machine; `diagnostics login-failures` on IdP and threat events; the runbook steps marked **unverified** |
| Review | Written and reviewed with AI assistance (Claude Code), directed by the maintainer. No independent security audit ([SECURITY.md](SECURITY.md#review-status)) |

What is left is tracked in the [plan](docs/implementation-plan.md).

## Read more

- [Okta setup](docs/okta-setup.md): prerequisites (API Access Management), clients, service app
- [Deployment scenarios](docs/deployment-scenarios.md): where to host it, internal or internet-facing, one host or replicated
- [Runbook](docs/runbook.md): deploy, operate, rotate, kill switch
- [Clients](docs/compatibility-matrix.md): how an MCP client connects, and which have been tried
- [Design](docs/design/mcp-server.md) · [Plan](docs/implementation-plan.md) · [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Install

There is no release yet. From the first one: the container image from GHCR, pinned by digest (the supported way), or the package installed from the release's hashed `requirements.lock` and wheel ([runbook §3.6](docs/runbook.md#36-without-a-container-install-from-a-release)). A plain `pip install independent-okta-mcp` resolves unpinned dependency versions and is not supported for production. The license is not OSI-approved (see [License](#license)), which some company dependency policies block.

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

Apache-2.0 with the Commons Clause: free to use and modify, not to sell. See [LICENSE](LICENSE). The Commons Clause makes it source-available, not open source: it isn't an OSI-approved license. The vendored Okta OpenAPI specification is Okta's, under Apache-2.0 ([NOTICE](NOTICE)).
