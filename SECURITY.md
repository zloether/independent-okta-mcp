# Security policy

independent-okta-mcp holds a service credential that can read an Okta org, so reports about it are welcome and handled first.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Please don't open a public issue or pull request for a suspected vulnerability.

Include what you can of:

- the commit or version, and how the server was run (HTTP or stdio dev mode, DPoP on or off);
- the role or policy involved, and the tool call or request that shows the problem;
- what you expected and what happened.

Never include real tokens, keys, Okta result bodies or your org's hostname. Use `example.okta.com` and `*.example.com`, as the tests do.

This is a personal project maintained in spare time. Expect an acknowledgement within a week; there is no bounty.

## Supported versions

Security fixes ship only in new versions. They are not backported: only the latest release is supported, and getting a fix means upgrading to the release that has it. Each fix is listed under **Security** in the [changelog](CHANGELOG.md), with what an operator should check (for example, a role that held an affected command). Read it before upgrading ([runbook §4.1](docs/runbook.md#41-upgrade)).

There is no release yet. Until the first one, fixes land on `main` only.

## What counts

Anything that breaks a property the [design](docs/design/mcp-server.md) claims (§12), for example:

- a caller reaching a command, argument or attribute their roles don't allow, or data from another endpoint (path injection, sibling-endpoint aliasing);
- the server sending anything but a GET to the Okta Management API, or sending its service token off the configured org;
- a secret the scrub rules should redact appearing in a result, a log line or the audit log;
- accepting a token it should refuse (wrong issuer, audience, client, signature, expiry or scope);
- the setup script or Terraform module widening access in Okta beyond what its config states.

## Known limits

These are documented and accepted, not vulnerabilities. Improvements are still welcome as ordinary issues.

- **Prompt injection through Okta data.** Results can hold text an outsider chose (design §12.1, R1; [runbook §3.5](docs/runbook.md#35-tell-your-users)).
- **Role-group membership is the authorization boundary**, and it is managed in Okta, outside the server's view (design §8.2, R7).
- **Redaction is by key name.** A secret inside a string value, or in a custom profile attribute with an ordinary name, is not redacted (design §12.1, §12.4; [runbook §1](docs/runbook.md#1-before-you-start)).
- **User tokens are checked locally**, so revoking one in Okta doesn't end it before it expires (design §9.6; [runbook §5](docs/runbook.md#5-kill-switch)).
- **`MCP_TRUST_PROXY` trusts any peer**, so the port must be reachable only by the proxy (design §11.4).

## Review status

The code and its recorded reviews ([decisions log](docs/decisions-log.md)) were produced with AI assistance (Claude Code), directed and checked by the maintainer. No independent security audit has been done. Treat the server accordingly until one has, and until the live checks listed in the [README](README.md#status) are complete.
