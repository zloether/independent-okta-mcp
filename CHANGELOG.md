# Changelog

Changes an operator or user of the server would notice. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Design and review history is in the [decisions log](docs/decisions-log.md).

## Unreleased

No release has been tagged and no image is published; the server builds from a checkout. The first release will be `1.0.0` ([plan](docs/implementation-plan.md) step 8.4). Until then anything may change without notice: command names, policy file format, environment variables.

### Changed

- `MCP_MAX_TOKEN_AGE` defaults to 3600 (was 86400): a token issued more than an hour ago is refused. Authorization servers set up with `scripts/okta-setup.py` or `terraform/okta` issue tokens of at most 30 minutes and are unaffected; set the variable for one that issues longer ones (the server logs `token_too_old` when it refuses an unexpired token for its age).
- `scripts/okta-setup.py` no longer uses a role group that existed, with members, before the tool first used it: it reports the group as `manual` until its ID is listed under `reviewed_groups` in the config.

### Added

- Read-only MCP server for the Okta Management API: 24 domains as one tool each, plus `okta_help` and `okta_status`.
- OAuth resource server for an Okta custom authorization server; group-to-role policy file; `okta-mcp --check`.
- Service app access with `private_key_jwt` and DPoP; stdio dev mode.
- Audit log, per-user request limits, JSON operational logs.
- Container image definition and Compose example; Okta setup script and Terraform module.
- `diagnostics login-failures`, a composite command for help-desk roles.
