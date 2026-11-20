# Changelog

Changes an operator or user of the server would notice. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Design and review history is in the [decisions log](docs/decisions-log.md).

## Unreleased

No release has been tagged and no image is published; the server builds from a checkout. The first release will be `1.0.0` ([plan](docs/implementation-plan.md) step 8.4). Until then anything may change without notice: command names, policy file format, environment variables.

### Security

- An `expand` value could return what a sibling command returns, to a role the policy refused that command: role targets through `groups`/`users list-roles` `expand=targets/…`, policy rules through `policies list`/`get` `expand=rules`, user classification through `users list` `expand=classification`, device users through `devices list` `expand=user`/`userSummary` (and possibly OS-account `expand=users`), scope details through `authorization-servers list-tokens`/`get-token` `expand=scope`, group names through `groups list-rules`/`get-rule` `expand=groupIdToGroupNameMap`, and possibly group rules through `groups get-members` `expand=group-rules`. Those values are gone; use the sibling commands. If a role of yours holds one of these commands without its sibling, its users could read the sibling's data.

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
- `BASE_IMAGE` build argument: build the image on your own Debian or Ubuntu Python base, pinned by digest (a tag is refused).
