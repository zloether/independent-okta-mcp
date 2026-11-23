# Changelog

Changes an operator or user of the server would notice. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Design and review history is in the [decisions log](docs/decisions-log.md).

## Unreleased

No release has been tagged and no image is published; the server builds from a checkout. The first release will be `1.0.0` ([plan](docs/implementation-plan.md) step 8.4). Until then anything may change without notice: command names, policy file format, environment variables.

### Security

- An `expand` value could return what a sibling command returns, to a role the policy refused that command: role targets through `groups`/`users list-roles` `expand=targets/…`, policy rules through `policies list`/`get` `expand=rules`, user classification through `users list` `expand=classification`, device users through `devices list` `expand=user`/`userSummary` (and possibly OS-account `expand=users`), scope details through `authorization-servers list-tokens`/`get-token` `expand=scope`, group names through `groups list-rules`/`get-rule` `expand=groupIdToGroupNameMap`, and possibly group rules through `groups get-members` `expand=group-rules`. Those values are gone; use the sibling commands. If a role of yours holds one of these commands without its sibling, its users could read the sibling's data.

### Changed

- `MCP_MAX_TOKEN_AGE` defaults to 3600 (was 86400): a token issued more than an hour ago is refused. Authorization servers set up with `scripts/okta-setup.py` or `terraform/okta` issue tokens of at most 30 minutes and are unaffected; set the variable for one that issues longer ones (the server logs `token_too_old` when it refuses an unexpired token for its age).
- A failed service token request now logs Okta's error code even when Okta puts it in `errorCode` instead of `error`, with the matching hint (for example `HTTP 400 invalid_client (check OKTA_CLIENT_ID, OKTA_PRIVATE_KEY_FILE and OKTA_KEY_ID …)`). A reply with no code says what it looked like (its JSON key names or media type), never its content.
- `okta.profileMappings.read` needs Org Administrator on the service app, not Read-only Administrator: `schemas get-mapping` got HTTP 403 under Read-only Administrator in the CI org. `scripts/okta-setup.py check` now reports the role as missing, and `terraform/okta` needs `allow_org_admin = true` with that scope. To stay at Read-only Administrator, drop the scope (both mapping commands disappear).
- `scripts/okta-setup.py` no longer uses a role group that existed, with members, before the tool first used it: it reports the group as `manual` until its ID is listed under `reviewed_groups` in the config.

### Added

- Read-only MCP server for the Okta Management API: 24 domains as one tool each, plus `okta_help` and `okta_status`.
- OAuth resource server for an Okta custom authorization server; group-to-role policy file; `okta-mcp --check`.
- Service app access with `private_key_jwt` and DPoP; stdio dev mode.
- Audit log, per-user request limits, JSON operational logs.
- Container image definition and Compose example; Okta setup script and Terraform module.
- `diagnostics login-failures`, a composite command for help-desk roles.
- `scripts/okta-probe.py`: one GET per Management API path with the server's own service app settings, printing each status and Okta error code, to find the admin role a scope needs on your org.
- Install docs for a package install from a release's hashed `requirements.lock` (runbook §3.6); a plain `pip install` is not supported for production.
- `BASE_IMAGE` build argument: build the image on your own Debian or Ubuntu Python base, pinned by digest (a tag is refused).
