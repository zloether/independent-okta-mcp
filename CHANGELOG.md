# Changelog

Changes an operator or user of the server would notice. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Design and review history is in the [decisions log](docs/decisions-log.md).

## Unreleased

### Changed

- `docker/compose.example.yaml` and runbook §1 run `0.1.1`, `ghcr.io/zloether/independent-okta-mcp:0.1.1`, pinned by its index digest, which runs natively on ARM hosts (an arm64 Mac, Graviton); the `platform: linux/amd64` note is gone.

## 0.1.1 - 2026-11-24

### Added

- The image is multi-platform: `ghcr.io/zloether/independent-okta-mcp:0.1.1` is one index of `linux/amd64` and `linux/arm64`, so `docker pull` takes the host's own platform and an ARM host (an arm64 Mac, Graviton) runs it natively. Each platform is built and tested (`tests/container/`, the Trivy scan) on a runner of its own architecture, and carries its own SBOM and BuildKit provenance; the release notes' digest, and the GitHub attestation, are the index's. Pin that digest as before: `gh attestation verify` is unchanged.

### Changed

- `docker/compose.example.yaml` and the runbook run the published `0.1.0` image, `ghcr.io/zloether/independent-okta-mcp:0.1.0`, pinned by digest, instead of building from a checkout; upgrades are a tag and digest bump and `docker compose pull`. The `0.1.0` image is `linux/amd64` only: on an ARM host, set `platform: linux/amd64` (emulated) for it, or pin `0.1.1`. The example moves to `0.1.1` once it is published.

### Security

- No third-party fixes: no Dependabot update (locked dependencies, actions, base image digests) has merged since `0.1.0`, so the image's Python packages and base are the same as `0.1.0`'s, apart from Debian security updates the build installs. Nothing to check after upgrading.

## 0.1.0 - 2026-11-23

The first release: alpha, not for production orgs yet. Before `1.0` a minor version can rename commands or change the policy file format and environment variables. The release candidate `0.1.0rc1` (TestPyPI, a GHCR `0.1.0rc1` tag and a GitHub pre-release) only tested the pipeline and had the same entries; use `0.1.0`.

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
- Install docs for a package install from a release's hashed `requirements.lock` (runbook §3.6); a plain `pip install` is not supported for production. Its `gh attestation verify` accepts only an attestation made by `release.yml` for that tag on a GitHub-hosted runner.
- The package states its license as `LicenseRef-Commons-Clause-Apache-2.0` and ships `LICENSE` and `NOTICE` (the vendored Okta spec's attribution) in the wheel, the sdist and the image.
- `BASE_IMAGE` build argument: build the image on your own Debian or Ubuntu Python base, pinned by digest (a tag is refused).
