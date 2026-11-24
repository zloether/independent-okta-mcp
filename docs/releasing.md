# Releasing

For the maintainer. How [`release.yml`](../.github/workflows/release.yml) works and why: [design §11.5](design/mcp-server.md#115-release-pipeline). The pipeline needs the repository to be **public** (artifact attestations on a private repository need GitHub Enterprise Cloud, and the tag check fetches without credentials).

## One-time setup

1. **Signing key.** Tags are SSH-signed with a key listed in [`.github/allowed_signers`](../.github/allowed_signers) on `main`. With `gpg.format ssh` and `user.signingkey` already set for commits, also set:

   ```bash
   git config --global tag.gpgSign true
   ```

   To add or revoke a key, change `allowed_signers` on `main`; the check reads it from `main`'s tip, so a removed key stops working for every later tag.

2. **`release` environment** (Settings → Environments → New environment, name `release`):
   - Required reviewers: the maintainer. Leave "Prevent self-review" off (single maintainer).
   - Deployment branches and tags: "Selected branches and tags", one **tag** rule `v*`, no branch rules.
   - No secrets or variables.

3. **Tag ruleset** (Settings → Rules → Rulesets → New tag ruleset): target `v*`, enforcement Active, rules Restrict creations, Restrict updates, Restrict deletions; bypass list: the maintainer only. If GitHub doesn't enforce rulesets on the repository's plan while it is private, set it at the visibility change.

4. **Trusted Publishing**, just before the first version is published (a pending publisher doesn't reserve the name; the first upload does). On [test.pypi.org](https://test.pypi.org) and on [pypi.org](https://pypi.org), separately: Account → Publishing → Add a new pending publisher, project `independent-okta-mcp`, owner `zloether`, repository `independent-okta-mcp`, workflow `release.yml`, environment `release`. Without it the `pypi` job fails, and no GitHub release is made.

5. **GHCR package**, after the first push creates `ghcr.io/zloether/independent-okta-mcp`: in the package's settings, link it to the repository and set its visibility to public (packages start private).

## Cutting a release

1. On a branch, set `version` in `pyproject.toml` (canonical PEP 440: `0.1.0rc1`, `0.1.0`), run `uv lock`, and move the changelog's **Unreleased** entries under the version. Merge to `main` with CI green. An `rcN` only tests the pipeline; a final folds its rc sections' entries into its own. Keep the classifier and the README's status in step (`tests/test_package_metadata.py`).
2. Tag that merge commit on `main` and push the tag:

   ```bash
   git fetch origin main && git tag -s v0.1.0rc1 -m v0.1.0rc1 origin/main
   ```

   ```bash
   git push origin v0.1.0rc1
   ```

3. Approve the `image` job once `build` and both `image-build` jobs (amd64, arm64) pass, then the `pypi` job once both `image-test` jobs pass (Actions → the run → Review deployments). Before approving, check the run's commit is the one you tagged. Expect about 5 minutes of job time besides the waits for approval (the single-platform `0.1.0` run took 4.5); an arm64 runner can take longer to start.
4. One tag at a time: a run waiting for approval holds the `release` concurrency group, and a third tag pushed meanwhile cancels the second's queued run. Push the next tag after the last run has ended.
5. `vX.Y.ZrcN` goes to TestPyPI, a GHCR `X.Y.ZrcN` tag and a GitHub pre-release; `vX.Y.Z` to PyPI, GHCR `X.Y.Z` and a release. Nothing is tagged `latest`. From `0.1.1` the GHCR tag is one index of `linux/amd64` and `linux/arm64` (`0.1.0` and its rc are `linux/amd64` only).

A refused tag (unsigned, not on `main`, version mismatch) fails `verify` and publishes nothing. Delete it, fix the cause (for a mismatch, step 1 again: the tag must equal `version` on `main`), and tag again (deleting needs the ruleset bypass):

```bash
git push origin :refs/tags/v0.1.0rc1
```

If `build` or an `image-build` job fails, `image` doesn't start and nothing is published: handle the tag like a refused one, above. If a run fails after `image` pushed, the GHCR tag exists but no release does; fix, bump the rc number, or for a final the patch version (`0.1.0` to `0.1.1`), (step 1: `version`, `uv lock`, merged to `main`) and tag again rather than reusing the tag.

## Checking a release

The image's platforms (from `0.1.1`, `linux/amd64` and `linux/arm64`, each with an SBOM and BuildKit provenance manifest beside it):

```bash
docker buildx imagetools inspect ghcr.io/zloether/independent-okta-mcp@sha256:<digest>
```

`--repo` alone accepts an attestation from any workflow on any branch of the repository, and anyone with write access can run one; the other flags pin it to `release.yml` run for that tag on a GitHub-hosted runner.

```bash
gh attestation verify oci://ghcr.io/zloether/independent-okta-mcp@sha256:<digest> --repo zloether/independent-okta-mcp --signer-workflow zloether/independent-okta-mcp/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

```bash
gh attestation verify independent_okta_mcp-<version>-py3-none-any.whl --repo zloether/independent-okta-mcp --signer-workflow zloether/independent-okta-mcp/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

## Taking down a compromised release

Only for a release with malicious code in a published file ([`SECURITY.md`](../SECURITY.md#supported-versions)). A release with an ordinary vulnerability stays published; the next release fixes it. Work in this order: stopping the way in comes before deleting, or the next release can be compromised the same way.

1. **Stop the way in.** Find how the code got in before publishing anything else. The paths a release can come from: the signing key, the maintainer's GitHub account, a commit merged to `main`, an action or base image the workflow pulled, a locked dependency.
   - Remove a suspect key from [`.github/allowed_signers`](../.github/allowed_signers) on `main`. The check reads `main`'s tip, so this refuses every later tag signed with it.
   - Rotate the maintainer's GitHub credentials (password, 2FA recovery codes, SSH keys, personal access tokens), and read the account's and the repository's security logs.
   - Compare the tagged commit with what was reviewed, and the run's resolved action SHAs, base image digests and wheel hashes with what is pinned.
2. **Delete from PyPI.** On pypi.org: the project → Manage → Releases → the version → Options → Delete. PyPI never accepts a deleted file name or version again, so the fix ships as a new version. Don't yank: a yanked file is still served to an exact `==` pin and to a direct file install, which is how [runbook §3.6](runbook.md#36-without-a-container-install-from-a-release) installs the wheel. Then email security@pypi.org with the version and file hashes, so mirrors and malware scanners that cached the files hear of it.
3. **Delete from GHCR.** The package's page on GitHub → View and manage all versions → the version carrying the tag → Delete version (the image index; its SBOM and provenance are inside it). Hosts that already pulled the digest keep running it; only the advisory reaches them.
4. **Delete the GitHub release** and its assets. Keep the tag: it records what was published, and the version can't be reused anyway.
5. **Publish a GitHub security advisory** (Security → Advisories → New draft security advisory; ecosystem pip, package `independent-okta-mcp`, the affected version). Name the image digest and the wheel and sdist sha256 values, since the attestations stay valid: they are in Sigstore's public, append-only log, so `gh attestation verify` still passes on the compromised files. Tell operators that the code ran with their service key and cursor key, so they follow [runbook §5](runbook.md#5-kill-switch): stop the server, deactivate the service app, rotate the service key and the cursor key, and read Okta's System Log for the service app's client ID.
6. **Release the fix** as the next patch version from a commit you have checked, after step 1 is closed ([Cutting a release](#cutting-a-release)), and add the advisory's link to its changelog **Security** entry.
