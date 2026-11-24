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

1. On a branch, set `version` in `pyproject.toml` (canonical PEP 440: `0.1.0rc1`, `0.1.0`), run `uv lock`, and move the changelog's **Unreleased** entries under the version. Merge to `main` with CI green. An `rcN` only tests the pipeline; a final folds its rc sections' entries into its own. With the first final (`0.1.0`), also move the classifier to `3 - Alpha` and the README's status (plan 8.4).
2. Tag that merge commit on `main` and push the tag:

   ```bash
   git fetch origin main && git tag -s v0.1.0rc1 -m v0.1.0rc1 origin/main
   ```

   ```bash
   git push origin v0.1.0rc1
   ```

3. Approve the `image` job, then the `pypi` job once `image-test` passes (Actions → the run → Review deployments). Before approving, check the run's commit is the one you tagged.
4. One tag at a time: a run waiting for approval holds the `release` concurrency group, and a third tag pushed meanwhile cancels the second's queued run. Push the next tag after the last run has ended.
5. `vX.Y.ZrcN` goes to TestPyPI, a GHCR `X.Y.ZrcN` tag and a GitHub pre-release; `vX.Y.Z` to PyPI, GHCR `X.Y.Z` and a release. Nothing is tagged `latest`.

A refused tag (unsigned, not on `main`, version mismatch) fails `verify` and publishes nothing. Delete it, fix the cause (for a mismatch, step 1 again: the tag must equal `version` on `main`), and tag again (deleting needs the ruleset bypass):

```bash
git push origin :refs/tags/v0.1.0rc1
```

If a run fails after `image` pushed, the GHCR tag exists but no release does; fix, bump the rc number (step 1: `version`, `uv lock`, merged to `main`) and tag again rather than reusing the tag.

## Checking a release

`--repo` alone accepts an attestation from any workflow on any branch of the repository, and anyone with write access can run one; the other flags pin it to `release.yml` run for that tag on a GitHub-hosted runner.

```bash
gh attestation verify oci://ghcr.io/zloether/independent-okta-mcp@sha256:<digest> --repo zloether/independent-okta-mcp --signer-workflow zloether/independent-okta-mcp/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

```bash
gh attestation verify independent_okta_mcp-<version>-py3-none-any.whl --repo zloether/independent-okta-mcp --signer-workflow zloether/independent-okta-mcp/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```
