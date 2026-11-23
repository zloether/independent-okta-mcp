"""Check a release tag before anything is built (plan 8.3.2); run by release.yml's `verify` job.

    python3 -I scripts/release-verify.py vX.Y.Z[rcN] [--fetch] [--sha COMMIT]

Passes (exit 0) only if all hold, else exits 1 with one fixed message:

- the name is `vX.Y.Z` or `vX.Y.ZrcN`;
- the ref is an annotated tag whose own `tag` header is that name (a tag signed for one
  version can't be pushed under another);
- it carries an SSH signature that `git verify-tag` accepts against `.github/allowed_signers`
  as it is on the tip of `main`, not as it is in the tagged commit, so removing a key on
  `main` revokes it and a commit off `main` can't add its own signer;
- the tagged commit is `--sha` (the workflow's `GITHUB_SHA`) and is on `main`;
- `project.version` in that commit's `pyproject.toml` equals the name without the `v`.

With `--fetch`, first fetches `main` (unshallowing a shallow clone) and the tag from
`origin`, overwriting a local tag of that name (actions/checkout can leave a lightweight
copy of an annotated tag). Writes
`version=` and `prerelease=` to `$GITHUB_OUTPUT`. Prints nothing from the signature, the
signers file or git's output: only the tag name, after it has matched the pattern.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

TAG = re.compile(r"v(\d+\.\d+\.\d+(rc\d+)?)")
MAIN = "refs/remotes/origin/main"
SIGNERS = ".github/allowed_signers"


class Refused(Exception):
    pass


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if check and done.returncode != 0:
        raise Refused(f"git {args[0]} failed")
    return done


def verify(tag: str, *, fetch: bool, sha: str | None) -> tuple[str, bool]:
    m = TAG.fullmatch(tag)
    if not m:
        raise Refused("tag name must be vX.Y.Z or vX.Y.ZrcN")
    version, prerelease = m.group(1), m.group(2) is not None
    ref = f"refs/tags/{tag}"
    if fetch:
        # A shallow clone (actions/checkout's default) hides the ancestry checked below.
        deepen = (
            ["--unshallow"]
            if _git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
            else []
        )
        _git("fetch", "--quiet", "--no-tags", *deepen, "origin", f"+refs/heads/main:{MAIN}")
        _git("fetch", "--quiet", "--no-tags", "--force", "origin", f"+{ref}:{ref}")

    if _git("cat-file", "-t", ref).stdout.strip() != "tag":
        raise Refused(f"{tag} is not an annotated tag")
    body = _git("cat-file", "tag", ref).stdout
    header = body.split("\n\n", 1)[0].splitlines()
    if f"tag {tag}" not in header:
        raise Refused(f"the tag object behind {ref} names a different tag")
    if "-----BEGIN SSH SIGNATURE-----" not in body:
        raise Refused(f"{tag} has no SSH signature")

    signers = _git("show", f"{MAIN}:{SIGNERS}", check=False)
    if signers.returncode != 0 or not signers.stdout.strip():
        raise Refused(f"no {SIGNERS} on main")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "allowed_signers"
        path.write_text(signers.stdout)
        checked = _git(
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={path}",
            "verify-tag",
            ref,
            check=False,
        )
    if checked.returncode != 0:
        raise Refused(f"{tag}'s signature isn't from a key in main's {SIGNERS}")

    commit = _git("rev-parse", f"{ref}^{{commit}}").stdout.strip()
    if sha is not None and commit != sha:
        raise Refused(f"{tag} doesn't point at GITHUB_SHA")
    if _git("merge-base", "--is-ancestor", commit, MAIN, check=False).returncode != 0:
        raise Refused(f"{tag} is not on main")

    try:
        project = tomllib.loads(_git("show", f"{commit}:pyproject.toml").stdout)["project"]
    except (Refused, tomllib.TOMLDecodeError, KeyError) as e:
        raise Refused("can't read project.version from pyproject.toml") from e
    if project.get("version") != version:
        raise Refused(f"{tag} doesn't match pyproject's version")
    return version, prerelease


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("tag")
    parser.add_argument("--fetch", action="store_true", help="fetch main and the tag first")
    parser.add_argument("--sha", help="the commit the tag must point at (GITHUB_SHA)")
    args = parser.parse_args(argv)
    try:
        version, prerelease = verify(args.tag, fetch=args.fetch, sha=args.sha)
    except Refused as e:
        print(f"::error::release-verify: {e}", file=sys.stderr)
        return 1
    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as f:
            f.write(f"version={version}\nprerelease={str(prerelease).lower()}\n")
    print(f"release-verify: {args.tag} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
