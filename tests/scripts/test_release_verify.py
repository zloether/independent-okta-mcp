"""scripts/release-verify.py (plan 8.3.2): a release tag must be an annotated tag, SSH-signed by
a key in `main`'s allowed-signers file, on a commit of `main`, naming pyproject's version.

Real git and ssh-keygen against a local bare "origin", as the release job runs it."""

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from _load import load_script

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "release-verify.py"
TAG = load_script("release-verify").TAG

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="needs ssh-keygen (on the CI runners)"
)

_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "maintainer@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "maintainer@example.com",
    "PATH": os.environ["PATH"],
}


def _run(*args: str | Path, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [str(a) for a in args], cwd=cwd, env=_ENV, capture_output=True, text=True, check=check
    )


def _git(cwd: Path, *args: str | Path) -> str:
    return _run("git", *args, cwd=cwd).stdout.strip()


def _key(tmp: Path, name: str) -> tuple[Path, str]:
    path = tmp / name
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path, cwd=tmp)
    return path, path.with_suffix(".pub").read_text().strip()


class Repo:
    """A maintainer clone pushing to a bare origin; `verify` runs in a fresh CI clone."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.origin = tmp / "origin.git"
        self.work = tmp / "work"
        _run("git", "init", "-q", "--bare", "-b", "main", self.origin, cwd=tmp)
        _run("git", "clone", "-q", self.origin, self.work, cwd=tmp)
        _git(self.work, "checkout", "-q", "-b", "main")
        self.key, pub = _key(tmp, "maintainer")
        self.other, self.other_pub = _key(tmp, "other")
        self.commit(signers=[pub], version="0.1.0rc1")
        _git(self.work, "push", "-q", "origin", "main")

    def commit(self, *, signers: list[str] | None = None, version: str | None = None) -> str:
        if signers is not None:
            (self.work / ".github").mkdir(exist_ok=True)
            lines = [f'maintainer@example.com namespaces="git" {k}' for k in signers]
            (self.work / ".github" / "allowed_signers").write_text("\n".join(lines) + "\n")
        if version is not None:
            (self.work / "pyproject.toml").write_text(
                f'[project]\nname = "independent-okta-mcp"\nversion = "{version}"\n'
            )
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-q", "--allow-empty", "-m", "change")
        return _git(self.work, "rev-parse", "HEAD")

    def tag(self, name: str, *, key: Path | None = None, signed: bool = True) -> None:
        key = key or self.key
        if signed:
            _git(
                self.work,
                "-c",
                "gpg.format=ssh",
                "-c",
                f"user.signingkey={key}",
                "tag",
                "-s",
                name,
                "-m",
                name,
            )
        else:
            _git(self.work, "tag", "-a", name, "-m", name)

    def push_tag(self, name: str, as_name: str | None = None) -> None:
        _git(self.work, "push", "-q", "origin", f"refs/tags/{name}:refs/tags/{as_name or name}")

    def verify(self, tag: str, *extra: str, depth: int | None = None) -> tuple[int, str, str]:
        ci = self.tmp / "ci"
        if ci.exists():
            shutil.rmtree(ci)
        # file:// so --depth applies, as actions/checkout's default depth 1 does.
        shallow = ["--depth", str(depth)] if depth else []
        src = self.origin.as_uri() if depth else self.origin
        _run("git", "clone", "-q", "--no-tags", *shallow, src, ci, cwd=self.tmp)
        out = self.tmp / "github_output"
        out.write_text("")
        env = _ENV | {"GITHUB_OUTPUT": str(out)}
        done = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(SCRIPT), tag, "--fetch", *extra],
            cwd=ci,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, done.stdout + done.stderr, out.read_text()


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


def test_signed_rc_tag_on_main(repo: Repo) -> None:
    repo.tag("v0.1.0rc1")
    repo.push_tag("v0.1.0rc1")
    code, log, out = repo.verify("v0.1.0rc1")
    assert code == 0, log
    assert "version=0.1.0rc1" in out.splitlines()
    assert "prerelease=true" in out.splitlines()
    # Nothing from the signature or the signers file is printed.
    assert "example.com" not in log


def test_final_release_is_not_prerelease(repo: Repo) -> None:
    repo.commit(version="0.1.0")
    _git(repo.work, "push", "-q", "origin", "main")
    repo.tag("v0.1.0")
    repo.push_tag("v0.1.0")
    code, log, out = repo.verify("v0.1.0")
    assert code == 0, log
    assert "prerelease=false" in out.splitlines()


def test_tag_must_match_github_sha(repo: Repo) -> None:
    repo.tag("v0.1.0rc1")
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1", "--sha", "0" * 40)
    assert code != 0
    assert "GITHUB_SHA" in log


@pytest.mark.parametrize(
    "name", ["v0.1", "0.1.0rc1", "v0.1.0-rc1", "v0.1.0.post1", "v0.1.0a1", "v0.1.0rc1\n"]
)
def test_tag_name_pattern(repo: Repo, name: str) -> None:
    code, log, out = repo.verify(name)
    assert code != 0
    assert "vX.Y.Z" in log
    assert out == ""


def test_pyproject_version_is_a_tag_this_accepts() -> None:
    """The tag is compared to pyproject's version as a string, and the wheel's file name
    carries the PEP 440 normalized version. Within TAG's grammar only a leading zero
    (`0.01.0`) normalizes differently, so both agree when there is none."""
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert TAG.fullmatch(f"v{version}")
    assert not re.search(r"(?<!\d)0\d", version), version


def test_releasing_doc_tags_are_accepted() -> None:
    # Every concrete tag the maintainer copies from the doc; `vX.Y.ZrcN` placeholders have no digit.
    text = (ROOT / "docs" / "releasing.md").read_text()
    tags = re.findall(r"(?:(?<=refs/tags/)|(?<![\w/.-]))v\d[^\s`]*", text)
    assert len(tags) >= 4
    for tag in tags:
        assert TAG.fullmatch(tag), tag


def test_lightweight_tag_refused(repo: Repo) -> None:
    _git(repo.work, "tag", "v0.1.0rc1")
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "annotated" in log


def test_unsigned_tag_refused(repo: Repo) -> None:
    repo.tag("v0.1.0rc1", signed=False)
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "SSH signature" in log


def test_signer_not_allowed(repo: Repo) -> None:
    repo.tag("v0.1.0rc1", key=repo.other)
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "signature" in log


def test_signers_read_from_main_tip_so_removal_revokes(repo: Repo) -> None:
    """A tag signed by a key `main` no longer lists fails, though its own commit listed it."""
    repo.tag("v0.1.0rc1")
    repo.commit(signers=[repo.other_pub])
    _git(repo.work, "push", "-q", "origin", "main")
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "signature" in log


def test_tag_off_main_refused_even_if_it_adds_its_signer(repo: Repo) -> None:
    _git(repo.work, "checkout", "-q", "-b", "side")
    repo.commit(signers=[repo.other_pub])
    repo.tag("v0.1.0rc1", key=repo.other)
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    # Refused on the signers read from main, before the is-it-on-main check.
    assert "signature" in log


def test_signed_tag_off_main_refused(repo: Repo) -> None:
    _git(repo.work, "checkout", "-q", "-b", "side")
    repo.commit()
    repo.tag("v0.1.0rc1")
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "not on main" in log


def test_version_mismatch_refused(repo: Repo) -> None:
    repo.tag("v0.2.0rc1")
    repo.push_tag("v0.2.0rc1")
    code, log, _ = repo.verify("v0.2.0rc1")
    assert code != 0
    assert "pyproject" in log


def test_tag_object_name_must_match_ref(repo: Repo) -> None:
    """A signed tag for one version can't be pushed under another name."""
    repo.tag("v0.1.0rc2")
    repo.push_tag("v0.1.0rc2", as_name="v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1")
    assert code != 0
    assert "names" in log


def test_tag_behind_main_tip_in_a_shallow_clone(repo: Repo) -> None:
    """main moved on after the tagged commit; the job's checkout is depth 1."""
    repo.tag("v0.1.0rc1")
    repo.commit()
    _git(repo.work, "push", "-q", "origin", "main")
    repo.push_tag("v0.1.0rc1")
    code, log, _ = repo.verify("v0.1.0rc1", depth=1)
    assert code == 0, log
