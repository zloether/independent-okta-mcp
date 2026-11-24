"""docker/compose.example.yaml keeps the runtime privileges design §11.4 asks for (plan 7.2).

Static: no Docker needed. `docker compose config` and a bring-up were run by hand (see the
decisions log); this pins what a later edit could quietly loosen.
"""

from __future__ import annotations

import base64
import os
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from okta_mcp.config import _NAMES, _SECRETS, load_config  # pyright: ignore[reportPrivateUsage]

ROOT = Path(__file__).parents[1]
DOCKER = ROOT / "docker"
COMPOSE = DOCKER / "compose.example.yaml"


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    return cast(dict[str, Any], yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def service(doc: dict[str, Any]) -> dict[str, Any]:
    services = cast(dict[str, Any], doc["services"])
    assert list(services) == ["okta-mcp"]
    return cast(dict[str, Any], services["okta-mcp"])


@pytest.fixture(scope="module")
def environment(service: dict[str, Any]) -> dict[str, str]:
    env = service["environment"]
    assert isinstance(env, dict), "use the mapping form, so keys can be checked"
    return {str(k): "" if v is None else str(v) for k, v in cast(dict[str, Any], env).items()}


def test_hardened(service: dict[str, Any]) -> None:
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    # Exactly this: `seccomp:unconfined` or `apparmor:unconfined` would loosen confinement.
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["user"] == "10001:10001"
    # env_file and extends could bring in MCP_ENV, dev mode or inline secrets unseen.
    for key in (
        "privileged",
        "network_mode",
        "pid",
        "ipc",
        "devices",
        "tmpfs",
        "env_file",
        "extends",
    ):
        assert key not in service, key


def test_port_published_on_loopback_only(service: dict[str, Any]) -> None:
    # Docker's published ports bypass host firewalls (design §11.4).
    for port in service.get("ports", []):
        assert isinstance(port, str) and port.startswith("127.0.0.1:"), port


IMAGE_REF = re.compile(
    r"ghcr\.io/(?P<repo>[a-z0-9._-]+/[a-z0-9._-]+):(?P<tag>[0-9][\w.]*)@sha256:[0-9a-f]{64}"
)


def test_image_is_a_release_pinned_by_digest(service: dict[str, Any]) -> None:
    """The published image, tag and digest (8.3.2): a tag alone can be moved, and a `build:`
    left beside `image:` would have Compose build instead of pulling what was verified."""
    image = str(service["image"])
    match = IMAGE_REF.fullmatch(image)
    assert match, image
    source = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["urls"]["Source"]
    assert source == f"https://github.com/{match['repo']}"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## {re.escape(match['tag'])} - ", changelog, re.M), "not a release"
    for key in ("build", "pull_policy"):
        assert key not in service, key


def test_runbook_gives_the_same_image(service: dict[str, Any]) -> None:
    # Runbook §1 names the image an operator verifies; it must be the one the example runs.
    runbook = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    found = {m[0] for m in IMAGE_REF.finditer(runbook)}
    assert found == {service["image"]}


def test_single_platform_notes_name_the_pinned_tag(service: dict[str, Any]) -> None:
    """Notes that `X` is `linux/amd64` only (8.4.1): once a multi-arch tag is pinned, a stale note
    for the old one fails here instead of telling ARM operators to emulate."""
    match = IMAGE_REF.fullmatch(str(service["image"]))
    assert match
    docs = [COMPOSE, *(ROOT / p for p in ("README.md", "docs/runbook.md"))]
    docs.append(ROOT / "docs" / "deployment-scenarios.md")
    pattern = re.compile(r"`?(\d+\.\d+\.\d+\w*)`? (?:image )?is `?linux/amd64`? only")
    notes = {(d.name, v) for d in docs for v in pattern.findall(d.read_text(encoding="utf-8"))}
    assert notes, "no amd64-only note found: drop this test with the multi-arch release"
    assert {v for _, v in notes} == {match["tag"]}, notes


def test_environment_names_are_config_variables(environment: dict[str, str]) -> None:
    known = set(_NAMES) | {f"{s}_FILE" for s in _SECRETS}
    assert set(environment) <= known, set(environment) - known


def test_no_secret_values_inline(environment: dict[str, str]) -> None:
    for name in _SECRETS:
        assert name not in environment, f"{name}: use {name}_FILE and a secret"
    assert environment["MCP_CURSOR_KEY_FILE"].startswith("/run/secrets/")
    assert environment["OKTA_PRIVATE_KEY_FILE"].startswith("/run/secrets/")


def test_production_and_no_dev_mode(environment: dict[str, str]) -> None:
    # The image sets MCP_ENV=production; the example must not undo it.
    assert "MCP_ENV" not in environment
    assert not any(k.startswith("MCP_DEV_") for k in environment)


def test_trust_proxy_off(environment: dict[str, str]) -> None:
    assert environment["MCP_TRUST_PROXY"] == "false"


def test_policy_mounted_read_only_and_must_exist(
    service: dict[str, Any], environment: dict[str, str]
) -> None:
    mounts = [cast(dict[str, Any], v) for v in service["volumes"]]
    policy = [m for m in mounts if m["target"] == environment["MCP_POLICY_FILE"]]
    assert len(policy) == 1
    assert policy[0]["type"] == "bind"
    assert policy[0]["read_only"] is True
    assert policy[0]["bind"]["create_host_path"] is False
    for m in mounts:
        assert m.get("read_only") is True, m


def test_secrets_are_files_in_the_ignored_directory(
    doc: dict[str, Any], service: dict[str, Any]
) -> None:
    declared = cast(dict[str, Any], doc["secrets"])
    assert set(service["secrets"]) == set(declared)
    for spec in declared.values():
        path = PurePosixPath(str(spec["file"]))
        assert ".." not in path.parts and path.parent == PurePosixPath("secrets"), path


def test_operator_files_are_git_ignored(service: dict[str, Any]) -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "docker/secrets/" in ignore
    for m in service["volumes"]:
        source = PurePosixPath(str(cast(dict[str, Any], m)["source"]))
        assert f"docker/{source}" in ignore, source


def test_example_values_pass_config_validation(environment: dict[str, str], tmp_path: Path) -> None:
    """The placeholders are valid as written, with the image's MCP_ENV, so an operator who
    changes only the CHANGE values doesn't meet a config error the example caused."""
    key = tmp_path / "okta.pem"
    key.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cursor = tmp_path / "cursor_key"
    cursor.write_text(base64.b64encode(os.urandom(32)).decode())
    env = {
        **environment,
        "MCP_ENV": "production",
        "MCP_POLICY_FILE": str(DOCKER / "policy.example.yaml"),
        "MCP_CURSOR_KEY_FILE": str(cursor),
        "OKTA_PRIVATE_KEY_FILE": str(key),
    }
    config = load_config(env)
    assert config.trust_proxy is False
