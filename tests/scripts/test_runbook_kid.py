"""The runbook's key-rotation one-liner (docs/runbook.md §4.4) prints the same JWK and `kid`
as `scripts/okta-setup.py`, so a rotated key's `OKTA_KEY_ID` matches what the setup tools
compute. The command is run as written in the runbook, not copied here."""

import json
import re
import subprocess
import sys
from pathlib import Path

from _load import load_script
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbook.md"
setup = load_script("okta-setup")


def _one_liner() -> str:
    match = re.search(
        r"uv run --frozen --no-dev python -c '([^']+)' okta-mcp-service-2\.pub\.pem",
        RUNBOOK.read_text(),
    )
    assert match is not None, "runbook §4.4 kid one-liner not found"
    return match.group(1)


def test_runbook_kid_matches_okta_setup(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "okta-mcp-service-2.pub.pem"
    path.write_bytes(pem)
    # The command comes from a checked-in doc, run in isolated mode on a temp key.
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", _one_liner(), str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert json.loads(out) == setup.public_jwk(pem)
