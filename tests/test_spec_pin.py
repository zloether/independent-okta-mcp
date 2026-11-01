import hashlib
import json
from importlib.resources import files

SPECS = files("okta_mcp") / "data" / "specs"


def test_spec_matches_pin() -> None:
    pin = json.loads((SPECS / "PINNED.json").read_text())
    spec = (SPECS / "management-minimal.yaml").read_bytes()
    assert hashlib.sha256(spec).hexdigest() == pin["sha256"]
    assert pin["url"].startswith("https://raw.githubusercontent.com/")
    assert pin["commit"] in pin["url"]
