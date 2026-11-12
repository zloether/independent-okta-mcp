import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPTS = Path(__file__).parents[2] / "scripts"
# Scripts import their shared modules (fixturelib) by name, as `python scripts/x.py` allows.
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_script(name: str) -> ModuleType:
    """Import `scripts/<name>.py`; the hyphenated file names aren't importable by name."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
