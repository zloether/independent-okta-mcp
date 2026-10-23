import subprocess
import sys
from importlib.resources import files

import okta_mcp
from okta_mcp.__main__ import main


def test_version() -> None:
    assert okta_mcp.__version__


def test_main_prints_version(capsys) -> None:
    assert main() == 0
    assert capsys.readouterr().out.strip() == f"okta-mcp {okta_mcp.__version__}"


def test_module_entrypoint_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "okta_mcp"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0


def test_data_dir_is_package_data() -> None:
    assert files("okta_mcp").joinpath("data").is_dir()
