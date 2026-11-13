import pytest

from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import load_spec


@pytest.fixture(scope="session")
def registry() -> Registry:
    """The shipped registry against the pinned spec, loaded once."""
    return load_registry(load_spec())
