import dataclasses
from types import MappingProxyType

import pytest

from okta_mcp.registry.loader import Domain, Registry, load_registry
from okta_mcp.registry.spec import load_spec


@pytest.fixture(scope="session")
def pilot() -> Registry:
    """The shipped registry, as the server loads it."""
    return load_registry(load_spec())


@pytest.fixture(scope="session")
def registry(pilot: Registry) -> Registry:
    """The pilot registries plus `vault`, a domain whose commands are all sensitive."""
    vault = {
        name: dataclasses.replace(c, domain="vault", sensitivity="sensitive")
        for name, c in pilot.domains["network-zones"].commands.items()
    }
    return Registry(
        MappingProxyType(
            {**pilot.domains, "vault": Domain("vault", "Secrets.", MappingProxyType(vault))}
        )
    )
