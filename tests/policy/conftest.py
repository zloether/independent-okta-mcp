import dataclasses
from types import MappingProxyType

import pytest

from okta_mcp.registry.loader import Domain, Registry

from ._pilot import pilot_registry


@pytest.fixture(scope="session")
def pilot() -> Registry:
    """The shipped pilot domains (groups, network-zones), as the server loads them. The tests
    that use it assert on exactly what those domains and `fixtures/pilot.yaml` hold."""
    return pilot_registry()


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
