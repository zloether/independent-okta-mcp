"""What the pilot registry and `fixtures/pilot.yaml` hold, for the tests that assert on it."""

import functools
from pathlib import Path
from types import MappingProxyType

from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import load_spec

PILOT = Path(__file__).parent / "fixtures" / "pilot.yaml"
READERS, HELPDESK = "00g1readers000000000", "00g1helpdsk000000000"
ANALYSTS, ADMINS = "00g1secanalyst000000", "00g1abc2defGHI3jkL45"
GROUPS_NORMAL = {"list", "get", "get-members", "get-apps", "get-owners", "list-rules", "get-rule"}
GROUPS_SENSITIVE = {"list-roles", "get-role", "list-role-app-targets", "list-role-group-targets"}
ZONES = {("network-zones", "list"), ("network-zones", "get")}

PILOT_DOMAINS = ("groups", "network-zones")


@functools.cache
def pilot_registry() -> Registry:
    """The shipped registry cut to the pilot domains (cached: the spec takes ~1 s to load)."""
    shipped = load_registry(load_spec())
    return Registry(MappingProxyType({d: shipped.domains[d] for d in PILOT_DOMAINS}))
