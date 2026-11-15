"""Composite command handlers (design §5.6): registry `handler:` name → coroutine.

A handler reaches Okta only through its `exec.composite.Context`, which allows the operations its
registry entry `uses`. The executor checks at startup that every handler command has an entry
here.
"""

from collections.abc import Mapping
from types import MappingProxyType

from okta_mcp.exec.composite import Handler
from okta_mcp.handlers import login_failures

HANDLERS: Mapping[str, Handler] = MappingProxyType({"login-failures": login_failures.run})
