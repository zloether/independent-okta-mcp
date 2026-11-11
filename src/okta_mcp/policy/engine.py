"""Policy decisions (design §9.1, §9.4): what a principal may list and call.

The loader has already expanded every pattern (`Role.allow`, `allow_raised`, `deny`), so this
module only does set arithmetic on those. It never matches a pattern itself; a second
implementation of the wildcard-vs-sensitive rule could disagree with the loader's.
"""

import enum
from collections.abc import Mapping
from dataclasses import dataclass

from okta_mcp.auth.principal import Principal
from okta_mcp.policy.model import Grant, Policy
from okta_mcp.registry.loader import Command, Registry


class Verdict(enum.Enum):
    ALLOWED = "allowed"
    FORBIDDEN = "forbidden_by_policy"
    """The caller's roles don't permit the call. Says nothing about why (§5.5)."""
    UNAVAILABLE = "unavailable"
    """Permitted, but the service app holds none of the command's scope sets."""


@dataclass(frozen=True)
class _Effective:
    """Union of `allow` minus union of `deny`, over one set of roles."""

    permitted: frozenset[Grant]
    raised: frozenset[Grant]
    """⊆ `permitted`: also callable with an argument that raises the call to sensitive."""


_NOTHING = _Effective(frozenset(), frozenset())


class Engine:
    """One per process, built at startup. Roles come from the principal's groups on every
    call; nothing about a principal is kept."""

    def __init__(self, policy: Policy, registry: Registry, okta_scopes: frozenset[str]) -> None:
        self._policy = policy
        self._commands: Mapping[Grant, Command] = {
            (d.name, c.name): c for d in registry.domains.values() for c in d.commands.values()
        }
        # Capability gate (§9.4 item 3). Plain subset: `OKTA_SCOPES` holds `.read` scopes only
        # (config), so there is no `.manage` to imply anything, and a command whose operation
        # accepts only a `.manage` scope is unavailable. No scope sets → unavailable.
        self.unavailable: frozenset[Grant] = frozenset(
            grant
            for grant, command in self._commands.items()
            if not any(scopes <= okta_scopes for scopes in command.scope_sets)
        )
        """Commands the service app can't run, whoever asks."""
        self._by_roles: dict[frozenset[str], _Effective] = {}

    def roles(self, principal: Principal) -> frozenset[str]:
        """Names of the roles the principal holds: those naming any of its groups."""
        return frozenset(
            role.name for role in self._policy.roles.values() if role.groups & principal.groups
        )

    def permitted(self, principal: Principal) -> frozenset[Grant]:
        """Commands the principal's roles allow. Includes `unavailable` ones, so `okta_help`
        can say why a permitted command won't run; `tools/list` leaves those out."""
        return self._effective(principal).permitted

    def check(
        self, principal: Principal, domain: str, command: str, args: Mapping[str, object]
    ) -> Verdict:
        """Decision for one call. `args` are the caller's arguments, validated against the
        command's schema; only their names are read. An argument counts as passed if its
        key is present, whatever its value."""
        grant = (domain, command)
        effective = self._effective(principal)
        entry = self._commands.get(grant)
        # An unknown command is forbidden, not an error: the answer must not depend on
        # whether a name the caller can't use exists.
        if entry is None or grant not in effective.permitted:
            return Verdict.FORBIDDEN
        for name in args:
            arg = entry.entry.args.get(name)
            if arg is None:
                # Schema validation rejects unknown names first; an argument with no known
                # rule is not let through if that ever stops being true.
                return Verdict.FORBIDDEN
            rule = arg.arg_rule
            if rule is None or rule.reviewed is not None:
                continue
            if rule.raises_sensitivity_to is None or grant not in effective.raised:
                # `forbidden`, a raise the roles don't cover, or a rule form added later
                # that this loop doesn't know.
                return Verdict.FORBIDDEN
        # After the policy checks, so a caller without the grant learns nothing about the
        # service app's scopes.
        if grant in self.unavailable:
            return Verdict.UNAVAILABLE
        return Verdict.ALLOWED

    def _effective(self, principal: Principal) -> _Effective:
        names = self.roles(principal)
        if not names:
            return _NOTHING
        cached = self._by_roles.get(names)
        if cached is None:
            roles = [self._policy.roles[n] for n in names]
            deny = frozenset[Grant]().union(*(r.deny for r in roles))
            cached = _Effective(
                permitted=frozenset[Grant]().union(*(r.allow for r in roles)) - deny,
                raised=frozenset[Grant]().union(*(r.allow_raised for r in roles)) - deny,
            )
            # At most one entry per distinct set of roles, and roles come from the policy
            # file, so this can't grow with the number of callers.
            self._by_roles[names] = cached
        return cached
