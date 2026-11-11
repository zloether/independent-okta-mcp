"""Policy decisions (design §9.1, §9.4): what a principal may list and call.

The loader has already expanded every pattern (`Role.allow`, `allow_raised`, `deny`), so this
module only does set arithmetic on those. It never matches a pattern itself; a second
implementation of the wildcard-vs-sensitive rule could disagree with the loader's.
"""

import enum
from collections.abc import Mapping
from dataclasses import dataclass

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.output import ScrubRules
from okta_mcp.policy.expression import ExpressionError, attribute, attributes, scrubbed
from okta_mcp.policy.model import WILDCARD, Grant, Policy
from okta_mcp.registry.loader import Command, Registry


class Verdict(enum.Enum):
    ALLOWED = "allowed"
    FORBIDDEN = "forbidden_by_policy"
    """The caller's roles don't permit the call. Says nothing about why (§5.5)."""
    UNAVAILABLE = "unavailable"
    """Permitted, but the service app holds none of the command's scope sets."""
    INVALID = "invalid_arguments"
    """Permitted, but a search, filter or sort expression isn't one the engine can read, so
    it can't tell which attributes the call touches."""


@dataclass(frozen=True)
class _Effective:
    """Union of `allow` minus union of `deny`, over one set of roles."""

    permitted: frozenset[Grant]
    raised: frozenset[Grant]
    """⊆ `permitted`: also callable with an argument that raises the call to sensitive."""
    search: Mapping[Grant, frozenset[str]]
    """Per permitted command, the `search_attributes` of the roles that allow that command.
    A role's attributes don't carry over to commands only another role allows."""


_NOTHING = _Effective(frozenset(), frozenset(), {})


class Engine:
    """One per process, built at startup. Roles come from the principal's groups on every
    call; nothing about a principal is kept."""

    def __init__(self, policy: Policy, registry: Registry, okta_scopes: frozenset[str]) -> None:
        self._policy = policy
        roles_by_group: dict[str, set[str]] = {}
        for role in policy.roles.values():
            for group in role.groups:
                roles_by_group.setdefault(group, set()).add(role.name)
        self._roles_by_group = {g: frozenset(names) for g, names in roles_by_group.items()}
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

    @property
    def scrub(self) -> ScrubRules:
        """The rules the policy was checked against (`Policy.scrub`). The executor scrubs
        results with these, so load-time checks, call-time checks and output agree."""
        return self._policy.scrub

    def roles(self, principal: Principal) -> frozenset[str]:
        """Names of the roles the principal holds: those naming any of its groups."""
        return frozenset[str]().union(
            *(self._roles_by_group.get(group, ()) for group in principal.groups)
        )

    def permitted(self, principal: Principal) -> frozenset[Grant]:
        """Commands the principal's roles allow. Includes `unavailable` ones, so `okta_help`
        can say why a permitted command won't run; `tools/list` leaves those out."""
        return self._effective(principal).permitted

    def search_attributes(self, principal: Principal, domain: str, command: str) -> frozenset[str]:
        """Attributes the principal may name in an expression on this command (`{"*"}`: any
        that results don't redact). Empty if the command isn't permitted. For help text."""
        return self._effective(principal).search.get((domain, command), frozenset())

    def check(
        self, principal: Principal, domain: str, command: str, args: Mapping[str, object]
    ) -> Verdict:
        """Decision for one call. An argument counts as passed if its key is present,
        whatever its value.

        Values are read only for `attribute_expression` arguments. Every other value
        (`allowed_values`, `pattern`) is the schema's to check, so `args` must already have
        passed `command.validator`; this is not a substitute for it."""
        grant = (domain, command)
        effective = self._effective(principal)
        entry = self._commands.get(grant)
        # An unknown command is forbidden, not an error: the answer must not depend on
        # whether a name the caller can't use exists.
        if entry is None or grant not in effective.permitted:
            return Verdict.FORBIDDEN
        invalid = False
        for name, value in args.items():
            arg = entry.entry.args.get(name)
            if arg is None or arg.allowed_values == ():
                # Unknown, or not exposed (`allowed_values: []`). Schema validation rejects
                # both first; neither is let through if that ever stops being true.
                return Verdict.FORBIDDEN
            rule = arg.arg_rule
            if rule is None or rule.reviewed is not None:
                continue
            if rule.attribute_expression:
                allowed = effective.search.get(grant, frozenset())
                if not allowed:
                    # No expression of any kind for this caller, well-formed or not.
                    return Verdict.FORBIDDEN
                try:
                    if not isinstance(value, str):
                        raise ExpressionError("not a string")
                    # `sortBy` takes one property, not an expression.
                    named = (attribute(value),) if arg.query == "sortBy" else attributes(value)
                except ExpressionError:
                    # Refused either way; a policy refusal on another argument comes first.
                    invalid = True
                    continue
                # The redaction test comes first and has no exception: `*` doesn't lift it.
                if any(scrubbed(a, self._policy.scrub) for a in named) or not (
                    WILDCARD in allowed or allowed.issuperset(named)
                ):
                    return Verdict.FORBIDDEN
                continue
            if rule.raises_sensitivity_to is None or grant not in effective.raised:
                # `forbidden`, a raise the roles don't cover, or a rule form added later
                # that this loop doesn't know.
                return Verdict.FORBIDDEN
        if invalid:
            return Verdict.INVALID
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
            permitted = frozenset[Grant]().union(*(r.allow for r in roles)) - deny
            search: dict[Grant, frozenset[str]] = {}
            for role in roles:
                if role.search_attributes:
                    for grant in role.allow & permitted:
                        search[grant] = search.get(grant, frozenset()) | role.search_attributes
            cached = _Effective(
                permitted=permitted,
                raised=frozenset[Grant]().union(*(r.allow_raised for r in roles)) - deny,
                search=search,
            )
            # At most one entry per distinct set of roles, and roles come from the policy
            # file, so this can't grow with the number of callers.
            self._by_roles[names] = cached
        return cached
