"""Load the policy file and check it against the registry (design §9.3).

Every error is collected and reported at once; any error fails the load, so the server doesn't
start on a policy that is only partly understood. Patterns are expanded here, once, against
the registry the server runs with: a command added to the registry later is granted by an
existing wildcard only if it is `normal`, or its domain is in the role's `include_sensitive`.
"""

from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml
from pydantic import ValidationError

from okta_mcp.policy.model import WILDCARD, Grant, Patterns, Policy, PolicyFile, Role, RoleEntry
from okta_mcp.registry.loader import Registry, UniqueKeyLoader

_EVERYWHERE = frozenset({WILDCARD})


class PolicyError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


def load_policy(path: Path, registry: Registry) -> Policy:
    """Raises `PolicyError` on a missing, unreadable or invalid file."""
    try:
        doc = yaml.load(path.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError([f"{path.name}: {e}"]) from e
    try:
        return build_policy(doc, registry)
    except PolicyError as e:
        raise PolicyError([f"{path.name}: {m}" for m in e.errors]) from e


def build_policy(doc: Any, registry: Registry) -> Policy:
    """`doc` is the parsed YAML."""
    try:
        parsed = PolicyFile.model_validate(doc)
    except ValidationError as e:
        raise PolicyError(
            [f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()]
        ) from e

    errors: list[str] = []
    for name, entry in parsed.roles.items():
        where = f"roles.{name}"
        errors.extend(_unknown(f"{where}.allow", entry.allow, registry))
        errors.extend(_unknown(f"{where}.deny", entry.deny, registry))
        errors.extend(
            f"{where}.include_sensitive: unknown domain {d!r}"
            for d in entry.include_sensitive
            if d != WILDCARD and d not in registry.domains
        )
    if errors:
        raise PolicyError(errors)

    roles: dict[str, Role] = {}
    for name, entry in parsed.roles.items():
        allow, allow_raised = _allowed(entry, frozenset(entry.include_sensitive), registry)
        roles[name] = Role(
            name=name,
            groups=frozenset(entry.groups),
            allow=allow,
            allow_raised=allow_raised,
            deny=_expand(entry.deny, registry, _EVERYWHERE),
        )
    return Policy(MappingProxyType(roles), tuple(_warnings(parsed, roles, registry)))


def _unknown(where: str, patterns: Patterns, registry: Registry) -> list[str]:
    errors: list[str] = []
    for domain, commands in patterns.items():
        if domain == WILDCARD:
            continue
        if domain not in registry.domains:
            errors.append(f"{where}: unknown domain {domain!r}")
            continue
        known = registry.domains[domain].commands
        errors.extend(
            f"{where}.{domain}: unknown command {c!r}"
            for c in commands
            if c != WILDCARD and c not in known
        )
    return errors


def _expand(
    patterns: Patterns, registry: Registry, sensitive: frozenset[str], *, plain: bool = True
) -> frozenset[Grant]:
    """A wildcard matches a sensitive command only in the domains in `sensitive` (`*`: all);
    a command named outright is matched whatever its sensitivity. With `plain` false, a
    wildcard matches nothing outside those domains (`Role.allow_raised`)."""
    grants: set[Grant] = set()
    for domain, commands in patterns.items():
        for pattern in commands:
            if pattern != WILDCARD:
                grants.add((domain, pattern))
                continue
            domains = (
                registry.domains.values() if domain == WILDCARD else [registry.domains[domain]]
            )
            grants.update(
                (d.name, c.name)
                for d in domains
                for c in d.commands.values()
                if (plain and c.sensitivity == "normal")
                or WILDCARD in sensitive
                or d.name in sensitive
            )
    return frozenset(grants)


def _allowed(
    entry: RoleEntry, include: frozenset[str], registry: Registry
) -> tuple[frozenset[Grant], frozenset[Grant]]:
    """(`Role.allow`, `Role.allow_raised`) for the role with `include` as its
    `include_sensitive`."""
    return (
        _expand(entry.allow, registry, include),
        _expand(entry.allow, registry, include, plain=False),
    )


def _warnings(parsed: PolicyFile, roles: dict[str, Role], registry: Registry) -> list[str]:
    warnings: list[str] = []
    allowed_by_any = frozenset[Grant]().union(*(r.allow for r in roles.values()))
    for name, entry in parsed.roles.items():
        where = f"roles.{name}"
        role = roles[name]
        include = frozenset(entry.include_sensitive)
        if WILDCARD in include:
            warnings.append(
                f'{where}.include_sensitive: "*" lets this role\'s wildcards match sensitive '
                "commands in every domain"
            )
        warnings.extend(
            f"{where}.include_sensitive: {d!r} has no effect (no wildcard in this role's allow "
            "reaches a command there that isn't granted in full already)"
            for d in entry.include_sensitive
            if _allowed(entry, include - {d}, registry) == (role.allow, role.allow_raised)
        )
        for domain, commands in entry.allow.items():
            if WILDCARD in commands and not _expand({domain: (WILDCARD,)}, registry, include):
                warnings.append(
                    f'{where}.allow.{domain}: "*" grants nothing (every command there is '
                    "sensitive; name them, or add the domain to include_sensitive)"
                )
        for domain, commands in entry.deny.items():
            warnings.extend(
                f"{where}.deny.{domain}: {c!r} matches nothing any role allows"
                for c in commands
                if not _expand({domain: (c,)}, registry, _EVERYWHERE) & allowed_by_any
            )
        if not role.allow - role.deny:
            warnings.append(f"{where}: grants nothing (its deny covers all of its allow)")
    return warnings
