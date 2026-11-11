"""The authenticated caller (design §8.5)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """Built by the token verifier (4.3) or, over stdio, from the dev principal file (4.1)."""

    uid: str
    """Okta user ID (`00u…`), the stable identity; audit, limiter and cursors key on it."""
    sub: str
    """Login. Mutable, so for display only."""
    groups: frozenset[str]
    """Okta group IDs from the groups claim. The policy maps them to roles."""
    client_id: str | None = None
    exp: int | None = None
    """Token expiry, seconds since the epoch. Dev mode has neither."""
