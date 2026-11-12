"""The authenticated caller (design §8.5)."""

from dataclasses import dataclass
from typing import Self, cast

from mcp.server.auth.provider import AccessToken
from pydantic import ConfigDict, model_validator


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

    def __post_init__(self) -> None:
        # A claim arrives as a JSON array, or a bare string for one group. Neither may reach
        # the policy engine as is: a string is a set of characters to `&`.
        groups = cast(object, self.groups)
        if not isinstance(groups, frozenset) or not all(
            isinstance(g, str) for g in cast(frozenset[object], groups)
        ):
            raise TypeError("Principal.groups must be a frozenset of strings")


class VerifiedToken(AccessToken):
    """What the HTTP token verifier (4.3) returns: the SDK's `AccessToken`, which its auth
    middleware checks and puts in the request context, plus the `Principal` built from the
    same token. The HTTP app reads only `principal`; any other `AccessToken` in the context is
    refused (`okta_mcp.app.http_principal`)."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    principal: Principal

    @model_validator(mode="after")
    def _same_caller(self) -> Self:
        # The SDK keys its own per-caller state on (client_id, iss, subject); they must name
        # the same caller as `principal`, or two users of one client would look alike to it.
        p = self.principal
        if self.subject != p.uid or (p.client_id is not None and self.client_id != p.client_id):
            raise ValueError("VerifiedToken subject and client_id must match its principal")
        return self
