"""The `user_id` resolver (design §5.6): a user arg given as a login becomes the user's ID.

It runs only after the policy check has allowed the call, so it can't tell a caller whether a
login exists on a command they may not use. A value shaped like a user ID is used as is. Anything
else is looked up with `getUser`, which Okta also answers for a login shortname, so the user it
returns must have exactly that login (Okta compares logins case-insensitively); otherwise, or on
a 404, the user is not found. The value goes into the lookup's path through the same §6.4 rule as
any path value, which refuses `me` before any request (`/api/v1/users/me` is the token's own user;
it is in `getUser`'s `Operation.reserved`).
"""

import re
from collections.abc import Mapping
from typing import Any, cast

from okta_mcp.exec.params import build_url, path_segment
from okta_mcp.okta.client import OktaClient, UpstreamError, json_body
from okta_mcp.registry.loader import Command
from okta_mcp.registry.schema import InvalidArguments
from okta_mcp.registry.spec import Operation

USER_ID = re.compile(r"00u[A-Za-z0-9]{17}")
"""Matched with `fullmatch`, so a trailing newline doesn't pass."""
_LOOKUP_PARAM = "id"
NOT_FOUND = "no user has that ID or exact login"


class NotFound(Exception):
    """No user with that ID or exact login. The message is safe to return (`not_found`); it
    never holds the value."""


class UserResolver:
    """Built once at startup with `getUser` from the spec index. `resolve` takes a per-call
    cache, so a call names each user once, however many args name it."""

    def __init__(self, client: OktaClient, org_url: str, get_user: Operation) -> None:
        if get_user.operation_id != "getUser" or _LOOKUP_PARAM not in get_user.params:
            raise ValueError("the resolver needs the spec's getUser operation")
        if "me" not in get_user.reserved.get(_LOOKUP_PARAM, frozenset()):
            # The path rule is the only thing between `me` and the token's own user.
            raise ValueError("getUser's reserved set must hold me (registry.spec.ROUTED_ALIASES)")
        self._client = client
        self._org_url = org_url
        self._get_user = get_user

    async def resolve(
        self, command: Command, args: Mapping[str, Any], cache: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """`args` with every `resolve: user_id` arg replaced by the user's ID. `args` must have
        passed validation and the policy check. Raises `NotFound`, `InvalidArguments` (`me`,
        or a value the lookup path refuses) and what `OktaClient.get` raises."""
        cache = {} if cache is None else cache
        out = dict(args)
        for name, arg in command.entry.args.items():
            if arg.resolve == "user_id" and name in out:
                out[name] = await self.user_id(name, out[name], cache)
        return out

    async def user_id(self, arg: str, value: object, cache: dict[str, str]) -> str:
        """The ID of the user `value` names (an ID, or an exact login)."""
        if not isinstance(value, str):
            raise InvalidArguments(f"arg {arg!r} must be a string")
        if USER_ID.fullmatch(value):
            return value
        if value in cache:
            return cache[value]
        reserved = self._get_user.reserved.get(_LOOKUP_PARAM, frozenset())
        segment = path_segment(arg, value, reserved)
        url = build_url(self._org_url, self._get_user.path, {_LOOKUP_PARAM: segment})
        found: str | None = None
        try:
            response = await self._client.get(url)
        except UpstreamError as e:
            if e.status != 404:
                raise
        else:
            found = _user_id_of(json_body(response), value)
        if found is None:
            raise NotFound(NOT_FOUND)
        cache[value] = found
        return found


def _user_id_of(body: object, login: str) -> str | None:
    """The user's ID if `body` is a user whose login is `login`, else None."""
    if not isinstance(body, dict):
        return None
    user = cast(dict[str, Any], body)
    profile = user.get("profile")
    found_login = cast(dict[str, Any], profile).get("login") if isinstance(profile, dict) else None
    user_id = user.get("id")
    if (
        isinstance(found_login, str)
        # `lower`, not `casefold` as the refusals use: this test accepts, so the narrower
        # comparison is the safe one (`casefold` would match `STRASSE` to `straße`).
        and found_login.lower() == login.lower()
        and isinstance(user_id, str)
        and USER_ID.fullmatch(user_id)
    ):
        return user_id
    return None
