"""What a handler command (design §5.6) may do: the one way its code reaches Okta.

A handler gets a `Context` bound to its registry command. Every request goes through the same
GET-only `OktaClient`, URL builder (§6.4 path rule, reserved segments) and paginator (next links
kept on the operation's path) as a simple command's, and names an operation the command's
`uses` lists; any other is a bug and raises `RuntimeError`, so the registry entry is the
reviewable list of what a composite can read. An optional operation the service app lacks the
scopes for raises `Unavailable`, which the handler reports as skipped instead of failing the call
(`available` asks first). The caller's policy check has already passed before a handler runs.

The paging token (`after`) is the paginator's; a handler can't set it.
"""

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from okta_mcp.exec.params import build_url, path_segment
from okta_mcp.exec.resolve import UserResolver
from okta_mcp.okta.client import OktaClient, UpstreamError, json_body
from okta_mcp.okta.paginate import Mode, paginate
from okta_mcp.policy.engine import Engine
from okta_mcp.registry.loader import Command
from okta_mcp.registry.spec import Operation

_SERVER_PARAMS = frozenset({"after"})


class Unavailable(Exception):
    """The service app holds none of the operation's scope sets. The message names the
    operation and its scopes, which a handler may report (they are in the public spec)."""


class Context:
    """One per handler call."""

    def __init__(
        self,
        *,
        command: Command,
        client: OktaClient,
        engine: Engine,
        resolver: UserResolver,
        org_url: str,
    ) -> None:
        if command.handler is None:
            raise RuntimeError("a Context is for handler commands")
        self._command = command
        self._client = client
        self._engine = engine
        self._resolver = resolver
        self._org_url = org_url

    def available(self, operation_id: str) -> bool:
        """The command may call it and the service app holds its scopes."""
        return self._engine.runs(self._declared(operation_id))

    def needs(self, operation_id: str) -> str:
        """What the service app would need to call it: its scope sets, any one of them."""
        op = self._declared(operation_id)
        return " or ".join(sorted(" + ".join(sorted(s)) for s in op.scope_sets))

    async def user(self, arg: str, value: object) -> dict[str, Any]:
        """The user `value` (an ID or exact login, the caller's arg `arg`) names: the
        resolver's lookup, so its rules and its `not_found` apply."""
        self._operation("getUser")
        return await self._resolver.user(arg, value)

    async def get(
        self,
        operation_id: str,
        path: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> Any:
        """One resource's JSON body. Raises `Unavailable`, `InvalidArguments` (a path value the
        §6.4 rule refuses) and what `OktaClient.get` raises."""
        op = self._operation(operation_id)
        response = await self._client.get(self._url(op, path), self._params(op, params))
        body = json_body(response)
        if body is None:
            raise UpstreamError(response.status_code, "Okta's response is not JSON")
        return body

    async def items(
        self,
        operation_id: str,
        path: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        *,
        mode: Mode,
        max_items: int,
        items_key: str | None = None,
    ) -> tuple[list[Any], bool]:
        """A list's first `max_items` items, following next links per `mode`. Returns them and
        whether Okta had more (no page past the one holding item `max_items` + 1 is fetched)."""
        op = self._operation(operation_id)
        out: list[Any] = []
        pages = paginate(
            self._client,
            self._url(op, path),
            self._params(op, params),
            mode=mode,
            items_key=items_key,
        )
        try:
            async for item, _, _ in pages:
                if len(out) == max_items:
                    return out, True
                out.append(item)
        finally:
            await pages.aclose()
        return out, False

    def _declared(self, operation_id: str) -> Operation:
        op = self._command.uses.get(operation_id)
        if op is None:
            raise RuntimeError(f"{operation_id} is not in the command's uses")
        return op

    def _operation(self, operation_id: str) -> Operation:
        op = self._declared(operation_id)
        if not self._engine.runs(op):
            raise Unavailable(f"{operation_id} needs {self.needs(operation_id)}")
        return op

    def _url(self, op: Operation, path: Mapping[str, str] | None) -> str:
        segments = {
            name: path_segment(name, value, op.reserved.get(name, frozenset()))
            for name, value in (path or {}).items()
        }
        return build_url(self._org_url, op.path, segments)

    def _params(self, op: Operation, params: Mapping[str, str] | None) -> dict[str, str]:
        out = dict(params or {})
        for name in out:
            param = op.params.get(name)
            if param is None or param.location != "query" or name in _SERVER_PARAMS:
                raise RuntimeError(f"{op.operation_id} takes no query param {name}")
        return out


Handler = Callable[[Context, Mapping[str, Any]], Awaitable[dict[str, Any]]]
"""A handler: the call's validated args in, the result (scrubbed and size-checked by the
executor) out."""
