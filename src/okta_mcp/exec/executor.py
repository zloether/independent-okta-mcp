"""One tool call, from the caller's request to the response text (design §5.5, §5.6, §7).

The order of the steps is a security property:

1. The command must be in `Engine.permitted(principal)`, else `forbidden_by_policy`. This comes
   before anything reads the args, so a command the caller can't use doesn't name its args in
   an `invalid_arguments` message.
2. The args are validated: the command's schema and the §6.4 path rule (`params.check_args`),
   then `select`, `links`, `limit` and `cursor`. The policy engine reads arg names, and the
   value of an expression arg, so it must not see args the schema hasn't passed.
3. With a cursor: the cursor must fit a resumable list call, and `Cursors.open` checks it is
   this caller's, for this command and these args.
4. `Engine.check` on the validated args. Only `ALLOWED` goes on; every other verdict, including
   one this module doesn't know, is a refusal.
5. Then, and only then, Okta: the `user_id` resolver (first calls only: a cursor holds resolved
   path params), then the request, under the call's deadline. A refused call sends nothing, so
   the resolver can't tell a caller whether a login exists.

Every failure becomes a `Failure` with a §5.5 code and a message safe to return. Anything
unexpected is `internal_error`, with the exception's type and frames, never its message, in the
server log.
"""

import enum
import json
import logging
from collections.abc import AsyncGenerator, Mapping
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import quote

import anyio
import httpx2

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.cursor import (
    NOT_VALID,
    RESUMED_WARNING,
    CursorError,
    Cursors,
    Resume,
    after,
    path_params,
    resumable,
    resume_url,
)
from okta_mcp.exec.envelope import (
    DEADLINE_HEADROOM,
    UNPAGED_WARNING,
    ResultTooLarge,
    item_result,
    list_budget,
    list_result,
)
from okta_mcp.exec.output import columns
from okta_mcp.exec.params import build_request, check_args
from okta_mcp.exec.resolve import NotFound, UserResolver
from okta_mcp.logs import log_internal
from okta_mcp.okta import ratelimit
from okta_mcp.okta.client import OktaClient, UpstreamError, json_body
from okta_mcp.okta.paginate import Mode, PaginationError, paginate
from okta_mcp.okta.ratelimit import RateLimited
from okta_mcp.policy.engine import Engine, Verdict
from okta_mcp.registry.loader import Command, Registry
from okta_mcp.registry.schema import InvalidArguments

log = logging.getLogger(__name__)

FORBIDDEN = "the command or an argument is not permitted by policy"
"""The one sentence for `forbidden_by_policy` (§5.5): no role names, no other commands."""
UNAVAILABLE = "the server's Okta service app can't run this command; contact the MCP administrator"
INTERNAL = "internal error; the server log has the details"
TOO_LONG = "the args make the request too long; shorten them"
EXPRESSION = (
    "a search, filter or sort expression can't be read: use attribute names in dotted segments, "
    "the operators eq ne gt ge lt le sw co ew pr and or not, true false null, numbers, "
    "parentheses, single spaces and double-quoted values without backslashes; a sort takes one "
    "attribute name"
)
CURSOR_MAX = 90_000
"""Longest cursor read, in characters. A cursor holds one page's query string, which httpx2's
64 KiB URL limit bounds, base64-encoded (x 4/3) with a small header; anything longer can't be
one of ours, and is refused before the tag is computed over it."""
_ATTRIBUTES_SHOWN = 20
_LOGGED_NAME = 64
"""Characters of a caller-sent domain or command name a log line may carry."""


class Code(enum.StrEnum):
    """The error codes of design §5.5."""

    INVALID_ARGUMENTS = "invalid_arguments"
    FORBIDDEN_BY_POLICY = "forbidden_by_policy"
    UNAVAILABLE = "unavailable"
    NOT_FOUND = "not_found"
    UPSTREAM_ERROR = "upstream_error"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    RESULT_TOO_LARGE = "result_too_large"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class Success:
    text: str
    """The response envelope (§7.1): one compact JSON text."""


@dataclass(frozen=True)
class Failure:
    code: Code
    message: str
    """Safe to return to the caller."""

    def text(self, request_id: str) -> str:
        """The error envelope (§5.5, T1 §3.4). `request_id` comes from the server (4.1)."""
        error = {"code": self.code.value, "message": self.message, "request_id": request_id}
        return json.dumps({"error": error}, separators=(",", ":"))


Outcome = Success | Failure


@dataclass(frozen=True)
class Call:
    """One `tools/call`. `domain` is the registry domain the tool serves (`tool_name`). The
    other fields are as the client sent them, so the executor checks their types."""

    principal: Principal
    domain: str
    command: str
    args: object = field(default_factory=dict[str, Any])
    select: object = None
    links: object = False
    limit: object = None
    cursor: object = None


def expression_args(command: Command) -> list[str]:
    """The command's `attribute_expression` args, the ones `search_attributes` govern."""
    return [
        name
        for name, arg in command.entry.args.items()
        if arg.arg_rule is not None and arg.arg_rule.attribute_expression
    ]


def searchable(engine: Engine, principal: Principal, command: Command) -> str:
    """What the principal's roles let them name in an expression on this command (§5.5). Also
    `okta_help`'s line for a command with expression args. Only those args are role-checked:
    a `reviewed` filter is not, so the message names the args it is about."""
    names = engine.search_attributes(principal, command.domain, command.name)
    # A registry closed set (`arg_rule.attributes`) narrows every role's list, `*` included.
    # Only when every expression arg has one, so nothing is hidden that an arg would take.
    # Shown in registry order, which puts the most useful first.
    rules = [command.entry.args[a].arg_rule for a in expression_args(command)]
    closed = (
        list(dict.fromkeys(a for r in rules if r is not None for a in r.attributes or ()))
        if rules and all(r is not None and r.attributes is not None for r in rules)
        else None
    )
    if closed is not None and names:
        shown = [a for a in closed if "*" in names or a in names]
    elif "*" in names:
        return "expressions may name any attribute that results don't redact"
    else:
        shown = sorted(names)
    if not shown:
        args = " or ".join(expression_args(command)) or "an expression"
        return f"your roles allow no {args} on this command"
    more = len(shown) - _ATTRIBUTES_SHOWN
    listed = ", ".join(shown[:_ATTRIBUTES_SHOWN]) + (f" (+{more})" if more > 0 else "")
    return f"expressions may name only: {listed}"


def tool_name(domain: str) -> str:
    """The MCP tool for a registry domain (§5.1): `network-zones` → `okta_network_zones`.
    Domain names are kebab-case, so this is one-to-one. Cursors are bound to it."""
    return "okta_" + domain.replace("-", "_")


@dataclass(frozen=True)
class _Options:
    args: dict[str, Any]
    cols: tuple[str, ...] | None
    links: bool
    limit: int
    resume: Resume | None


def _logged(name: object) -> str:
    return repr(name[:_LOGGED_NAME]) if isinstance(name, str) else type(name).__name__


async def _replay(items: list[tuple[Any, str, int]]) -> AsyncGenerator[tuple[Any, str, int]]:
    for item in items:
        yield item


class Executor:
    """One per process, built at startup. Results are scrubbed with `Engine.scrub`, the rules
    the policy was checked against. Raises `ValueError` for a configuration no call could
    work under: a `call_timeout` a list can't fit in, or no `resolver` while a command has a
    `resolve` arg."""

    def __init__(
        self,
        *,
        registry: Registry,
        engine: Engine,
        client: OktaClient,
        cursors: Cursors,
        resolver: UserResolver | None,
        org_url: str,
        default_limit: int,
        max_items: int,
        max_bytes: int,
        call_timeout: float,
    ) -> None:
        if not 0 < default_limit <= max_items:
            raise ValueError("default_limit must be from 1 to max_items")
        if call_timeout < 2 * DEADLINE_HEADROOM:
            # A resumable list stops DEADLINE_HEADROOM before the deadline; with less than
            # that again left to read in, every list would time out or come back cut.
            raise ValueError(f"call_timeout must be at least {2 * DEADLINE_HEADROOM:g} s")
        if resolver is None and any(
            arg.resolve is not None
            for domain in registry.domains.values()
            for command in domain.commands.values()
            for arg in command.entry.args.values()
        ):
            raise ValueError("a command resolves users, so the executor needs a resolver")
        self._registry = registry
        self._engine = engine
        self._client = client
        self._cursors = cursors
        self._resolver = resolver
        self._org_url = org_url
        self._default_limit = default_limit
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._call_timeout = call_timeout

    async def execute(self, call: Call) -> Outcome:
        """The response for `call`. Never raises, except for cancellation by the caller."""
        token = ratelimit.principal.set(call.principal.uid)
        try:
            return await self._execute(call)
        except (InvalidArguments, CursorError) as e:
            return Failure(Code.INVALID_ARGUMENTS, str(e))
        except httpx2.InvalidURL as e:
            # Raised by the client before anything is sent, for a URL its args make too long
            # (combined or non-ASCII args can pass the per-arg bound). Logged by type only, so
            # a path-rule regression relabelled as the caller's error still leaves a trace.
            log.debug("request URL refused by the HTTP client: %s", type(e).__name__)
            return Failure(Code.INVALID_ARGUMENTS, TOO_LONG)
        except NotFound as e:
            return Failure(Code.NOT_FOUND, str(e))
        except (UpstreamError, PaginationError) as e:
            return Failure(Code.UPSTREAM_ERROR, str(e))
        except RateLimited as e:
            return Failure(Code.RATE_LIMITED, str(e))
        except ResultTooLarge as e:
            return Failure(Code.RESULT_TOO_LARGE, str(e))
        except TimeoutError:
            return Failure(Code.TIMEOUT, f"the call took longer than {self._call_timeout:g} s")
        except Exception as e:
            # `OriginError`, `RuntimeError` (a DPoP token without a key, a URL off its
            # template, no principal for the limiter) and anything else. The message may hold
            # data, so only the type and the frames are logged.
            log_internal(log, f"{_logged(call.domain)} {_logged(call.command)}", e)
            return Failure(Code.INTERNAL_ERROR, INTERNAL)
        finally:
            ratelimit.principal.reset(token)

    async def _execute(self, call: Call) -> Outcome:
        principal = call.principal
        # Typed `str`, but from the client: refused as an unknown command is, before anything
        # uses them as names.
        if not isinstance(cast(object, call.domain), str) or not isinstance(
            cast(object, call.command), str
        ):
            return Failure(Code.FORBIDDEN_BY_POLICY, FORBIDDEN)
        if not principal.uid:
            # A cursor binds the uid and the limiter keys on it: an empty one would be shared.
            raise RuntimeError("principal without a uid")
        # 1. Permitted at all, before the args are read.
        if (call.domain, call.command) not in self._engine.permitted(principal):
            return Failure(Code.FORBIDDEN_BY_POLICY, FORBIDDEN)
        command = self._registry.domains[call.domain].commands[call.command]
        # 2 and 3. Validate everything the caller sent; open the cursor.
        options = self._options(call, command)
        # 4. The policy decision on those args; only ALLOWED goes on.
        verdict = self._engine.check(principal, call.domain, call.command, options.args)
        match verdict:
            case Verdict.ALLOWED:
                pass
            case Verdict.FORBIDDEN:
                return Failure(Code.FORBIDDEN_BY_POLICY, self._forbidden(call, command, options))
            case Verdict.INVALID:
                return Failure(Code.INVALID_ARGUMENTS, self._unreadable(call, command))
            case Verdict.UNAVAILABLE:
                return Failure(Code.UNAVAILABLE, UNAVAILABLE)
            case _:  # pyright: ignore[reportUnnecessaryComparison]
                raise RuntimeError("unknown policy verdict")
        # 5. Okta, under the call's deadline.
        with anyio.fail_after(self._call_timeout):
            if command.is_list:
                return Success(await self._list(call, command, options))
            return Success(await self._item(command, options))

    def _options(self, call: Call, command: Command) -> _Options:
        check_args(command, call.args)
        if not isinstance(call.args, dict):  # the schema's `type: object` should have said so
            raise InvalidArguments("args must be an object")
        # A copy, so the args checked are the args sent, whatever holds the caller's dict.
        args = dict(cast(dict[str, Any], call.args))  # pyright: ignore[reportUnknownMemberType]
        if call.select is not None and not isinstance(call.select, str):
            raise InvalidArguments("select must be a string")
        cols = columns(call.select, command.entry.view)
        if command.is_list and resumable(command, args):
            self._query_fits(command, args)
        if not isinstance(call.links, bool):
            raise InvalidArguments("links must be true or false")
        limit = self._limit(call.limit)
        resume = None
        if call.cursor is not None:
            if (
                not isinstance(call.cursor, str)
                or len(call.cursor) > CURSOR_MAX
                or not resumable(command, args)
            ):
                # Not a cursor, or a single resource or a list that is never resumed with
                # these args: no cursor of this call's could exist.
                raise CursorError(NOT_VALID)
            resume = self._cursors.open(
                call.cursor,
                uid=call.principal.uid,
                tool=tool_name(call.domain),
                command=call.command,
                args=args,
            )
        return _Options(args, cols, call.links, limit, resume)

    def _query_fits(self, command: Command, args: Mapping[str, Any]) -> None:
        """A resumable list's cursor carries the page's query string, and every row is charged
        for it, so long query args (each within its own bound) can fill `max_bytes` with cursor
        and fail as `result_too_large` after an Okta request (2.10 F3). Refused here instead,
        before any request, at a quarter of `max_bytes` once URL-encoded (the cursor is ~4/3 of
        it). The real encoding may differ by a little; the byte budget still backs this up."""
        size = 0
        for name, value in args.items():
            if command.entry.args[name].query is None:
                continue
            values = cast(list[object], value) if isinstance(value, list) else [value]
            size += sum(len(quote(str(v), safe="")) for v in values)
        budget = self._max_bytes // 4
        if size > budget:
            raise InvalidArguments(
                f"the query args are too long for a list: at most {budget} characters together "
                "once URL-encoded; shorten them"
            )

    def _limit(self, limit: object) -> int:
        if limit is None:
            return self._default_limit
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 0 < limit <= self._max_items
        ):
            raise InvalidArguments(f"limit must be an integer from 1 to {self._max_items}")
        return limit

    def _forbidden(self, call: Call, command: Command, options: _Options) -> str:
        """`FORBIDDEN`, and when an expression arg is what was refused, what the caller may
        name in one: their own roles' `search_attributes` for this command, which they may
        call. The engine gives no reason, so the call is checked again without the expression
        args: still forbidden means another arg (or the command) is the cause."""
        expressions = {
            name
            for name in options.args
            if (arg := command.entry.args.get(name)) is not None
            and arg.arg_rule is not None
            and arg.arg_rule.attribute_expression
        }
        if not expressions:
            return FORBIDDEN
        rest = {k: v for k, v in options.args.items() if k not in expressions}
        if self._engine.check(call.principal, call.domain, call.command, rest) is Verdict.FORBIDDEN:
            return FORBIDDEN
        return f"{FORBIDDEN}; {searchable(self._engine, call.principal, command)}"

    def _unreadable(self, call: Call, command: Command) -> str:
        return f"{EXPRESSION}; {searchable(self._engine, call.principal, command)}"

    async def _resolved(self, command: Command, args: dict[str, Any]) -> dict[str, Any]:
        if not any(a.resolve is not None for a in command.entry.args.values()):
            return args
        # `__init__` refused a missing resolver while any command resolves.
        return await cast(UserResolver, self._resolver).resolve(command, args, {})

    async def _item(self, command: Command, options: _Options) -> str:
        args = await self._resolved(command, options.args)
        url, params = build_request(command, args, self._org_url)
        response = await self._client.get(url, params)
        body = json_body(response)
        if body is None:
            raise UpstreamError(response.status_code, "Okta's response is not JSON")
        return item_result(
            body,
            self._engine.scrub,
            links=options.links,
            cols=options.cols,
            max_bytes=self._max_bytes,
        )

    async def _list(self, call: Call, command: Command, options: _Options) -> str:
        entry = command.entry
        args = options.args
        items: AsyncGenerator[tuple[Any, str, int]]
        cut_by_okta = False
        unpaged = any(a in args for a in entry.unpaged_args)
        resume = options.resume
        # Before the resolver and any page: a `select` long enough to fill `max_bytes` with the
        # envelope alone fails without an Okta request. Reserved at the most warnings it can get.
        list_budget(
            cols=options.cols,
            limit=options.limit,
            max_bytes=self._max_bytes,
            warnings=(RESUMED_WARNING,) if resume else (UNPAGED_WARNING,) if unpaged else (),
        )
        if resume is not None:
            # No resolver: the cursor's path params are the resolved ones.
            url = resume_url(command, resume, self._org_url)
            items = after(
                paginate(self._client, url, mode=entry.paginate, items_key=entry.items_key),
                resume.skip,
            )
            bound: Mapping[str, str] = resume.path_params
            warnings: tuple[str, ...] = (RESUMED_WARNING,)
        else:
            resolved = await self._resolved(command, args)
            url, params = build_request(command, resolved, self._org_url)
            if unpaged:
                # One page, links ignored. Read whole first, so the cut is judged on the page
                # Okta returned, not on how much of it `limit` or the byte budget lets out.
                page = [
                    x
                    async for x in paginate(
                        self._client, url, params, mode="none", items_key=entry.items_key
                    )
                ]
                cut_by_okta = len(page) >= cast(int, entry.page_size)
                items = _replay(page)
            else:
                mode: Mode = entry.paginate
                items = paginate(self._client, url, params, mode=mode, items_key=entry.items_key)
            bound = path_params(command, resolved)
            warnings = ()
        issue = (
            self._cursors.issuer(
                uid=call.principal.uid,
                tool=tool_name(call.domain),
                command=call.command,
                args=args,
                path_params=bound,
            )
            if resumable(command, args)
            else None
        )
        return await list_result(
            items,
            self._engine.scrub,
            links=options.links,
            cols=options.cols,
            limit=options.limit,
            max_bytes=self._max_bytes,
            next_cursor=issue,
            warnings=warnings,
            cut_by_okta=cut_by_okta,
        )
