"""The audit log (design §12.3): one JSON line per `tools/call`, `tool_denied` for a policy
refusal, `tool_call` for everything else.

What a line may hold:

- Who: `uid`, `sub`, `client_id` and the caller's roles. Okta's own System Log attributes every
  call to the service app, so this is the only per-human record (§10).
- What: the tool and command, the args and options. Caller-sent names (a tool or command that
  doesn't exist) are cut to 64 characters. Args are logged only for a command that exists, and
  only the ones it declares; an undeclared key is counted, never named. An arg whose name a
  scrub.yaml rule names is `[redacted]`. A value is cut to `VALUE_MAX` characters of its JSON.
  A cursor is never logged, only that one was sent: it carries the page's query string.
  `MCP_AUDIT_ARGS=hash` replaces each arg value with a keyed hash (`hash_key`), so equal values
  can be matched across lines without the log holding them.
- How it went: the outcome (`ok` or the error code), the last Okta status, the Okta requests
  sent, items, bytes and truncation from the envelope, and the duration.

Never a result body, a token or a key. Each line is written before the result is returned: if
it can't be written, the call fails (`AuditError`) rather than go unrecorded.
"""

import contextvars
import hashlib
import hmac
import json
import os
import sys
import time
from collections.abc import Callable, Collection, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.executor import Code, Failure, Success, tool_name
from okta_mcp.exec.output import REDACTED, ScrubRules
from okta_mcp.policy.engine import Engine
from okta_mcp.registry.loader import Registry

NAME_MAX = 64
"""Characters of a caller-sent tool or command name a line carries."""
VALUE_MAX = 512
"""Characters of one arg value's JSON a line carries."""
CUT = "…[cut]"
HASH_LABEL = b"okta-mcp audit args v1"

_HELP = "okta_help"
_STATUS = "okta_status"
_OPTIONS = ("select", "links", "limit")

ArgsMode = Literal["full", "hash"]
Reason = Literal[
    "unknown_tool", "tool_not_permitted", "command_not_permitted", "args_not_permitted"
]


class AuditError(Exception):
    """The audit line couldn't be written."""


class Sink(Protocol):
    def write(self, s: str, /) -> object: ...
    def flush(self) -> object: ...


@dataclass
class CallStats:
    """Okta traffic of one call, filled in by `OktaClient`'s `on_sent` (`record_sent`)."""

    okta_requests: int = 0
    status: int | None = None
    """The last Okta response's status; None if none came back."""


_stats: contextvars.ContextVar[CallStats | None] = contextvars.ContextVar(
    "okta_mcp_audit_stats", default=None
)


def record_sent(status: int | None) -> None:
    """`OktaClient`'s `on_sent`: one request sent, and its response's status (None for a
    transport error). Outside a tool call (none is being audited) it does nothing."""
    stats = _stats.get()
    if stats is not None:
        stats.okta_requests += 1
        if status is not None:
            stats.status = status


@contextmanager
def collect() -> Generator[CallStats]:
    """Count the Okta requests made inside the block."""
    stats = CallStats()
    token = _stats.set(stats)
    try:
        yield stats
    finally:
        _stats.reset(token)


def hash_key(cursor_key: bytes) -> bytes:
    """The key `MCP_AUDIT_ARGS=hash` uses, derived from `MCP_CURSOR_KEY` under its own label,
    so the cursor key itself never keys anything else. Rotating the cursor key changes every
    hash."""
    return hmac.new(cursor_key, HASH_LABEL, hashlib.sha256).digest()


def open_sink(target: str, *, stdio: bool) -> Sink:
    """`MCP_AUDIT_LOG`: `stdout`, `stderr` or a file path (appended to, one line per write).
    Over stdio, stdout is the transport, so `stdout` means stderr. Raises `OSError` for a file
    that can't be opened."""
    if target == "stderr" or (target == "stdout" and stdio):
        return sys.stderr
    if target == "stdout":
        return sys.stdout
    # Owner-only when created: full-mode args are PII (§12.3). An existing file keeps its mode.
    fd = os.open(Path(target), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value if len(value) <= NAME_MAX else value[:NAME_MAX] + CUT


class AuditLog:
    """One per process. `sink` gets one line per call; `clock` and `now` are for tests."""

    def __init__(
        self,
        sink: Sink,
        *,
        registry: Registry,
        engine: Engine,
        args_mode: ArgsMode,
        key: bytes,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], str] = _now,
    ) -> None:
        self._sink = sink
        self._registry = registry
        self._engine = engine
        self._mode: ArgsMode = args_mode
        self._key = key
        self._clock = clock
        self._now = now
        self._domains = {tool_name(d): d for d in registry.domains}
        self._redacted = _arg_names(engine.scrub)
        self._tools = frozenset(self._domains) | {_HELP, _STATUS}

    def start(self) -> float:
        return self._clock()

    def record(
        self,
        *,
        request_id: str,
        principal: Principal,
        tool: object,
        arguments: object,
        outcome: object,
        started: float,
        stats: CallStats,
    ) -> None:
        """Write the line for one call. `tool` and `arguments` are as the client sent them;
        `outcome` is what `Tools.call` returned (`Success`, `okta_mcp.tools.Text` or `Failure`),
        or None for a call cancelled before it returned. Raises `AuditError` if the line can't
        be written."""
        given: Mapping[str, object] = (
            cast(Mapping[str, object], arguments) if isinstance(arguments, dict) else {}
        )
        line: dict[str, Any] = {
            "ts": self._now(),
            "event": "tool_call",
            "request_id": request_id,
            "uid": principal.uid,
            "sub": principal.sub,
            "client_id": principal.client_id,
            "roles": sorted(self._engine.roles(principal)),
            "tool": self._caller_name(tool, self._tools),
        }
        domain = self._domains.get(tool) if isinstance(tool, str) else None
        command = given.get("command")
        if tool == _HELP:
            target = given.get("tool")
            names = self._commands(self._domains.get(target) if isinstance(target, str) else None)
            known = {"tool": frozenset(self._domains), "command": names}
            line["args"] = {
                k: self._caller_name(given[k], known[k]) for k in ("tool", "command") if k in given
            }
        elif domain is not None:
            line["command"] = self._caller_name(command, self._commands(domain))
            self._call_args(line, domain, command, given)
        if outcome is None:
            line["outcome"] = "cancelled"
        elif isinstance(outcome, Failure):
            line["outcome"] = outcome.code.value
            if outcome.code is Code.FORBIDDEN_BY_POLICY:
                line["event"] = "tool_denied"
                line["reason"] = self._reason(principal, tool, domain, command, given)
        else:
            line["outcome"] = "ok"
            text = cast(str, getattr(outcome, "text", ""))
            line["bytes"] = len(text.encode())
            if isinstance(outcome, Success):
                _envelope(line, text)
        line["status"] = stats.status
        line["okta_requests"] = stats.okta_requests
        line["duration_ms"] = round((self._clock() - started) * 1000)
        try:
            self._sink.write(json.dumps(line, separators=(",", ":")) + "\n")
            self._sink.flush()
        except (OSError, ValueError) as e:
            # The message names the file, never the line.
            raise AuditError(type(e).__name__) from None

    # --- args ----------------------------------------------------------------------------

    def _call_args(
        self, line: dict[str, Any], domain: str, command: object, given: Mapping[str, object]
    ) -> None:
        commands = self._registry.domains[domain].commands
        cmd = commands.get(command) if isinstance(command, str) else None
        if cmd is None:
            return  # an unknown command's args are the caller's, not ours to name
        sent = given.get("args", {})
        if isinstance(sent, dict):
            declared = cmd.entry.args
            args: dict[str, Any] = {}
            unknown = 0
            for key, value in cast(dict[object, object], sent).items():
                if not isinstance(key, str) or key not in declared:
                    unknown += 1
                elif key.lower() in self._redacted:
                    args[key] = REDACTED
                else:
                    args[key] = self._value(value)
            line["args"] = dict(sorted(args.items()))
            if unknown:
                line["unknown_args"] = unknown
        elif "args" in given:
            line["args"] = "invalid"
        options: dict[str, Any] = {}
        for key in _OPTIONS:
            if key in given:
                value = given[key]
                options[key] = (
                    self._caller_name(value, ()) if isinstance(value, str) else _scalar(value)
                )
        if "cursor" in given:
            options["cursor"] = True
        if options:
            line["options"] = options

    def _commands(self, domain: str | None) -> frozenset[str]:
        if domain is None:
            return frozenset()
        return frozenset(self._registry.domains[domain].commands)

    def _caller_name(self, value: object, known: Collection[str]) -> str | None:
        """A tool or command name, or `select`, as the caller sent it: as is if it is one of
        ours, else cut to `NAME_MAX`, or hashed in hash mode (it is free text, so it could
        hold what an arg would)."""
        if not isinstance(value, str):
            return None
        if value in known:
            return value
        if self._mode == "hash":
            return self._hash(value)
        return _name(value)

    def _hash(self, text: str) -> str:
        return "hmac:" + hmac.new(self._key, text.encode(), hashlib.sha256).hexdigest()[:32]

    def _value(self, value: object) -> object:
        try:
            text = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return "invalid"
        if self._mode == "hash":
            return self._hash(text)
        if len(text) <= VALUE_MAX:
            return value
        return text[:VALUE_MAX] + CUT

    # --- denials -------------------------------------------------------------------------

    def _reason(
        self,
        principal: Principal,
        tool: object,
        domain: str | None,
        command: object,
        given: Mapping[str, object],
    ) -> Reason:
        """Which check refused it, from the same `Engine.permitted` the call used."""
        permitted = self._engine.permitted(principal)
        if tool == _HELP:
            # Help is refused only for a target the caller can't call or that doesn't exist;
            # the same reasons as a call to that target.
            target = given.get("tool")
            domain = self._domains.get(target) if isinstance(target, str) else None
            command = given.get("command")
        if domain is None:
            return "unknown_tool"
        if not any(d == domain for d, _ in permitted):
            return "tool_not_permitted"
        if not isinstance(command, str) or (domain, command) not in permitted:
            return "command_not_permitted"
        return "args_not_permitted"


def _arg_names(rules: ScrubRules) -> frozenset[str]:
    """Single-key scrub paths: an arg so named is redacted from the log."""
    return frozenset(chain[0] for chain, _ in rules.chains if len(chain) == 1)


def _scalar(value: object) -> object:
    if value is None or isinstance(value, bool | int | float):
        return value
    return "invalid"


def _envelope(line: dict[str, Any], text: str) -> None:
    """`items` and `truncated` from a list envelope (`count`), `items: 1` for a single
    resource. `okta_status` is a `Success` too, with no `untrusted` key: nothing is added."""
    try:
        envelope = json.loads(text)
    except ValueError:
        return
    if not isinstance(envelope, dict) or "untrusted" not in envelope:
        return
    body = cast(dict[str, Any], envelope)
    count = body.get("count")
    line["items"] = count if isinstance(count, int) and not isinstance(count, bool) else 1
    line["truncated"] = body.get("truncated", False)
