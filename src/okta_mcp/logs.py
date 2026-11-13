"""Operational logging (design §13): stderr, one JSON object per line, each with the request ID
(`null` outside an MCP request, e.g. the HTTP auth layer or background refreshes).

A line has `ts`, `level`, `logger`, `request_id` and `msg`; a record logged with
`extra=event(name, **fields)` also has `event` and its fields, so 429s, retries, limiter
rejections, truncations and JWKS failures can be counted without parsing `msg`. Fields are
scalars we chose (counts, reasons, waits), never a value the caller or Okta sent: an event
can't carry what the rest of this module keeps out. The principal isn't on a line; the
audit log (§12.3) joins on `request_id`.

What may not be logged (AGENTS.md: tokens, keys, Okta result bodies) is enforced here for code
we don't own, and by `log_internal` for our own exceptions:

- `MCP_LOG_LEVEL` applies to `okta_mcp` only. Every other logger is held at WARNING or above:
  httpx2 logs each request URL at INFO (search values, logins, Okta's `after` tokens) and the
  SDK can log whole messages at DEBUG (Okta results).
- A dependency's record keeps its message but loses its exception text: the SDK logs a result
  that fails its own validation with `logger.exception`, and pydantic's message repeats the
  result, i.e. Okta data. The exception's type stays, so the line is still useful.
"""

import contextvars
import json
import logging
import sys
import traceback
from datetime import UTC, datetime
from typing import cast

PACKAGE = "okta_mcp"

request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "okta_mcp_request_id", default=None
)
"""The current request's ID, returned in error responses and tagged on every log line."""


def log_internal(logger: logging.Logger, where: str, e: BaseException) -> None:
    """Log an unexpected exception by its type and traceback frames only, never its message,
    which may hold Okta data or a caller's args. The one place that rule lives for our code."""
    frames = "".join(traceback.format_tb(e.__traceback__))
    logger.error("internal error in %s: %s\n%s", where, type(e).__name__, frames)


Field = str | int | float | bool | None

_EVENT = "okta_mcp_event"
_BASE = frozenset({"ts", "level", "logger", "request_id", "msg", "event", "exc_type"})


def event(name: str, **fields: Field) -> dict[str, object]:
    """`extra=` for a structured event: `log.warning("...", extra=event("okta_rate_limited",
    retry=False))`. A field named like a base key (`ts`, `msg`, ...) is a bug."""
    if clash := fields.keys() & _BASE:
        raise ValueError(f"event field names a base key: {sorted(clash)}")
    return {_EVENT: (name, fields)}


class JsonFormatter(logging.Formatter):
    """One compact JSON object per record. Runs after the filters, so a dependency's exception
    text is already gone; our own code never attaches `exc_info` (`log_internal` formats frames
    into the message)."""

    def format(self, record: logging.LogRecord) -> str:
        line: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", None),
            "msg": record.getMessage(),
        }
        tagged = getattr(record, _EVENT, None)
        if isinstance(tagged, tuple):
            name, fields = cast(tuple[str, dict[str, Field]], tagged)
            line["event"] = name
            line.update(fields)
        if record.exc_info and record.exc_info[1] is not None:
            # Not expected (see above); kept as the type only, never the message.
            line["exc_type"] = type(record.exc_info[1]).__name__
        return json.dumps(line, ensure_ascii=True, default=str)


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get()
        return True


class DependencyExceptionFilter(logging.Filter):
    """Replaces a non-`okta_mcp` record's exception and stack with the exception's type."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == PACKAGE or record.name.startswith(PACKAGE + "."):
            return True
        if record.name == "py.warnings":
            # `warnings.formatwarning` text: "file:line: Category: message\n  source". The
            # message can hold values (pydantic serializer warnings); keep where and what.
            where, _, rest = record.getMessage().partition(": ")
            category = rest.partition(":")[0]
            record.msg = f"{where}: {category} (details withheld)"
            record.args = None
        if record.exc_info:
            exc = record.exc_info[1]
            if exc is not None:
                try:
                    message = record.getMessage()
                except Exception:  # a dependency's bad format string must not break its caller
                    message = str(record.msg)
                record.msg = f"{message} ({type(exc).__name__}; details withheld)"
                record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def configure_logging(level: str) -> None:
    """stderr only; stdout is the stdio transport's. `level` is `MCP_LOG_LEVEL`."""
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(DependencyExceptionFilter())
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    # `warnings` output (pydantic's can hold input values) goes through the filters above.
    logging.captureWarnings(True)
    # Never below WARNING for dependencies, and never noisier than what was asked for.
    root.setLevel(max(logging.WARNING, logging.getLevelNamesMapping()[level]))
    logging.getLogger(PACKAGE).setLevel(level)
