"""Operational logging (design §11): stderr, one line per record, each tagged with the request
ID. JSON lines are step 6.2's.

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
import logging
import sys
import traceback

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


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get() or "-"
        return True


class DependencyExceptionFilter(logging.Filter):
    """Replaces a non-`okta_mcp` record's exception and stack with the exception's type."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == PACKAGE or record.name.startswith(PACKAGE + "."):
            return True
        if record.exc_info:
            exc = record.exc_info[1]
            if exc is not None:
                record.msg = f"{record.getMessage()} ({type(exc).__name__}; details withheld)"
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
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    # Never below WARNING for dependencies, and never noisier than what was asked for.
    root.setLevel(max(logging.WARNING, logging.getLevelNamesMapping()[level]))
    logging.getLogger(PACKAGE).setLevel(level)
