"""The `okta-mcp` console script (design §4.1, §8.6).

`okta-mcp --stdio` serves stdio dev mode: it needs `MCP_DEV_MODE` on (stdio has no
authentication, so a fixed dev principal is the only caller it can have). `okta-mcp` serves
the HTTP app, which always authenticates and refuses to start while `MCP_DEV_MODE` is on.
Startup problems go to stderr, one per line, and the exit status is 2.

`--check` loads everything the chosen transport would (config, private key, spec, registry,
scrub rules, policy, resources) and exits without serving or sending a request: 0 with the
policy's warnings on stdout, or 2 with the same problems serving would print.
"""

import argparse
import sys
from collections.abc import Awaitable, Callable, Sequence

import anyio

from okta_mcp import __version__
from okta_mcp.app import check, serve_http
from okta_mcp.config import Config, ConfigError, load_config
from okta_mcp.exec.output import ScrubError
from okta_mcp.logs import configure_logging
from okta_mcp.policy.loader import PolicyError
from okta_mcp.registry.loader import RegistryError
from okta_mcp.resources import ResourceError
from okta_mcp.server import serve_stdio

STARTUP_FAILED = 2
STDIO_NEEDS_DEV_MODE = (
    "--stdio: needs MCP_DEV_MODE=1 and MCP_DEV_PRINCIPAL_FILE; stdio has no authentication, "
    "so it serves only the dev principal"
)
HTTP_REFUSES_DEV_MODE = (
    "MCP_DEV_MODE: refused by the HTTP transport, which always authenticates; dev mode is "
    "okta-mcp --stdio only"
)


CHECK_PASSED = "okta-mcp: check passed"
CHECK_FAILED = "okta-mcp: check failed"
CANNOT_START = "okta-mcp: cannot start"


def _fail(errors: Sequence[str], header: str = CANNOT_START) -> int:
    print(header, file=sys.stderr)
    for line in errors:
        print(f"  {line}", file=sys.stderr)
    return STARTUP_FAILED


def _run(run: Callable[[], Awaitable[int]], header: str) -> int:
    """`run()`'s exit status, or 2 after printing its startup errors under `header`."""
    try:
        return anyio.run(run)
    # The loaders' errors, raised only before the transport opens. Anything else is a bug and
    # keeps its traceback.
    except (ConfigError, PolicyError, RegistryError, ResourceError) as e:
        return _fail(e.errors, header)
    except ScrubError as e:
        return _fail([str(e)], header)


def _serve(serve: Callable[[Config], Awaitable[None]], config: Config) -> int:
    async def run() -> int:
        await serve(config)
        return 0

    return _run(run, CANNOT_START)


def _check(config: Config, *, stdio: bool) -> int:
    async def run() -> int:
        warnings = await check(config, stdio=stdio)
        print(CHECK_PASSED)
        for warning in warnings:
            print(f"  warning: {warning}")
        return 0

    return _run(run, CHECK_FAILED)


def _refusal(config: Config, *, stdio: bool) -> str | None:
    if stdio and not config.dev_mode:
        return STDIO_NEEDS_DEV_MODE
    if not stdio and config.dev_mode:
        return HTTP_REFUSES_DEV_MODE
    return None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="okta-mcp", description="Read-only MCP server for the Okta Management API."
    )
    parser.add_argument("--stdio", action="store_true", help="serve stdio dev mode")
    parser.add_argument(
        "--check",
        action="store_true",
        help="load config, key, registry and policy for the chosen transport, then exit",
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print(f"okta-mcp {__version__}")
        return 0
    header = CHECK_FAILED if args.check else CANNOT_START
    try:
        config = load_config()
    except ConfigError as e:
        return _fail(e.errors, header)
    configure_logging(config.log_level)
    refusal = _refusal(config, stdio=args.stdio)
    if refusal is not None:
        return _fail([refusal], header)
    if args.check:
        return _check(config, stdio=args.stdio)
    return _serve(serve_stdio if args.stdio else serve_http, config)


if __name__ == "__main__":
    sys.exit(main())
