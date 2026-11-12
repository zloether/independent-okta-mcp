"""The `okta-mcp` console script (design §4.1, §8.6).

`okta-mcp --stdio` serves stdio dev mode: it needs `MCP_DEV_MODE` on (stdio has no
authentication, so a fixed dev principal is the only caller it can have). `okta-mcp` serves
the HTTP app, which always authenticates and refuses to start while `MCP_DEV_MODE` is on.
Startup problems go to stderr, one per line, and the exit status is 2.
"""

import argparse
import sys
from collections.abc import Awaitable, Callable, Sequence

import anyio

from okta_mcp import __version__
from okta_mcp.app import serve_http
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


def _fail(errors: Sequence[str]) -> int:
    print("okta-mcp: cannot start", file=sys.stderr)
    for line in errors:
        print(f"  {line}", file=sys.stderr)
    return STARTUP_FAILED


def _serve(serve: Callable[[Config], Awaitable[None]], config: Config) -> int:
    try:
        anyio.run(serve, config)
    # The loaders' errors, raised only before the transport opens. Anything else is a bug and
    # keeps its traceback.
    except (ConfigError, PolicyError, RegistryError, ResourceError) as e:
        return _fail(e.errors)
    except ScrubError as e:
        return _fail([str(e)])
    return 0


def _stdio(config: Config) -> int:
    if not config.dev_mode:
        return _fail([STDIO_NEEDS_DEV_MODE])
    return _serve(serve_stdio, config)


def _http(config: Config) -> int:
    if config.dev_mode:
        return _fail([HTTP_REFUSES_DEV_MODE])
    return _serve(serve_http, config)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="okta-mcp", description="Read-only MCP server for the Okta Management API."
    )
    parser.add_argument("--stdio", action="store_true", help="serve stdio dev mode")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print(f"okta-mcp {__version__}")
        return 0
    try:
        config = load_config()
    except ConfigError as e:
        return _fail(e.errors)
    configure_logging(config.log_level)
    return _stdio(config) if args.stdio else _http(config)


if __name__ == "__main__":
    sys.exit(main())
