"""Which Okta endpoints the server's service app can read: one GET per path, status only.

    uv run python scripts/okta-probe.py [PATH ...]      # default: /api/v1/users?limit=1

Reads the server's own settings from the environment: `OKTA_ORG_URL`, `OKTA_CLIENT_ID`,
`OKTA_PRIVATE_KEY_FILE`, `OKTA_KEY_ID` (optional), `OKTA_SCOPES` and `OKTA_DPOP` (default
true). It gets a token and sends each GET the way the server does (`ClientCredentialsProvider`,
`DPoP`, `OktaClient`), so a path that works here works for the server.

Use it to find the admin role a scope needs on your org (docs/okta-setup.md): give the service
app the narrower role, probe the commands' paths, and read the codes. `E0000006` is an admin
role that is too narrow; `E0000015` a feature the org doesn't have; `E0000007` an object that
isn't there.

Prints one line per path: `GET <path> -> <status> <detail>`, where `detail` is `list of N` or
`object` for a success, and Okta's `errorCode` (only if it is `E` and seven digits) or OAuth
`error` code (lower-case letters and `_`) for a failure, else `-`. Never a token, a response
body, a field value or Okta's error text. Paths must be on the org's Management API
(`/api/v1/…`, `/<area>/api/…` or `/oauth2/v1/clients/…`). Only GET is ever sent.

Exit status: 0 every path answered 2xx, 1 at least one didn't, 2 settings or token error.
"""

import argparse
import logging
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import anyio
import httpx2

from okta_mcp.config import ConfigError
from okta_mcp.okta.client import OktaClient, OriginError, UpstreamError, new_http_client
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.ratelimit import RateLimited
from okta_mcp.okta.token import ClientCredentialsProvider, TokenError, load_private_key

DEFAULT_PATH = "/api/v1/users?limit=1"
_API_PATH = re.compile(r"/(api/v1|[a-z][a-z-]*/api|oauth2/v1/clients)/[!-~]*")
_DOT_SEGMENT = re.compile(r"(^|/)(\.|%2e){1,2}(/|$|\?)", re.IGNORECASE)
_ERROR_CODE = re.compile(r"E[0-9]{7}")
_OAUTH_CODE = re.compile(r"[a-z_]{1,64}")
TRANSPORT: httpx2.AsyncBaseTransport | None = None
"""Replaced by the tests; None sends to Okta."""


class ProbeError(Exception):
    """Settings or the token request failed; nothing was probed. Safe to print."""


@dataclass(frozen=True)
class Settings:
    org: str
    client_id: str
    key_file: Path
    key_id: str | None
    scopes: frozenset[str]
    dpop: bool


@dataclass(frozen=True)
class Result:
    path: str
    status: int | None
    detail: str


def check_org(org: str) -> str:
    """`org` as an `https` origin with no trailing slash, or ProbeError."""
    try:
        url = httpx2.URL(org.rstrip("/"))
    except httpx2.InvalidURL:
        url = None
    if (
        url is None
        or url.scheme != "https"
        or not url.host
        or url.userinfo
        or url.raw_path not in (b"", b"/")
        or url.query
        or url.fragment
    ):
        raise ProbeError(
            "OKTA_ORG_URL must be the org's https origin, e.g. https://example.okta.com"
        )
    return str(url).rstrip("/")


def check_path(path: str) -> str:
    """`path` if it is a Management API path on the org, else ProbeError."""
    if not _API_PATH.fullmatch(path) or _DOT_SEGMENT.search(path) or "\\" in path:
        raise ProbeError(
            f"refused {path!r}: only Management API paths "
            "(/api/v1/…, /<area>/api/…, /oauth2/v1/clients/…)"
        )
    return path


def _detail(response: httpx2.Response) -> str:
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError):
        body = None
    if response.is_success:
        if isinstance(body, list):
            return f"list of {len(body)}"  # pyright: ignore[reportUnknownArgumentType]
        return "object" if isinstance(body, dict) else "-"
    if isinstance(body, dict):
        code = body.get("errorCode")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(code, str) and _ERROR_CODE.fullmatch(code):
            return code
        error = body.get("error")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if isinstance(error, str) and _OAUTH_CODE.fullmatch(error):
            return error
    return "-"


async def run(
    settings: Settings, paths: Sequence[str], transport: httpx2.AsyncBaseTransport | None = None
) -> list[Result]:
    """GET each of `paths` (checked first) and return what answered, in order."""
    paths = [check_path(p) for p in paths]
    org = check_org(settings.org)
    try:
        key = load_private_key(settings.key_file)
    except ConfigError as e:
        raise ProbeError(str(e.args[0][0])) from None
    answers: dict[str, tuple[int, str]] = {}

    async def answer(response: httpx2.Response) -> None:
        await response.aread()
        answers[response.request.url.raw_path.decode()] = (response.status_code, _detail(response))

    async with new_http_client(transport) as http:
        http.event_hooks["response"].append(answer)
        dpop = DPoP() if settings.dpop else None
        provider = ClientCredentialsProvider(
            http,
            org_url=org,
            client_id=settings.client_id,
            key=key,
            key_id=settings.key_id,
            scopes=settings.scopes,
            dpop=dpop,
        )
        try:
            await provider.token()
        except TokenError as e:
            raise ProbeError(str(e)) from None
        client = OktaClient(
            http, org_url=org, tokens=provider, dpop=dpop, max_inflight=1, rate_limit_max_wait=10
        )
        results: list[Result] = []
        for path in paths:
            url = org + path
            try:
                await client.get(url)
            except (UpstreamError, RateLimited):
                pass  # the answer hook has the status; the client's message is for MCP callers
            except OriginError:
                raise ProbeError(f"refused {path!r}: not on the org") from None
            status, detail = answers.get(httpx2.URL(url).raw_path.decode(), (None, "no answer"))
            results.append(Result(path, status, detail))
        return results


def describe(result: Result) -> str:
    return f"GET {result.path} -> {result.status or '-'} {result.detail}"


def settings_from_env() -> Settings:
    missing = [
        name
        for name in ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY_FILE", "OKTA_SCOPES")
        if not os.environ.get(name)
    ]
    if missing:
        raise ProbeError(f"set {', '.join(missing)} (the server's settings)")
    dpop = os.environ.get("OKTA_DPOP", "true").strip().lower()
    if dpop not in ("true", "false"):
        raise ProbeError("OKTA_DPOP must be true or false")
    return Settings(
        org=os.environ["OKTA_ORG_URL"],
        client_id=os.environ["OKTA_CLIENT_ID"],
        key_file=Path(os.environ["OKTA_PRIVATE_KEY_FILE"]),
        key_id=os.environ.get("OKTA_KEY_ID") or None,
        scopes=frozenset(os.environ["OKTA_SCOPES"].replace(",", " ").split()),
        dpop=dpop == "true",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("paths", nargs="*", metavar="PATH", help=f"default {DEFAULT_PATH}")
    args = parser.parse_args(argv)
    # The client logs each refusal for the server's operator; here the result line says it.
    logger = logging.getLogger("okta_mcp")
    level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        settings = settings_from_env()
        results = anyio.run(run, settings, args.paths or [DEFAULT_PATH], TRANSPORT)
    except ProbeError as e:
        print(f"okta-probe: {e}", file=sys.stderr)
        return 2
    finally:
        logger.setLevel(level)
    for result in results:
        print(describe(result))
    return 0 if all(r.status is not None and 200 <= r.status < 300 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
