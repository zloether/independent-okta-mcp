"""Check 1 (plan 8.2.1): the CI service app's token, as the server gets it."""

from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest
from _live import remember_token

from okta_mcp.okta.client import new_http_client
from okta_mcp.okta.dpop import DPoP
from okta_mcp.okta.token import ClientCredentialsProvider, load_private_key

pytestmark = pytest.mark.anyio


@pytest.fixture
async def fresh(
    config: Any,
) -> AsyncIterator[tuple[ClientCredentialsProvider, list[httpx2.Request]]]:
    """A provider with an empty cache: the shared one may already hold a token."""
    sent: list[httpx2.Request] = []

    async def record(request: httpx2.Request) -> None:
        sent.append(request)

    async with new_http_client() as http:
        http.event_hooks["request"].append(record)
        provider = ClientCredentialsProvider(
            http,
            org_url=config.okta_org_url,
            client_id=config.okta_client_id,
            key=load_private_key(config.okta_private_key_file),
            key_id=config.okta_key_id,
            scopes=config.okta_scopes,
            dpop=DPoP(),
        )
        yield provider, sent


async def test_dpop_token_nonce_and_cache(
    fresh: tuple[ClientCredentialsProvider, list[httpx2.Request]],
    org_url: str,
) -> None:
    provider, sent = fresh
    token_url = org_url + "/oauth2/v1/token"

    first = await provider.token()
    remember_token(first.value)
    posts = [r for r in sent if str(r.url) == token_url]

    # Okta asks for a nonce on the first DPoP token request (V15), so there are two POSTs.
    # A token_type other than DPoP would have raised in the provider: a Bearer downgrade fails.
    assert first.scheme == "DPoP"
    assert len(posts) == 2, f"token POSTs on first fetch: {len(posts)} (expected a nonce retry)"
    # Booleans only: pytest would print a header value in a failed assert.
    proof_sent = bool(posts[1].headers.get("DPoP"))
    assert proof_sent, "the retry carried no DPoP proof"

    again = await provider.token()
    cached = again is first
    assert cached, "the second call wasn't served from the cache"
    assert len([r for r in sent if str(r.url) == token_url]) == 2


async def test_resource_call_with_dpop(okta: tuple[Any, Any, list[Any]], org_url: str) -> None:
    _provider, client, sent = okta
    before = len(sent)
    response = await client.get(org_url + "/api/v1/users", {"limit": "1"})
    assert response.status_code == 200
    calls = [r for r in sent[before:] if r.url.path == "/api/v1/users"]
    assert calls, "no request recorded"
    dpop_scheme = calls[-1].headers["Authorization"].startswith("DPoP ")
    proof_sent = bool(calls[-1].headers.get("DPoP"))
    assert dpop_scheme, "the resource request didn't use the DPoP scheme"
    assert proof_sent, "resource request without a DPoP proof"
