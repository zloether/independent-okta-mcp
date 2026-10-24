"""Run: uv run pytest spikes/okta"""

import base64
import hashlib
import json

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from okta_spike import (
    b64url,
    client_assertion,
    discovery_urls,
    dpop_proof,
    fetch_service_token,
    pkce_pair,
)

ORG = "https://example.okta.com"
TOKEN_URL = f"{ORG}/oauth2/v1/token"


def test_pkce_pair_is_s256() -> None:
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert challenge == b64url(hashlib.sha256(verifier.encode()).digest())
    assert "=" not in challenge


def test_client_assertion_claims() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = client_assertion("0oaclient", TOKEN_URL, key, "kid1")
    assert jwt.get_unverified_header(token)["kid"] == "kid1"
    claims = jwt.decode(token, key.public_key(), algorithms=["RS256"], audience=TOKEN_URL)
    assert claims["iss"] == claims["sub"] == "0oaclient"
    assert claims["exp"] - claims["iat"] <= 300
    assert claims["jti"]


def test_dpop_proof_shape() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    url = f"{ORG}/api/v1/users?limit=1"
    proof = dpop_proof(key, "GET", url, nonce="n1", access_token="at")  # noqa: S106
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "d" not in header["jwk"]
    claims = jwt.decode(proof, key.public_key(), algorithms=["ES256"])
    assert claims["htm"] == "GET"
    assert claims["htu"] == f"{ORG}/api/v1/users"
    assert claims["nonce"] == "n1"
    assert claims["ath"] == b64url(hashlib.sha256(b"at").digest())


def test_dpop_proof_omits_optional_claims() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    claims = jwt.decode(dpop_proof(key, "POST", TOKEN_URL), options={"verify_signature": False})
    assert "nonce" not in claims
    assert "ath" not in claims


def test_discovery_urls() -> None:
    urls = discovery_urls(f"{ORG}/oauth2/aus1")
    assert urls == {
        "oidc": f"{ORG}/oauth2/aus1/.well-known/openid-configuration",
        "rfc8414_insertion": f"{ORG}/.well-known/oauth-authorization-server/oauth2/aus1",
        "rfc8414_appended": f"{ORG}/oauth2/aus1/.well-known/oauth-authorization-server",
    }


def _form(request: httpx2.Request) -> dict[str, str]:
    return dict(pair.split("=", 1) for pair in request.content.decode().split("&"))


def test_fetch_service_token_retries_once_with_nonce() -> None:
    seen: list[dict[str, object]] = []
    assertions: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        proof = jwt.decode(request.headers["DPoP"], options={"verify_signature": False})
        seen.append(proof)
        assertions.append(_form(request)["client_assertion"])
        if "nonce" not in proof:
            return httpx2.Response(
                400, headers={"DPoP-Nonce": "n1"}, json={"error": "use_dpop_nonce"}
            )
        assert _form(request)["grant_type"] == "client_credentials"
        return httpx2.Response(200, json={"access_token": "at", "token_type": "DPoP"})

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dpop_key = ec.generate_private_key(ec.SECP256R1())
    with httpx2.Client(transport=httpx2.MockTransport(handler)) as http:
        result = fetch_service_token(
            http, ORG, "0oaclient", rsa_key, "kid1", "okta.users.read", dpop_key
        )
    assert result.token_type == "DPoP"  # noqa: S105
    assert result.nonce_required is True
    assert len(seen) == 2
    assert seen[1]["nonce"] == "n1"
    assert len(set(assertions)) == 2  # fresh jti per attempt; Okta rejects replays


def test_fetch_service_token_without_dpop() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert "DPoP" not in request.headers
        return httpx2.Response(200, json={"access_token": "at", "token_type": "Bearer"})

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with httpx2.Client(transport=httpx2.MockTransport(handler)) as http:
        result = fetch_service_token(http, ORG, "0oaclient", rsa_key, "kid1", "s", None)
    assert result.token_type == "Bearer"  # noqa: S105
    assert result.nonce_required is False


def test_b64url_roundtrip() -> None:
    raw = json.dumps({"a": 1}).encode()
    assert base64.urlsafe_b64decode(b64url(raw) + "==") == raw
