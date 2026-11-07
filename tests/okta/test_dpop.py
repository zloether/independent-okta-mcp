import base64
import hashlib
import json
from typing import Any

import httpx2
import jwt
import pytest
from jwt.algorithms import ECAlgorithm

from okta_mcp.okta.dpop import DPoP

URL = "https://example.okta.com/api/v1/users"


def _decode(proof: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header = jwt.get_unverified_header(proof)
    key = ECAlgorithm.from_jwk(json.dumps(header["jwk"]))
    return header, jwt.decode(proof, key, algorithms=["ES256"])  # pyright: ignore[reportArgumentType]


def test_proof_claims() -> None:
    header, claims = _decode(DPoP(clock=lambda: 1000.7).proof("GET", URL + "?limit=1#x"))
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert header["jwk"]["kty"] == "EC"
    assert header["jwk"]["crv"] == "P-256"
    assert "d" not in header["jwk"]
    assert claims["htm"] == "GET"
    assert claims["htu"] == URL
    assert claims["iat"] == 1000
    assert len(claims["jti"]) >= 16
    assert "ath" not in claims
    assert "nonce" not in claims


def test_ath_is_token_hash() -> None:
    _, claims = _decode(DPoP().proof("GET", URL, access_token="tok"))  # noqa: S106
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"tok").digest()).rstrip(b"=").decode()
    assert claims["ath"] == digest


def test_fresh_jti_per_proof_and_one_key_per_instance() -> None:
    dpop = DPoP()
    proofs = [dpop.proof("GET", URL) for _ in range(5)]
    assert len({_decode(p)[1]["jti"] for p in proofs}) == 5
    assert len({json.dumps(_decode(p)[0]["jwk"]) for p in proofs}) == 1
    assert _decode(DPoP().proof("GET", URL))[0]["jwk"] != _decode(proofs[0])[0]["jwk"]


def _response(status: int, headers: dict[str, str], body: Any = None) -> httpx2.Response:
    return httpx2.Response(status, headers=headers, json=body)


@pytest.mark.parametrize(
    "response",
    [
        _response(400, {"DPoP-Nonce": "n1"}, {"error": "use_dpop_nonce"}),
        _response(401, {"DPoP-Nonce": "n1", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}),
        _response(401, {"DPoP-Nonce": "n1", "WWW-Authenticate": "DPoP error=use_dpop_nonce"}),
    ],
    ids=["token-endpoint", "resource", "resource-unquoted"],
)
def test_nonce_error_retries_with_nonce(response: httpx2.Response) -> None:
    dpop = DPoP()
    assert dpop.needs_retry(response)
    assert _decode(dpop.proof("GET", URL))[1]["nonce"] == "n1"


def test_nonce_on_success_is_captured_without_retry() -> None:
    dpop = DPoP()
    assert not dpop.needs_retry(_response(200, {"DPoP-Nonce": "n2"}, []))
    assert dpop.nonce == "n2"


@pytest.mark.parametrize(
    "response",
    [
        _response(400, {}, {"error": "use_dpop_nonce"}),
        _response(400, {"DPoP-Nonce": "n1"}, {"error": "invalid_dpop_proof"}),
        _response(400, {"DPoP-Nonce": "n1"}, ["use_dpop_nonce"]),
        httpx2.Response(400, headers={"DPoP-Nonce": "n1"}, content=b"not json"),
        _response(401, {"DPoP-Nonce": "n1", "WWW-Authenticate": 'DPoP error="invalid_token"'}),
        _response(403, {"DPoP-Nonce": "n1", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}),
        _response(
            401,
            {
                "DPoP-Nonce": "n1",
                "WWW-Authenticate": 'DPoP error="invalid_token", DPoP error="use_dpop_nonce"',
            },
        ),
    ],
    ids=["no-header", "other-error", "non-object", "non-json", "other-401", "403", "two-errors"],
)
def test_no_retry(response: httpx2.Response) -> None:
    assert not DPoP().needs_retry(response)


@pytest.mark.parametrize("nonce", ['a"b', "a b", "a\\b", "x" * 513])
def test_invalid_nonce_ignored(nonce: str) -> None:
    dpop = DPoP()
    assert not dpop.needs_retry(_response(400, {"DPoP-Nonce": nonce}, {"error": "use_dpop_nonce"}))
    assert dpop.nonce is None
