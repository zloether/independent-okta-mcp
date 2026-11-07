"""DPoP proofs for the service app's requests to Okta (RFC 9449; design §6.5, V15).

One ephemeral EC P-256 key per `DPoP`, generated in memory and never written out or logged.
Each request, the token call and every Management API request alike, gets a fresh proof. Okta
rejects a proof without the nonce it wants (`use_dpop_nonce`, with a `DPoP-Nonce` header);
`needs_retry` records that nonce, later proofs carry it, and the caller retries once.
"""

import base64
import hashlib
import re
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

_NONCE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{1,512}")  # RFC 9449 NQCHAR, bounded
_RESOURCE_NONCE_ERROR = re.compile(r'\berror\s*=\s*"?use_dpop_nonce\b')  # quoted or token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def use_dpop_nonce(response: httpx2.Response) -> bool:
    """Token endpoint: 400 with `error` in the body (RFC 9449 §8). Resource server: 401 with
    the error in `WWW-Authenticate` (§9). True whether or not a usable nonce came with it."""
    if response.status_code == 401:
        return bool(_RESOURCE_NONCE_ERROR.search(response.headers.get("WWW-Authenticate", "")))
    if response.status_code == 400:
        try:
            body = response.json()
        except (ValueError, UnicodeDecodeError):
            return False
        match body:
            case {"error": "use_dpop_nonce"}:
                return True
            case _:
                return False
    return False


class DPoP:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._header: dict[str, Any] = {
            "typ": "dpop+jwt",
            "jwk": ECAlgorithm.to_jwk(self._key.public_key(), as_dict=True),
        }
        self._clock = clock
        self.nonce: str | None = None

    def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        """A proof for one request; pass `access_token` on resource requests (`ath`)."""
        parts = urlsplit(url)
        claims: dict[str, Any] = {
            "jti": secrets.token_urlsafe(16),
            "htm": method,
            "htu": urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")),
            "iat": int(self._clock()),
        }
        if self.nonce is not None:
            claims["nonce"] = self.nonce
        if access_token is not None:
            claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
        return jwt.encode(claims, self._key, algorithm="ES256", headers=self._header)

    def needs_retry(self, response: httpx2.Response) -> bool:
        """Record a valid `DPoP-Nonce` from any response; True if `response` is a
        `use_dpop_nonce` error that came with one, so the request should be retried once."""
        nonce = response.headers.get("DPoP-Nonce")
        if nonce is None or not _NONCE.fullmatch(nonce):
            return False
        self.nonce = nonce
        return use_dpop_nonce(response)
