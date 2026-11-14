"""Step 0.5 Okta dev-org spike helpers. Throwaway; findings go to docs/design/spike-findings.md.

Run from the repo root with `uv run python spikes/okta/okta_spike.py <command> --help`:

  keygen      RSA key for the service app; prints the public JWK to upload (V15)
  discover    probe OIDC and RFC 8414 metadata URLs for a custom AS (V10)
  user-token  Authorization Code + PKCE over a loopback redirect; prints access-token
              header and claims, never the token itself (V1, V9, V11, V13)
  service     private_key_jwt client credentials (+DPoP), then GET /api/v1/users?limit=1
              (or each --path); prints statuses, nonce behavior, and a list's length or an
              object's id/errorCode, never tokens or result bodies (V15, 2.10)
"""

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


def client_assertion(client_id: str, token_url: str, key: rsa.RSAPrivateKey, kid: str) -> str:
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_url,
        "iat": now,
        "exp": now + 300,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def dpop_proof(
    key: ec.EllipticCurvePrivateKey,
    method: str,
    url: str,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    htu = urllib.parse.urlsplit(url)._replace(query="", fragment="").geturl()
    claims: dict[str, Any] = {
        "htm": method,
        "htu": htu,
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(16),
    }
    if nonce:
        claims["nonce"] = nonce
    if access_token:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode()).digest())
    jwk = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})


def discovery_urls(issuer: str) -> dict[str, str]:
    parts = urllib.parse.urlsplit(issuer)
    origin = f"{parts.scheme}://{parts.netloc}"
    return {
        "oidc": f"{issuer}/.well-known/openid-configuration",
        "rfc8414_insertion": f"{origin}/.well-known/oauth-authorization-server{parts.path}",
        "rfc8414_appended": f"{issuer}/.well-known/oauth-authorization-server",
    }


@dataclass
class ServiceToken:
    access_token: str
    token_type: str
    nonce_required: bool
    nonce: str | None


def _oauth_error(response: httpx2.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    return f"HTTP {response.status_code} {body.get('error')}: {body.get('error_description')}"


def fetch_service_token(
    http: httpx2.Client,
    org: str,
    client_id: str,
    key: rsa.RSAPrivateKey,
    kid: str,
    scopes: str,
    dpop_key: ec.EllipticCurvePrivateKey | None,
) -> ServiceToken:
    token_url = f"{org}/oauth2/v1/token"
    nonce: str | None = None
    while True:
        form = {
            "grant_type": "client_credentials",
            "scope": scopes,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion(client_id, token_url, key, kid),
        }
        headers = {"DPoP": dpop_proof(dpop_key, "POST", token_url, nonce)} if dpop_key else {}
        response = http.post(token_url, data=form, headers=headers)
        if response.status_code == 200:
            body = response.json()
            return ServiceToken(body["access_token"], body["token_type"], nonce is not None, nonce)
        new_nonce = response.headers.get("DPoP-Nonce")
        if dpop_key is None or nonce is not None or new_nonce is None:
            raise RuntimeError(f"token request failed: {_oauth_error(response)}")
        nonce = new_nonce


def _decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    return jwt.get_unverified_header(token), jwt.decode(token, options={"verify_signature": False})


def cmd_keygen(args: argparse.Namespace) -> None:
    out = Path(args.out)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out.touch(mode=0o600, exist_ok=False)
    out.write_bytes(pem)
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk["kid"] = b64url(hashlib.sha256(json.dumps(jwk, sort_keys=True).encode()).digest())[:16]
    jwk |= {"use": "sig", "alg": "RS256"}
    print(f"private key written to {out} (0600); public JWK to paste into Okta:")
    print(json.dumps(jwk, indent=2))


def cmd_discover(args: argparse.Namespace) -> None:
    with httpx2.Client(timeout=10) as http:
        for name, url in discovery_urls(args.issuer.rstrip("/")).items():
            response = http.get(url)
            line = f"{name:18} {response.status_code} {url}"
            if response.status_code == 200:
                meta = response.json()
                line += (
                    f"\n{'':18} issuer={meta.get('issuer')}"
                    f" pkce={meta.get('code_challenge_methods_supported')}"
                    f" dpop_algs={meta.get('dpop_signing_alg_values_supported')}"
                )
            print(line)


def _wait_for_code(port: int, state: str) -> str:
    result: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
            result.update(query)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Done; return to the terminal.")

        def log_message(self, format: str, *args: Any) -> None:
            pass

    with http.server.HTTPServer(("127.0.0.1", port), Handler) as server:
        server.handle_request()
    if "error" in result:
        detail = result.get("error_description")
        raise RuntimeError(f"authorize failed: {result['error']}: {detail}")
    if result.get("state") != state:
        raise RuntimeError("state mismatch")
    return result["code"]


def cmd_user_token(args: argparse.Namespace) -> None:
    issuer = args.issuer.rstrip("/")
    redirect_uri = f"http://{args.redirect_host}:{args.port}/callback"
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": args.client_id,
        "redirect_uri": redirect_uri,
        "scope": args.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if args.resource:
        params["resource"] = args.resource
    print("Open in a browser:\n" + f"{issuer}/v1/authorize?{urllib.parse.urlencode(params)}")
    code = _wait_for_code(args.port, state)
    form = {
        "grant_type": "authorization_code",
        "client_id": args.client_id,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": verifier,
    }
    if args.resource and not args.no_resource_on_token:
        form["resource"] = args.resource
    with httpx2.Client(timeout=10) as http:
        response = http.post(f"{issuer}/v1/token", data=form)
    if response.status_code != 200:
        raise RuntimeError(f"token request failed: {_oauth_error(response)}")
    header, claims = _decode_unverified(response.json()["access_token"])
    print("access-token header:", json.dumps(header, indent=2))
    print("access-token claims:", json.dumps(claims, indent=2))


def cmd_service(args: argparse.Namespace) -> None:
    org = args.org.rstrip("/")
    pem = Path(args.key_file).read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SystemExit("expected an RSA private key")
    dpop_key = None if args.no_dpop else ec.generate_private_key(ec.SECP256R1())
    with httpx2.Client(timeout=10) as http:
        token = fetch_service_token(http, org, args.client_id, key, args.kid, args.scopes, dpop_key)
        print(f"token: type={token.token_type} nonce_required_at_token={token.nonce_required}")
        nonce = token.nonce
        for path in args.path or ["/api/v1/users?limit=1"]:
            response, nonce = probe(http, org + path, token, dpop_key, nonce)
            if line := describe(response):
                print(f"  {line}")


def probe(
    http: httpx2.Client,
    url: str,
    token: ServiceToken,
    dpop_key: ec.EllipticCurvePrivateKey | None,
    nonce: str | None,
) -> tuple[httpx2.Response, str | None]:
    """GET `url`, retrying once with a new DPoP nonce; returns the nonce to use next."""
    path = url.split("/", 3)[3]
    for attempt in (1, 2):
        if dpop_key:
            proof = dpop_proof(dpop_key, "GET", url, nonce, token.access_token)
            headers = {"Authorization": f"DPoP {token.access_token}", "DPoP": proof}
        else:
            headers = {"Authorization": f"Bearer {token.access_token}"}
        response = http.get(url, headers=headers)
        new_nonce = response.headers.get("DPoP-Nonce")
        print(
            f"GET /{path} attempt {attempt}: {response.status_code}"
            f" www-authenticate={response.headers.get('WWW-Authenticate')!r}"
            f" dpop-nonce-sent={new_nonce is not None}"
            f" reused-token-nonce={nonce is not None and nonce == token.nonce}"
        )
        retry = dpop_key is not None and response.status_code != 200 and new_nonce != nonce
        nonce = new_nonce or nonce
        if not retry or new_nonce is None:
            break
    return response, nonce


def describe(response: httpx2.Response) -> str | None:
    """Which resource answered, not what it holds: a list's length, an object's `id`, an
    error's code and summary."""
    json_body = "json" in response.headers.get("content-type", "")
    body = response.json() if json_body and response.content else None
    if isinstance(body, list):
        return f"list of {len(body)}"
    if not isinstance(body, dict):
        return None
    if response.status_code >= 400 and "errorCode" in body:
        return f"errorCode={body['errorCode']!r} {body.get('errorSummary')!r}"
    if response.status_code >= 400 and "error" in body:  # OAuth/DPoP error
        return f"error={body['error']!r} {body.get('error_description')!r}"
    return f"id={body.get('id')!r}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Step 0.5 Okta dev-org spike helpers")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("keygen")
    p.add_argument("--out", required=True, help="private key path (outside the repo)")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("discover")
    p.add_argument("--issuer", required=True)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("user-token")
    p.add_argument("--issuer", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--scope", default="openid okta-mcp")
    p.add_argument("--resource", help="RFC 8707 resource (MCP_PUBLIC_URL)")
    p.add_argument("--no-resource-on-token", action="store_true")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--redirect-host", choices=["127.0.0.1", "localhost"], default="127.0.0.1")
    p.set_defaults(func=cmd_user_token)

    p = sub.add_parser("service")
    p.add_argument("--org", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--kid", required=True)
    p.add_argument("--scopes", default="okta.users.read okta.groups.read")
    p.add_argument("--no-dpop", action="store_true")
    p.add_argument("--path", action="append", help="GET this path instead (repeatable)")
    p.set_defaults(func=cmd_service)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
