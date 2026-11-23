"""scripts/okta-probe.py: which admin role a scope needs, one GET per path (plan 8.3.1)."""

import logging
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from _load import load_script
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

probe = load_script("okta-probe")

ORG = "https://example.okta.com"
ACCESS_TOKEN = "eyJ.probe-access-token.sig"  # noqa: S105
SUMMARY = "Summary naming jane@example.com"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def key_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path_factory.mktemp("key") / "service.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def token_ok(scheme: str = "DPoP") -> httpx2.Response:
    body = {"access_token": ACCESS_TOKEN, "token_type": scheme, "expires_in": 3600}
    return httpx2.Response(200, json=body)


def okta(answers: dict[str, httpx2.Response], sent: list[httpx2.Request]) -> httpx2.MockTransport:
    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        if request.url.path == "/oauth2/v1/token":
            return token_ok("DPoP" if "DPoP" in request.headers else "Bearer")
        return answers[request.url.raw_path.decode()]

    return httpx2.MockTransport(handler)


def settings(key_file: Path, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "org": ORG,
        "client_id": "0oa1service0000000000",
        "key_file": key_file,
        "key_id": "kid1",
        "scopes": frozenset({"okta.users.read", "okta.profileMappings.read"}),
        "dpop": True,
    }
    return probe.Settings(**(values | overrides))


@pytest.mark.anyio
async def test_reports_status_code_and_shape_only(key_file: Path) -> None:
    sent: list[httpx2.Request] = []
    answers = {
        "/api/v1/users?limit=1": httpx2.Response(200, json=[{"id": "00u1", "profile": {}}]),
        "/api/v1/mappings/prm1": httpx2.Response(
            403, json={"errorCode": "E0000006", "errorSummary": SUMMARY}
        ),
        "/api/v1/mappings": httpx2.Response(200, json={"id": "prm1", "secret": "x"}),
    }
    results = await probe.run(
        settings(key_file),
        ["/api/v1/users?limit=1", "/api/v1/mappings/prm1", "/api/v1/mappings"],
        transport=okta(answers, sent),
    )
    lines = [probe.describe(r) for r in results]
    assert lines == [
        "GET /api/v1/users?limit=1 -> 200 list of 1",
        "GET /api/v1/mappings/prm1 -> 403 E0000006",
        "GET /api/v1/mappings -> 200 object",
    ]
    # Never Okta's free text or field values (the object's `id` and `secret` aren't shown).
    assert not any(SUMMARY in line or "secret" in line or "00u1" in line for line in lines)
    # Only GETs reach the resource endpoints, with a DPoP-bound token and a proof each.
    resource = [r for r in sent if r.url.path != "/oauth2/v1/token"]
    assert {r.method for r in resource} == {"GET"}
    assert all(r.headers["Authorization"] == f"DPoP {ACCESS_TOKEN}" for r in resource)
    proofs = [jwt.decode(r.headers["DPoP"], options={"verify_signature": False}) for r in resource]
    assert [p["htm"] for p in proofs] == ["GET"] * 3


@pytest.mark.anyio
async def test_error_code_must_be_okta_shaped(key_file: Path) -> None:
    sent: list[httpx2.Request] = []
    answers = {
        "/api/v1/a": httpx2.Response(403, json={"errorCode": "free text, a@example.com"}),
        "/api/v1/b": httpx2.Response(401, json={"error": "invalid_dpop_proof", "x": 1}),
        "/api/v1/c": httpx2.Response(404, text="not json"),
    }
    results = await probe.run(
        settings(key_file), ["/api/v1/a", "/api/v1/b", "/api/v1/c"], transport=okta(answers, sent)
    )
    assert [probe.describe(r) for r in results] == [
        "GET /api/v1/a -> 403 -",
        "GET /api/v1/b -> 401 invalid_dpop_proof",
        "GET /api/v1/c -> 404 -",
    ]


@pytest.mark.anyio
async def test_retries_once_on_a_resource_nonce(key_file: Path) -> None:
    sent: list[httpx2.Request] = []
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        sent.append(request)
        if request.url.path == "/oauth2/v1/token":
            return token_ok()
        calls += 1
        if calls == 1:
            return httpx2.Response(
                401,
                headers={"DPoP-Nonce": "n2", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'},
                json={"error": "use_dpop_nonce"},
            )
        return httpx2.Response(200, json=[])

    results = await probe.run(
        settings(key_file), ["/api/v1/users"], transport=httpx2.MockTransport(handler)
    )
    assert [probe.describe(r) for r in results] == ["GET /api/v1/users -> 200 list of 0"]
    last = jwt.decode(sent[-1].headers["DPoP"], options={"verify_signature": False})
    assert last["nonce"] == "n2"


@pytest.mark.anyio
async def test_bearer_without_dpop(key_file: Path) -> None:
    sent: list[httpx2.Request] = []
    answers = {"/api/v1/sessions/x": httpx2.Response(404, json={"errorCode": "E0000007"})}
    results = await probe.run(
        settings(key_file, dpop=False), ["/api/v1/sessions/x"], transport=okta(answers, sent)
    )
    assert [probe.describe(r) for r in results] == ["GET /api/v1/sessions/x -> 404 E0000007"]
    assert sent[-1].headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert "DPoP" not in sent[-1].headers


@pytest.mark.parametrize(
    "path",
    [
        "api/v1/users",  # not absolute
        "//evil.example.com/api/v1/users",  # scheme-relative
        "/oauth2/v1/token",  # not the Management API
        "/api/v1/users\n",
        "/api/v1/../../oauth2/v1/clients",
        "https://evil.example.com/api/v1/users",
        "/api/v1/..#x",  # httpx2 would send `/api`
        "/api/v1/users#frag",
    ],
)
def test_refuses_paths_off_the_management_api(path: str) -> None:
    with pytest.raises(probe.ProbeError):
        probe.check_path(path)


@pytest.mark.anyio
async def test_a_repeated_path_reports_its_own_answer(key_file: Path) -> None:
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        if request.url.path == "/oauth2/v1/token":
            return token_ok()
        calls += 1
        if calls == 1:
            return httpx2.Response(200, json=[])
        raise httpx2.ConnectError("refused")

    results = await probe.run(
        settings(key_file),
        ["/api/v1/users", "/api/v1/users"],
        transport=httpx2.MockTransport(handler),
    )
    assert [probe.describe(r) for r in results] == [
        "GET /api/v1/users -> 200 list of 0",
        "GET /api/v1/users -> - no answer",
    ]


@pytest.mark.parametrize(
    "org",
    [
        "http://example.okta.com",
        "https://example.okta.com/oauth2/default",
        "https://user@example.okta.com",
        "https://example.okta.com?x=1",
        "example.okta.com",
    ],
)
def test_refuses_an_org_url_that_is_not_an_https_origin(org: str) -> None:
    with pytest.raises(probe.ProbeError):
        probe.check_org(org)


def test_org_url_trailing_slash_is_dropped() -> None:
    assert probe.check_org("https://example.okta.com/") == ORG


@pytest.mark.anyio
async def test_token_error_is_reported_without_the_body(key_file: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path == "/oauth2/v1/token"
        return httpx2.Response(401, json={"error": "invalid_client", "error_description": SUMMARY})

    with pytest.raises(probe.ProbeError) as e:
        await probe.run(
            settings(key_file), ["/api/v1/users"], transport=httpx2.MockTransport(handler)
        )
    assert "invalid_client" in str(e.value)
    assert SUMMARY not in str(e.value)


def test_main_exit_codes_and_output(
    key_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = {
        "/api/v1/users?limit=1": httpx2.Response(200, json=[]),
        "/api/v1/mappings/prm1": httpx2.Response(403, json={"errorCode": "E0000006"}),
    }
    sent: list[httpx2.Request] = []
    monkeypatch.setattr(probe, "TRANSPORT", okta(answers, sent))
    env = {
        "OKTA_ORG_URL": ORG,
        "OKTA_CLIENT_ID": "0oa1service0000000000",
        "OKTA_PRIVATE_KEY_FILE": str(key_file),
        "OKTA_KEY_ID": "kid1",
        "OKTA_SCOPES": "okta.users.read okta.profileMappings.read",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("OKTA_DPOP", raising=False)

    assert probe.main([]) == 0  # default path
    assert capsys.readouterr().out.splitlines()[-1] == "GET /api/v1/users?limit=1 -> 200 list of 0"

    assert probe.main(["/api/v1/users?limit=1", "/api/v1/mappings/prm1"]) == 1
    out = capsys.readouterr().out
    assert "GET /api/v1/mappings/prm1 -> 403 E0000006" in out
    assert ACCESS_TOKEN not in out

    assert probe.main(["/oauth2/v1/token"]) == 2
    assert "Management API" in capsys.readouterr().err

    monkeypatch.delenv("OKTA_CLIENT_ID")
    assert probe.main([]) == 2
    assert "OKTA_CLIENT_ID" in capsys.readouterr().err
    # The quieted client logger is put back, for whatever runs next in the process.
    assert logging.getLogger("okta_mcp").level == logging.NOTSET


def test_never_sends_anything_but_get() -> None:
    # Read-only invariant (AGENTS.md): the probe's only Okta request is `OktaClient.get`.
    assert probe.__file__
    text = Path(probe.__file__).read_text()
    for call in (".post(", ".put(", ".patch(", ".delete(", ".request(", ".send(", ".stream("):
        assert call not in text
