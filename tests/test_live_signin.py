"""The login-failure checks' sign-in driver (`tests/live/_signin.py`), offline: it posts only
to the org, carries the state handle forward, picks the TOTP authenticator from Okta's form,
and never puts the password in what it returns or raises."""

import json
from typing import Any

import httpx2
import pytest
from live._signin import (
    PASSWORD_KEY,
    REDIRECT_URI,
    TOTP_KEY,
    Signin,
    SigninError,
    choice,
    outcome,
    wrong_code,
)

pytestmark = pytest.mark.anyio

ORG = "https://example.okta.com"
PASSWORD = "correct horse battery staple"  # noqa: S105 - a fake, checked never to be sent wrongly


def _form(name: str, *fields: str, href: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "href": href or f"{ORG}/idp/idx/{name}",
        "method": "POST",
        "value": [{"name": f} for f in fields] + [{"name": "stateHandle", "value": "s"}],
    }


_ENROLLMENTS = {
    "authenticatorEnrollments": {
        "value": [{"key": PASSWORD_KEY, "id": "aut-pw"}, {"key": TOTP_KEY, "id": "aut-totp"}]
    }
}


def _reply(state: str, *forms: dict[str, Any], keys: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {
        "stateHandle": state,
        "remediation": {"value": list(forms)},
        **_ENROLLMENTS,
    }
    if keys:
        out["messages"] = {"value": [{"i18n": {"key": k}, "message": "x"} for k in keys]}
    return out


_TOTP_SELECT = {
    "name": "select-authenticator-authenticate",
    "href": f"{ORG}/idp/idx/challenge",
    "value": [
        {
            "name": "authenticator",
            "options": [
                {
                    "label": "Password",
                    "relatesTo": "$.authenticatorEnrollments.value[0]",
                    "value": {
                        "form": {
                            "value": [
                                {"name": "id", "value": "aut-pw"},
                                {"name": "methodType", "value": "password"},
                            ]
                        }
                    },
                },
                {
                    # A label that isn't "Google Authenticator": matched by key, not label.
                    "label": "Authenticator app (TOTP)",
                    "relatesTo": "$.authenticatorEnrollments.value[1]",
                    "value": {
                        "form": {
                            "value": [
                                {"name": "id", "value": "aut-totp"},
                                {"name": "methodType", "value": "otp"},
                            ]
                        }
                    },
                },
            ],
        },
        {"name": "stateHandle", "value": "s"},
    ],
}


class Okta:
    """Answers IDX calls from a script keyed by path, recording every request."""

    def __init__(self, replies: dict[str, list[dict[str, Any]]]) -> None:
        self.replies = replies
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/oauth2/v1/interact":
            return httpx2.Response(200, json={"interaction_handle": "ih"})
        queue = self.replies[path]
        return httpx2.Response(200 if len(queue) > 1 else 401, json=queue.pop(0))

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.url.path.startswith("/idp/")]


async def _run(okta: Okta, fn: str, *args: Any) -> Any:
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(okta)) as http:
        return await getattr(Signin(http, ORG, "u@example.com", PASSWORD), fn)(*args)


async def test_identify_then_password() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier"))],
            "/idp/idx/identify": [_reply("s2", _form("challenge-authenticator", "credentials"))],
            "/idp/idx/challenge-authenticator": [
                _reply("s3", keys=("idx.unassigned.app",)),
            ],
        }
    )
    result = await _run(okta, "attempt", "0oaclient")
    assert result.messages == ["idx.unassigned.app"]
    interact = okta.requests[0]
    form = dict(httpx2.QueryParams(interact.content.decode()))
    assert form["client_id"] == "0oaclient"
    assert form["code_challenge_method"] == "S256"
    assert form["redirect_uri"] == REDIRECT_URI
    introspect, identify, challenge = okta.bodies()
    assert introspect == {"interactionHandle": "ih"}
    assert identify == {"identifier": "u@example.com", "stateHandle": "s1"}
    assert challenge == {"credentials": {"passcode": PASSWORD}, "stateHandle": "s2"}
    assert all(r.url.host == "example.okta.com" for r in okta.requests)


async def test_identify_with_credentials_in_one_step() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier", "credentials"))],
            "/idp/idx/identify": [_reply("s2", keys=("errors.E0000004",))],
        }
    )
    result = await _run(okta, "attempt", "0oaclient")
    assert result.messages == ["errors.E0000004"]
    assert okta.bodies()[1]["credentials"] == {"passcode": PASSWORD}


async def test_refused_at_identify_sends_no_password() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier"))],
            "/idp/idx/identify": [_reply("s2", keys=("idx.deny",))],
        }
    )
    await _run(okta, "attempt", "0oaclient")
    assert PASSWORD not in "".join(r.content.decode() for r in okta.requests)


async def test_wrong_totp_picks_the_totp_option() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier"))],
            "/idp/idx/identify": [_reply("s2", _form("challenge-authenticator", "credentials"))],
            "/idp/idx/challenge-authenticator": [
                _reply("s3", _TOTP_SELECT),
                _reply("s5", keys=("errors.E0000068",)),
            ],
            "/idp/idx/challenge": [_reply("s4", _form("challenge-authenticator", "credentials"))],
        }
    )
    result = await _run(okta, "wrong_totp", "0oaclient")
    assert result.messages == ["errors.E0000068"]
    select, code = okta.bodies()[3:]
    assert select == {"authenticator": {"id": "aut-totp", "methodType": "otp"}, "stateHandle": "s3"}
    passcode = code["credentials"]["passcode"]
    assert len(passcode) == 6 and passcode.isdigit() and code["stateHandle"] == "s4"


async def test_wrong_passwords_never_send_the_real_one() -> None:
    challenge = _reply("s2", _form("challenge-authenticator", "credentials"))
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier"))] * 4,
            "/idp/idx/identify": [challenge] * 4,
            "/idp/idx/challenge-authenticator": [_reply("s3")] * 4,
        }
    )
    results = await _run(okta, "wrong_passwords", "0oaclient", 3)
    assert len(results) == 3
    assert sum(r.url.path == "/oauth2/v1/interact" for r in okta.requests) == 3
    assert PASSWORD not in "".join(r.content.decode() for r in okta.requests)


async def test_form_posting_off_the_org_is_refused() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [
                _reply("s1", _form("identify", "identifier", href="https://evil.example.com/x"))
            ],
        }
    )
    with pytest.raises(SigninError, match="off the org") as e:
        await _run(okta, "attempt", "0oaclient")
    assert PASSWORD not in str(e.value)
    assert all(r.url.host == "example.okta.com" for r in okta.requests)


async def test_missing_form_names_what_was_offered() -> None:
    okta = Okta({"/idp/idx/introspect": [_reply("s1", _form("redirect-idp"))]})
    with pytest.raises(SigninError, match=r"no 'identify' form; offered: \['redirect-idp'\]"):
        await _run(okta, "attempt", "0oaclient")


async def test_interact_refused() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"error": "invalid_client"})

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)) as http:
        with pytest.raises(SigninError, match="interact: HTTP 400"):
            await Signin(http, ORG, "u@example.com", PASSWORD).attempt("0oaclient")


def test_outcome_keeps_names_and_keys_only() -> None:
    reply = _reply("secret-state", _form("identify", "identifier"), keys=("errors.E0000004",))
    result = outcome(reply)
    assert result.remediations == ["identify"] and result.messages == ["errors.E0000004"]
    assert "secret-state" not in repr(result)


def test_choice_by_key() -> None:
    reply = _reply("s", _TOTP_SELECT)
    assert choice(reply, _TOTP_SELECT, TOTP_KEY) == {"id": "aut-totp", "methodType": "otp"}
    assert choice(reply, _TOTP_SELECT, PASSWORD_KEY) == {"id": "aut-pw", "methodType": "password"}
    assert choice(reply, _TOTP_SELECT, "okta_email") is None


def test_choice_ignores_a_relates_to_that_isnt_a_path() -> None:
    select = {
        "value": [
            {
                "name": "authenticator",
                "options": [
                    {
                        "relatesTo": TOTP_KEY,
                        "value": {"form": {"value": [{"name": "id", "value": "aut-x"}]}},
                    }
                ],
            }
        ]
    }
    assert choice(_reply("s"), select, TOTP_KEY) is None


async def test_password_picked_from_an_authenticator_list() -> None:
    okta = Okta(
        {
            "/idp/idx/introspect": [_reply("s1", _form("identify", "identifier"))],
            "/idp/idx/identify": [_reply("s2", _TOTP_SELECT)],
            "/idp/idx/challenge": [_reply("s3", _form("challenge-authenticator", "credentials"))],
            "/idp/idx/challenge-authenticator": [_reply("s4", keys=("errors.E0000004",))],
        }
    )
    result = await _run(okta, "attempt", "0oaclient")
    assert result.messages == ["errors.E0000004"]
    _, _, select, answer = okta.bodies()
    assert select["authenticator"] == {"id": "aut-pw", "methodType": "password"}
    assert answer == {"credentials": {"passcode": PASSWORD}, "stateHandle": "s3"}


async def test_interact_200_without_json() -> None:
    def page(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=b"<html>proxy</html>")

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(page)) as http:
        with pytest.raises(SigninError, match="interact: HTTP 200, no interaction handle"):
            await Signin(http, ORG, "u@example.com", PASSWORD).attempt("0oaclient")


def test_wrong_code_is_six_digits() -> None:
    assert all(len(c) == 6 and c.isdigit() for c in (wrong_code() for _ in range(50)))
