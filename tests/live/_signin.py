"""Headless sign-ins that fail on purpose, for the login-failure live checks (plan 8.2.1, 9.1).

The one part of the live checks that changes state in Okta: each sign-in leaves System Log
events, a session attempt and, for the lockout case, a locked account that the seeded password
policy unlocks by itself. It uses the Identity Engine IDX API (`/oauth2/v1/interact`, then the
`remediation` forms Okta returns) as a browser would, with the test user's own password and the
seeded apps' public client IDs: no admin credential, and never the server's service app.

Nothing here prints or returns a password, passcode, interaction or state handle. What a caller
gets back is `Outcome`: remediation names and Okta's message keys, both fixed strings.
"""

import base64
import hashlib
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx2

ION = "application/ion+json; okta-version=1.0.0"
REDIRECT_URI = "http://localhost:8080/login/callback"
"""Registered on each seeded app and never followed: no sign-in here completes."""
_TOTP_KEYS = ("google_otp",)


class SigninError(Exception):
    """The flow couldn't go on: Okta's reply had no form the case needs. Names only."""


@dataclass
class Outcome:
    """What one attempt ended with: the remediations Okta offered next and its message keys."""

    remediations: list[str] = field(default_factory=list[str])
    messages: list[str] = field(default_factory=list[str])


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def outcome(reply: Mapping[str, Any]) -> Outcome:
    forms = reply.get("remediation", {}).get("value", [])
    names = [f["name"] for f in forms if isinstance(f, dict) and isinstance(f.get("name"), str)]
    keys: list[str] = []
    for m in reply.get("messages", {}).get("value", []):
        key = m.get("i18n", {}).get("key") if isinstance(m, dict) else None
        if isinstance(key, str):
            keys.append(key)
    return Outcome(names, keys)


def form(reply: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    for f in reply.get("remediation", {}).get("value", []):
        if isinstance(f, dict) and f.get("name") == name:
            return f
    return None


def fields(f: Mapping[str, Any]) -> set[str]:
    return {v["name"] for v in f.get("value", []) if isinstance(v, dict) and "name" in v}


def totp_choice(f: Mapping[str, Any]) -> dict[str, str] | None:
    """The `authenticator` value that picks a TOTP app from a `select-authenticator-authenticate`
    form, read from the option's own form (`id`, `methodType`), or None if none is offered."""
    for v in f.get("value", []):
        if not isinstance(v, dict) or v.get("name") != "authenticator":
            continue
        for option in v.get("options", []):
            inner = option.get("value", {}).get("form", {}).get("value", [])
            values = {
                i["name"]: i["value"]
                for i in inner
                if isinstance(i, dict) and isinstance(i.get("value"), str) and "name" in i
            }
            key = option.get("relatesTo", "")
            label = str(option.get("label", "")).lower()
            if "id" in values and (
                any(k in str(key) for k in _TOTP_KEYS) or "google authenticator" in label
            ):
                return {k: values[k] for k in ("id", "methodType") if k in values}
    return None


def wrong_code() -> str:
    """Six random digits. Not checked against the user's current code (no seed is held): about
    a one-in-a-million chance per run of a correct guess, which fails the case, never passes a
    wrong one."""
    return f"{secrets.randbelow(10**6):06d}"


class Signin:
    """One IDX transaction per `start`. `http` is a plain client; nothing here retries."""

    def __init__(self, http: httpx2.AsyncClient, org_url: str, login: str, password: str) -> None:
        self._http = http
        self._org = org_url.rstrip("/")
        self._login = login
        self._password = password

    async def _post(self, url: str, body: Mapping[str, Any]) -> dict[str, Any]:
        response = await self._http.post(
            url, json=dict(body), headers={"Content-Type": ION, "Accept": ION}
        )
        try:
            reply = response.json()
        except ValueError:
            raise SigninError(f"IDX reply to {url.rsplit('/', 1)[-1]} isn't JSON") from None
        if not isinstance(reply, dict):
            raise SigninError("IDX reply isn't an object")
        return reply

    async def _remediate(
        self, reply: Mapping[str, Any], name: str, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        f = form(reply, name)
        if f is None or not isinstance(f.get("href"), str):
            raise SigninError(f"no '{name}' form; offered: {outcome(reply).remediations}")
        if not str(f["href"]).startswith(self._org + "/"):
            raise SigninError(f"'{name}' form posts off the org")
        return await self._post(f["href"], {**values, "stateHandle": reply.get("stateHandle")})

    async def start(self, client_id: str) -> dict[str, Any]:
        _verifier, challenge = _pkce()
        response = await self._http.post(
            f"{self._org}/oauth2/v1/interact",
            data={
                "client_id": client_id,
                "scope": "openid",
                "redirect_uri": REDIRECT_URI,
                "state": secrets.token_urlsafe(16),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            headers={"Accept": "application/json"},
        )
        handle = response.json().get("interaction_handle") if response.status_code == 200 else None
        if not isinstance(handle, str):
            raise SigninError(f"interact: HTTP {response.status_code}, no interaction handle")
        return await self._post(f"{self._org}/idp/idx/introspect", {"interactionHandle": handle})

    async def password(self, client_id: str, password: str | None = None) -> dict[str, Any]:
        """Identify, then answer the password challenge (or send both at once where the
        identify form takes credentials). `password` defaults to the user's real one."""
        passcode = self._password if password is None else password
        reply = await self.start(client_id)
        identify = form(reply, "identify")
        if identify is not None and "credentials" in fields(identify):
            return await self._remediate(
                reply,
                "identify",
                {"identifier": self._login, "credentials": {"passcode": passcode}},
            )
        reply = await self._remediate(reply, "identify", {"identifier": self._login})
        if form(reply, "challenge-authenticator") is None:
            return reply  # refused at identify (not assigned, denied): nothing more to send
        return await self._remediate(
            reply, "challenge-authenticator", {"credentials": {"passcode": passcode}}
        )

    async def attempt(self, client_id: str) -> Outcome:
        """A sign-in with the right password, to an app that should refuse it."""
        return outcome(await self.password(client_id))

    async def wrong_totp(self, client_id: str) -> Outcome:
        reply = await self.password(client_id)
        select = form(reply, "select-authenticator-authenticate")
        if select is not None:
            choice = totp_choice(select)
            if choice is None:
                raise SigninError("no TOTP authenticator offered after the password")
            reply = await self._remediate(
                reply, "select-authenticator-authenticate", {"authenticator": choice}
            )
        reply = await self._remediate(
            reply, "challenge-authenticator", {"credentials": {"passcode": wrong_code()}}
        )
        return outcome(reply)

    async def wrong_passwords(self, client_id: str, attempts: int) -> list[Outcome]:
        """`attempts` sign-ins with a wrong password, each its own transaction."""
        results: list[Outcome] = []
        for _ in range(attempts):
            results.append(outcome(await self.password(client_id, secrets.token_urlsafe(18))))
        return results


def message_keys(outcomes: Sequence[Outcome]) -> list[str]:
    return sorted({k for o in outcomes for k in o.messages})
