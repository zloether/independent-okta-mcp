"""Committed fixtures name only reserved hosts, mail domains and IPs (design §14, AGENTS.md).

The rules here are written independently of scripts/fixturelib.py, which produces fixtures, so
a bug in one doesn't hide in the other. sanitize-fixture.py runs `violations` on its output.
"""

import ipaddress
import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

ORG_HOSTS = frozenset({"example.okta.com", "example-admin.okta.com"})
LOOPBACK = frozenset({"localhost", "127.0.0.1", "[::1]"})
RESERVED = re.compile(r"^(?:[a-z0-9-]+\.)*example\.(?:com|net|org)$")
OKTA = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+\.)+(?:(?:okta|oktapreview|okta-emea|okta-gov|oktacdn|trexcloud)"
    r"\.com|okta\.mil)(?![\w-])",
    re.IGNORECASE,
)
URL_HOST = re.compile(
    r"[a-z][a-z0-9+.-]*://(?:[^/?#@\s\"']*@)?(\[[0-9A-Fa-f:.]+\]|[^/:?#\s\"'\\]+)", re.IGNORECASE
)
EMAIL = re.compile(r"[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _global_ip(text: str) -> bool:
    ip = _ip(text)
    return ip is not None and ip.is_global


def violations(text: str) -> list[str]:
    """`line: problem` for each disallowed host, mail domain or public IP in `text`."""
    found: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        for domain in EMAIL.findall(line):
            if not RESERVED.match(domain.lower()):
                found.append(f"{n}: mail domain {domain}")
        for host in URL_HOST.findall(line):
            h = host.lower()
            if h in ORG_HOSTS or h in LOOPBACK or RESERVED.match(h) or _ip(h.strip("[]")):
                continue  # An IP host is left to the IP rule below.
            found.append(f"{n}: host {host}")
        for host in OKTA.findall(line):
            if host.lower() not in ORG_HOSTS:
                found.append(f"{n}: Okta host {host}")
        for ip in IPV4.findall(line) + IPV6.findall(line):
            if _global_ip(ip):
                found.append(f"{n}: public IP {ip}")
    return found


def fixture_files() -> list[Path]:
    return sorted(
        p
        for p in FIXTURES.rglob("*")
        if p.is_file() and p.suffix != ".py" and "__pycache__" not in p.parts
    )


def test_fixtures_exist() -> None:
    assert fixture_files(), "tests/fixtures/ is empty: did gen-fixtures.py run?"


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fixture_is_clean(path: Path) -> None:
    assert violations(path.read_text()) == []


CLEAN = """
{"login": "alice@example.com", "other": "bob@mail.example.org", "n": "c@example.net",
 "href": "https://example.okta.com/api/v1/users/00u1", "admin": "https://example-admin.okta.com/",
 "idp": "https://idp.example.com/sso", "dev": "http://localhost:8080/cb", "lo": "http://127.0.0.1/",
 "zone": ["203.0.113.4/32", "198.51.100.0-198.51.100.9", "192.0.2.1", "10.0.0.0/8", "0.0.0.0/0"],
 "v6": ["2001:db8::1/128", "::1", "fe80::1"], "at": "2015-02-06T10:11:28.000Z",
 "mac": "aa:bb:cc:dd:ee:ff", "ip_url": "http://203.0.113.9:8080/x", "v6_url": "http://[::1]/"}
"""


def test_reserved_values_pass() -> None:
    assert violations(CLEAN) == []


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ('"login": "jane.doe@acme-corp.test"', "mail domain acme-corp.test"),
        ('"e": "x@example.com.evil.test"', "mail domain example.com.evil.test"),
        ('"href": "https://dev-000000.okta.com/api/v1/users"', "host dev-000000.okta.com"),
        ('"href": "https://dev-000000.okta.com/api/v1/users"', "Okta host dev-000000.okta.com"),
        ('"sub": "acme.oktapreview.com"', "Okta host acme.oktapreview.com"),
        ('"logo": "https://ok12static.oktacdn.com/a.png"', "Okta host ok12static.oktacdn.com"),
        ('"admin": "acme-admin.okta-emea.com"', "Okta host acme-admin.okta-emea.com"),
        ('"href": "https://login.acme-corp.test/sso"', "host login.acme-corp.test"),
        ('"href": "https://notexample.com/"', "host notexample.com"),
        ('"gateway": "8.8.4.4/32"', "public IP 8.8.4.4"),
        ('"ip": "2606:4700::1111"', "public IP 2606:4700::1111"),
        ('"href": "http://8.8.4.4/"', "public IP 8.8.4.4"),
    ],
)
def test_unreserved_values_fail(text: str, kind: str) -> None:
    assert f"1: {kind}" in violations(text)
