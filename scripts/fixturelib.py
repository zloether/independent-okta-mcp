"""What a committed fixture may contain (design §14); shared by the two fixture scripts.

A fixture names only reserved hosts and mail domains: `example.okta.com` (and its `-admin`
host) for the Okta org, RFC 2606 `example.com`/`.net`/`.org` and their subdomains for anything
else, plus loopback. Public IP addresses become RFC 5737 / RFC 3849 documentation addresses.

`Neutralizer` rewrites every string of a JSON value to that rule, consistently within one
instance: the same host, address or IP always maps to the same replacement, so links and
references inside one fixture still line up. tests/test_fixture_hygiene.py checks the result
with its own, independent rules.
"""

import ipaddress
import re
from collections.abc import Callable
from typing import Any, cast

ORG_HOST = "example.okta.com"
ADMIN_HOST = "example-admin.okta.com"

OKTA_FAMILY = re.compile(
    r"^(?:[a-z0-9-]+\.)*(?:okta|oktapreview|okta-emea|okta-gov|oktacdn|trexcloud)\.com$"
    r"|^(?:[a-z0-9-]+\.)*okta\.mil$",
    re.IGNORECASE,
)
"""Okta's own domains: an org, its admin host, a cell's CDN. All of them map to the example org."""

_RESERVED = re.compile(r"^(?:[a-z0-9-]+\.)*example\.(?:com|net|org)$", re.IGNORECASE)
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "[::1]"})

_PLACEHOLDER = re.compile(r"\$?\{yourOktaDomain\}(?:\.okta\.com)?", re.IGNORECASE)
"""The spec's examples write the org as `{yourOktaDomain}`, or `${...}`, or `{...}.okta.com`."""

_URL = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<userinfo>[^/?#@\s\"']*@)?(?P<host>\[[0-9A-Fa-f:.]+\]|[^/:?#\s\"'\\]+)",
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r"(?<![\w.+-])(?P<local>[\w.+-]+)@(?P<domain>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
)
_BARE_OKTA = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+\.)+"
    r"(?:okta|oktapreview|okta-emea|okta-gov|oktacdn|trexcloud)\.com(?![\w-])"
    r"|(?<![\w.-])(?:[a-z0-9-]+\.)+okta\.mil(?![\w-])",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")


def is_reserved_host(host: str) -> bool:
    host = host.lower()
    return host in (ORG_HOST, ADMIN_HOST) or host in _LOOPBACK or bool(_RESERVED.match(host))


def is_reserved_mail_domain(domain: str) -> bool:
    return bool(_RESERVED.match(domain))


def _okta_host(host: str) -> str:
    label = host.split(".")[0].lower()
    return ADMIN_HOST if label.endswith("-admin") else ORG_HOST


def okta_labels(host: str) -> str | None:
    """The org's subdomain label of an Okta host (`dev-123456` of `dev-123456-admin.okta.com`),
    or None for anything else, including the example org."""
    host = host.lower()
    if not OKTA_FAMILY.match(host) or is_reserved_host(host) or host.count(".") != 2:
        return None
    label = host.split(".")[0].removesuffix("-admin")
    return None if label in _PUBLIC_LABELS else label


_PUBLIC_LABELS = frozenset({"www", "developer", "help", "login", "support", "status", "trust"})
"""Okta's public sites, not an org; their names say nothing about the recorded org."""


class Neutralizer:
    """Rewrites hosts, mail addresses and IP addresses in every string of a JSON value."""

    def __init__(self) -> None:
        self.hosts: dict[str, str] = {}
        self.emails: dict[str, str] = {}
        self.ips: dict[str, str] = {}

    def __call__(self, value: Any) -> Any:
        return walk_strings(value, self.text)

    def text(self, s: str) -> str:
        s = _PLACEHOLDER.sub(ORG_HOST, s)
        s = _URL.sub(self._url, s)
        s = _EMAIL.sub(self._email, s)
        s = _BARE_OKTA.sub(lambda m: _okta_host(m.group(0)), s)
        s = _IPV4.sub(self._ipv4, s)
        return _IPV6.sub(self._ipv6, s)

    def host(self, host: str) -> str:
        lower = host.lower()
        if is_reserved_host(lower):
            return host
        if OKTA_FAMILY.match(lower):
            return _okta_host(lower)
        if _ip(lower.strip("[]")) is not None:
            return host  # The IP rules below rewrite it.
        if lower not in self.hosts:
            self.hosts[lower] = f"host-{len(self.hosts) + 1}.example.com"
        return self.hosts[lower]

    def _url(self, m: re.Match[str]) -> str:
        userinfo = m.group("userinfo")
        if userinfo:  # Credentials or a person's name in a URL: never kept.
            userinfo = "user@"
        return f"{m.group('scheme')}{userinfo or ''}{self.host(m.group('host'))}"

    def _email(self, m: re.Match[str]) -> str:
        address = m.group(0)
        if is_reserved_mail_domain(m.group("domain")):
            return address
        key = address.lower()
        if key not in self.emails:
            self.emails[key] = f"user-{len(self.emails) + 1}@example.com"
        return self.emails[key]

    def _ipv4(self, m: re.Match[str]) -> str:
        ip = _ip(m.group(0))
        if ip is None or not ip.is_global:
            return m.group(0)
        key = str(ip)
        if key not in self.ips:
            n = len([k for k in self.ips if ":" not in k])
            # 203.0.113.0/24, then 198.51.100.0/24, then 192.0.2.0/24 (RFC 5737).
            net = ("203.0.113", "198.51.100", "192.0.2")[min(n // 254, 2)]
            self.ips[key] = f"{net}.{n % 254 + 1}"
        return self.ips[key]

    def _ipv6(self, m: re.Match[str]) -> str:
        ip = _ip(m.group(0))
        if ip is None or ip.version != 6 or not ip.is_global:
            return m.group(0)
        key = str(ip)
        if key not in self.ips:
            n = len([k for k in self.ips if ":" in k])
            self.ips[key] = f"2001:db8::{n + 1:x}"  # RFC 3849
        return self.ips[key]


def _ip(s: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def walk_strings(value: Any, fn: Callable[[str], str]) -> Any:
    """`value` with `fn` applied to every string value. Keys are left as they are."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: walk_strings(v, fn) for k, v in cast(dict[str, Any], value).items()}
    if isinstance(value, list):
        return [walk_strings(v, fn) for v in cast(list[Any], value)]
    return value
