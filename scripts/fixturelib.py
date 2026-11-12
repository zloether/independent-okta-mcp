"""What a committed fixture may contain (design §14); shared by the two fixture scripts.

A fixture names only reserved hosts and mail domains (AGENTS.md): `example.okta.com` (and its
`-admin` host) for the Okta org, `example.com` and its subdomains for anything else, plus
loopback. Public IP addresses become RFC 5737 / RFC 3849 documentation addresses.

`Neutralizer` rewrites every string of a JSON value to that rule, consistently within one
instance: the same host, address or IP always maps to the same replacement, so links and
references inside one fixture still line up. tests/test_fixture_hygiene.py checks the result
with its own, independent rules.
"""

import hashlib
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

_RESERVED = re.compile(r"^(?:[a-z0-9-]+\.)*example\.com$", re.IGNORECASE)
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
_BARE_HOST = re.compile(r"^(?P<host>(?:[a-z0-9-]+\.)+[a-z0-9-]+)(?P<port>:\d+)?$", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")


BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

HOST_KEY_SUFFIXES = ("domain", "domains", "host", "hosts", "hostname", "hostnames", "fqdn")
"""A key ending in one of these (`domain`, `emailDomain`, `trustDomain`, `domains`) holds bare
hostnames (`host[:port]`), in a string or a list of them. Other bare hostnames can't be told
from dotted names such as scopes (`okta.users.read`)."""


def is_host_key(key: str) -> bool:
    return key.casefold().endswith(HOST_KEY_SUFFIXES)


def okta_id(seed: str, prefix: str = "00x") -> str:
    """An ID with Okta's shape (3-character prefix, 17 base-62 characters), the same for the
    same seed, so fixtures made at different times agree."""
    n = int.from_bytes(hashlib.sha256(seed.encode()).digest()[:16])
    body = ""
    for _ in range(17):
        n, r = divmod(n, 62)
        body += BASE62[r]
    return prefix + body


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
        self._taken: set[str] = set()
        """Documentation addresses already in the input, never handed out as a replacement."""

    def __call__(self, value: Any) -> Any:
        def note(s: str) -> str:
            for literal in _IPV4.findall(s) + _IPV6.findall(s):
                if (ip := _ip(literal)) is not None and not ip.is_global:
                    self._taken.add(str(ip))
            return s

        walk_strings(value, note)
        return self._walk(value, None)

    def _walk(self, value: Any, key: str | None) -> Any:
        if isinstance(value, dict):
            return {k: self._walk(v, k) for k, v in cast(dict[str, Any], value).items()}
        if isinstance(value, list):
            return [self._walk(v, key) for v in cast(list[Any], value)]
        if isinstance(value, str):
            if key is not None and is_host_key(key) and (m := _BARE_HOST.match(value)):
                # An IP host comes back unchanged from host(); text() rewrites it.
                return self.text(self.host(m.group("host"))) + (m.group("port") or "")
            return self.text(value)
        return value

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
            self.ips[key] = self._free(_IPV4_POOL, "IPv4")
        return self.ips[key]

    def _ipv6(self, m: re.Match[str]) -> str:
        ip = _ip(m.group(0))
        if ip is None or ip.version != 6 or not ip.is_global:
            return m.group(0)
        key = str(ip)
        if key not in self.ips:
            self.ips[key] = self._free(_IPV6_POOL, "IPv6")
        return self.ips[key]

    def _free(self, pool: tuple[str, ...], kind: str) -> str:
        """The first pool address neither handed out nor already in the input."""
        used = self._taken | set(self.ips.values())
        for address in pool:
            if address not in used:
                return address
        raise ValueError(f"more public {kind} addresses than documentation addresses")


# RFC 5737: 203.0.113.0/24, then 198.51.100.0/24, then 192.0.2.0/24; RFC 3849 for IPv6.
_IPV4_POOL = tuple(
    f"{net}.{n}" for net in ("203.0.113", "198.51.100", "192.0.2") for n in range(1, 255)
)
_IPV6_POOL = tuple(f"2001:db8::{n:x}" for n in range(1, 4096))


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
