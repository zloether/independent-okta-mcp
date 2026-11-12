#!/usr/bin/env python3
"""Sanitize a recorded dev-org response into a committed fixture (design §14).

    uv run python scripts/sanitize-fixture.py RECORDING.json --operation listJwk \\
        --out tests/fixtures/<domain>/<command>.json [--replace OLD=NEW ...]

RECORDING.json is the raw response body as Okta returned it. The output is the fixture file
gen-fixtures.py reads: `{"source": "recorded", "operation": ..., "body": ...}`, which it never
overwrites. Rewritten, consistently across the file (the same input always maps to the same
output, so IDs inside links still match the `id` they point to):

- hosts, mail addresses and IPs, as for generated fixtures (fixturelib.py): the org and any
  Okta host become example.okta.com, other hosts host-N.example.com, addresses
  user-N@example.com, public IPs documentation addresses;
- the org's subdomain label (`dev-123456`) wherever it appears on its own, e.g. `subdomain`;
- Okta IDs (3-character prefix + 17 base-62 characters): the prefix is kept, the rest numbered;
- values of person fields (names, phones, addresses, employee data) at any depth;
- every `--replace OLD=NEW` string, before anything else, for what no rule can know (a company
  name, a custom domain, a group or app named after a person).

What no rule catches still needs a read before committing: free text in `description` or
`name` fields, and secrets the server's scrub.yaml would redact anyway. The script prints
what it rewrote by kind and exits 1, writing nothing, when the result still fails the rules
tests/test_fixture_hygiene.py enforces.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

from fixturelib import OKTA_FAMILY, Neutralizer, okta_labels, walk_strings

OKTA_ID = re.compile(
    r"(?<![A-Za-z0-9])(?P<prefix>[0-9a-z]{3})(?P<body>[0-9A-Za-z]{17})(?![A-Za-z0-9])"
)
"""Okta's object IDs. Only a run with a digit in it counts, so a 20-letter word isn't one."""

PERSON_FIELDS = {
    k.casefold(): label
    for label, keys in {
        "Given": ("firstName", "givenName", "middleName", "nickName", "honorificPrefix"),
        "Family": ("lastName", "familyName", "honorificSuffix"),
        "Person": ("displayName", "fullName", "manager", "title"),
        "user": ("login", "email", "secondEmail", "alternateId", "username", "userName"),
        "phone": ("mobilePhone", "primaryPhone", "phoneNumber", "phone"),
        "address": ("streetAddress", "postalAddress", "city", "state", "zipCode", "postalCode"),
        "employee": ("employeeNumber", "managerId", "costCenter", "department", "division"),
        "org": ("organization", "companyName", "company"),
    }.items()
    for k in keys
}
"""Profile and log-actor fields that hold a person's data. Matched case-insensitively at any
depth, string values only."""


class Sanitizer:
    def __init__(self, replace: list[tuple[str, str]] | None = None) -> None:
        self.replace = replace or []
        self.neutral = Neutralizer()
        self.ids: dict[str, str] = {}
        self.people: dict[tuple[str, str], str] = {}
        self.labels: set[str] = set()

    def __call__(self, value: Any) -> Any:
        if self.replace:
            value = walk_strings(value, self._replace)
        self.labels = _org_labels(value)
        value = self._people(value)
        value = walk_strings(value, self._ids)
        value = self.neutral(value)
        return walk_strings(value, self._labels)

    def _replace(self, s: str) -> str:
        for old, new in self.replace:
            s = s.replace(old, new)
        return s

    def _people(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {k: self._people(v, k) for k, v in cast(dict[str, Any], value).items()}
        if isinstance(value, list):
            return [self._people(v, key) for v in cast(list[Any], value)]
        if isinstance(value, str) and key is not None and value:
            label = PERSON_FIELDS.get(key.casefold())
            if label is not None:
                return self._person(label, value)
        return value

    def _person(self, label: str, value: str) -> str:
        if label == "user" and "@" in value:
            return self.neutral.text(value)  # One numbering for addresses wherever they appear.
        k = (label, value.casefold())
        if k not in self.people:
            n = sum(1 for lbl, _ in self.people if lbl == label) + 1
            self.people[k] = {
                "user": f"login-{n}",
                "phone": f"+1 555-01{n % 100:02d}",  # 555-0100..0199: fictional (NANPA)
            }.get(label, f"{label} {n}")
        return self.people[k]

    def _ids(self, s: str) -> str:
        return OKTA_ID.sub(self._id, s)

    def _id(self, m: re.Match[str]) -> str:
        whole = m.group(0)
        if not any(c.isdigit() for c in whole):
            return whole
        if whole not in self.ids:
            n = len(self.ids) + 1
            self.ids[whole] = f"{m.group('prefix')}EXAMPLE{n:010d}"
        return self.ids[whole]

    def _labels(self, s: str) -> str:
        for label in self.labels:
            s = re.sub(rf"(?<![\w-]){re.escape(label)}(?![\w-])", "example", s, flags=re.I)
        return s

    def summary(self) -> dict[str, int]:
        return {
            "ids": len(self.ids),
            "person values": len(self.people),
            "hosts": len(self.neutral.hosts),
            "mail addresses": len(self.neutral.emails),
            "ips": len(self.neutral.ips),
            "org labels": len(self.labels),
        }


_HOSTS = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w-])", re.I)


def _org_labels(value: Any) -> set[str]:
    """Subdomain labels of every Okta org host in `value`."""
    found: set[str] = set()

    def visit(s: str) -> str:
        for host in _HOSTS.findall(s):
            if OKTA_FAMILY.match(host) and (label := okta_labels(host)):
                found.add(label)
        return s

    walk_strings(value, visit)
    return found


def _pair(text: str) -> tuple[str, str]:
    old, sep, new = text.partition("=")
    if not sep or not old:
        raise argparse.ArgumentTypeError(f"expected OLD=NEW, got {text!r}")
    return old, new


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("recording", type=Path)
    parser.add_argument("--operation", required=True, help="the Okta operationId recorded")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replace", type=_pair, action="append", default=[], metavar="OLD=NEW")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
    from test_fixture_hygiene import violations  # The test's own rules.

    sanitizer = Sanitizer(args.replace)
    doc = {
        "source": "recorded",
        "operation": args.operation,
        "body": sanitizer(json.loads(args.recording.read_text())),
    }
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    for kind, n in sanitizer.summary().items():
        print(f"rewrote {n} {kind}")
    if found := violations(text):
        for v in found:
            print(f"still fails hygiene: {v}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
