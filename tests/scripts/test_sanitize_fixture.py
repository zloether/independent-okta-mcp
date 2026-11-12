import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from _load import load_script

sys.path.insert(0, str(Path(__file__).parents[1]))
from test_fixture_hygiene import violations

san = load_script("sanitize-fixture")

# A made-up dev-org recording: every value a real one would leak, in the places Okta puts them.
RECORDING: list[dict[str, Any]] = [
    {
        "id": "00u8abcdEFGH1234ijk5",
        "status": "ACTIVE",
        "profile": {
            "firstName": "Jane",
            "lastName": "Doe",
            "displayName": "Jane Doe",
            "login": "jane.doe@acme-corp.test",
            "email": "jane.doe@acme-corp.test",
            "secondEmail": None,
            "mobilePhone": "+1 206 555 7788",
            "streetAddress": "12 Real Street",
            "employeeNumber": "E-4411",
            "organization": "Acme Corp",
        },
        "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}},
        "_links": {
            "self": {"href": "https://dev-31337.okta.com/api/v1/users/00u8abcdEFGH1234ijk5"},
            "manager": {"href": "https://dev-31337-admin.okta.com/admin/user/00u8abcdEFGH1234ijk5"},
        },
    },
    {
        "id": "00u9zyxwVUTS9876rqp4",
        "profile": {
            "firstName": "Jane",
            "lastName": "Roe",
            "login": "jroe",
            "email": "JANE.DOE@acme-corp.test",
            "manager": "Jane Doe",
        },
        "lastLogin": {"ip": "8.8.4.4", "zone": "nzo1a2b3c4d5e6f7g8h9"},
        "_embedded": {"org": {"subdomain": "dev-31337", "website": "https://www.acme-corp.test"}},
        "notes": "Acme Corp contractor; see 00u8abcdEFGH1234ijk5",
    },
]


def sanitize(value: Any, replace: list[tuple[str, str]] | None = None) -> Any:
    return san.Sanitizer(replace)(value)


def test_unsanitized_recording_fails_hygiene() -> None:
    found = violations(json.dumps(RECORDING, indent=2))
    assert any("dev-31337.okta.com" in v for v in found)
    assert any("acme-corp.test" in v for v in found)
    assert any("8.8.4.4" in v for v in found)


def test_sanitized_recording_passes_hygiene() -> None:
    assert violations(json.dumps(sanitize(RECORDING), indent=2)) == []


OKTA_ID = re.compile(r"^[0-9a-z]{3}[0-9A-Za-z]{17}$")


def test_ids_are_remapped_consistently_and_keep_their_prefix() -> None:
    jane, roe = sanitize(RECORDING)
    a, b = jane["id"], roe["id"]
    assert OKTA_ID.match(a) and a.startswith("00u") and a != "00u8abcdEFGH1234ijk5"
    assert OKTA_ID.match(b) and a != b
    assert jane["_links"]["self"]["href"] == f"https://example.okta.com/api/v1/users/{a}"
    assert jane["_links"]["manager"]["href"].startswith("https://example-admin.okta.com/")
    assert roe["notes"].endswith(f"see {a}")
    assert roe["lastLogin"]["zone"].startswith("nzo")
    assert "nzo1a2b3c4d5e6f7g8h9" not in json.dumps(roe)


def test_ids_agree_across_separate_recordings() -> None:
    first = sanitize({"id": "00g1aaaaBBBBccccDDDD"})
    second = sanitize({"members": "/api/v1/groups/00g1aaaaBBBBccccDDDD/users"})
    assert second["members"] == f"/api/v1/groups/{first['id']}/users"


def test_manager_id_is_remapped_as_an_id() -> None:
    out = sanitize(
        [{"id": "00u1aaaaBBBBccccDDDD"}, {"profile": {"managerId": "00u1aaaaBBBBccccDDDD"}}]
    )
    assert out[1]["profile"]["managerId"] == out[0]["id"]
    assert sanitize({"managerId": "E-77"}) == {"managerId": "employee 1"}


def test_bare_host_keys_are_rewritten() -> None:
    out = sanitize(
        {"domain": "login.acme-corp.test", "app": {"domain": "acme"}, "host": "x.example.com"}
    )
    assert out == {
        "domain": "host-1.example.com",
        "app": {"domain": "acme"},
        "host": "x.example.com",
    }


def test_host_key_variants_are_rewritten() -> None:
    out = sanitize(
        {
            "host": "8.8.8.8",
            "hostname": "ldap.acme-corp.test:636",
            "emailDomain": "acme-corp.test",
            "domains": ["acme-corp.test", "ok.example.com"],
        }
    )
    assert out == {
        "host": "203.0.113.1",
        "hostname": "host-1.example.com:636",
        "emailDomain": "host-2.example.com",
        "domains": ["host-2.example.com", "ok.example.com"],
    }
    assert violations(json.dumps(out, indent=2)) == []


def test_replacement_ips_avoid_documentation_addresses_in_the_input() -> None:
    assert sanitize(["8.8.8.8", "203.0.113.1"]) == ["203.0.113.2", "203.0.113.1"]


def test_id_shaped_person_value_without_a_digit_is_still_replaced() -> None:
    assert sanitize({"city": "llanfairpwllgwyngyll"}) == {"city": "address 1"}


def test_too_many_values_fail_rather_than_collide() -> None:
    with pytest.raises(ValueError, match="phone"):
        sanitize([{"mobilePhone": f"+1 206 555 {i:04d}"} for i in range(100)])
    with pytest.raises(ValueError, match="IPv4"):
        sanitize([f"8.8.{i // 250}.{i % 250 + 1}" for i in range(763)])


def test_person_fields_are_replaced_consistently() -> None:
    jane, roe = sanitize(RECORDING)
    p, q = jane["profile"], roe["profile"]
    assert (p["firstName"], q["firstName"]) == ("Given 1", "Given 1")  # same value, same output
    assert (p["lastName"], q["lastName"]) == ("Family 1", "Family 2")
    assert p["displayName"] == q["manager"] == "Person 1"
    assert p["login"] == p["email"] == q["email"] == "user-1@example.com"
    assert q["login"] == "login-1"
    assert p["secondEmail"] is None
    assert p["mobilePhone"] == "+1 555-0101"
    assert p["streetAddress"] == "address 1"
    assert p["employeeNumber"] == "employee 1"
    assert p["organization"] == "org 1"
    assert jane["credentials"]["provider"] == {"type": "OKTA", "name": "OKTA"}


def test_hosts_ips_and_org_label() -> None:
    _, roe = sanitize(RECORDING)
    assert roe["lastLogin"]["ip"] == "203.0.113.1"
    assert roe["_embedded"]["org"] == {
        "subdomain": "example",
        "website": "https://host-1.example.com",
    }
    assert "Acme Corp" in roe["notes"]  # free text: only --replace knows the company name


def test_replace_runs_first() -> None:
    _, roe = sanitize(RECORDING, [("Acme Corp", "Example Co")])
    assert roe["notes"].startswith("Example Co contractor")


def test_twenty_letter_word_is_not_an_id() -> None:
    assert sanitize({"k": "abcdefghijklmnopqrst"}) == {"k": "abcdefghijklmnopqrst"}


def test_main_writes_recorded_fixture(tmp_path: Path) -> None:
    src = tmp_path / "raw.json"
    src.write_text(json.dumps(RECORDING))
    out = tmp_path / "fixtures" / "users" / "list.json"
    assert san.main([str(src), "--operation", "listUsers", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["source"] == "recorded" and doc["operation"] == "listUsers"
    assert violations(out.read_text()) == []


def test_bare_okta_host_in_free_text() -> None:
    assert sanitize({"note": "mirror at acme.okta.com"}) == {"note": "mirror at example.okta.com"}


def test_main_refuses_output_that_still_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Whatever the rules miss, the hygiene check on the output stops it being written.
    monkeypatch.setattr(san.Sanitizer, "__call__", lambda self, v: v)  # pyright: ignore
    src = tmp_path / "raw.json"
    src.write_text(json.dumps({"login": "jane@acme-corp.test"}))
    out = tmp_path / "out.json"
    assert san.main([str(src), "--operation", "x", "--out", str(out)]) == 1
    assert not out.exists()
    assert "still fails hygiene: 5: mail domain acme-corp.test" in capsys.readouterr().err


def test_bad_replace_pair() -> None:
    with pytest.raises(SystemExit):
        san.main(["r.json", "--operation", "x", "--out", "o.json", "--replace", "novalue"])
