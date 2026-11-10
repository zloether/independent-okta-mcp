import json
from pathlib import Path
from typing import Any

import pytest

from okta_mcp.exec.output import (
    REDACTED,
    ScrubError,
    ScrubRules,
    columns,
    load_scrub,
    pick,
    prune,
    render,
    scrub,
    strip_links,
)
from okta_mcp.registry.schema import InvalidArguments

RULES = load_scrub()
SECRET = "s3cr3t-value"  # noqa: S105
# Each shipped entry alone, so an entry another one also covers (`client_secret` covers both
# `…client_secret` chains) is still tested on its own.
ENTRIES = [pytest.param(ScrubRules((p,)), ".".join(p), id=".".join(p)) for p in RULES.paths] + [
    pytest.param(ScrubRules((), (p,)), ".".join(p), id="strings:" + ".".join(p))
    for p in RULES.strings
]


def nest(path: str, value: Any) -> dict[str, Any]:
    out: Any = value
    for key in reversed(path.split(".")):
        out = {key: out}
    return out


def assert_no_secret(item: Any, rules: ScrubRules) -> None:
    for cols in (None, ("_embedded",), tuple(item)):
        for links in (False, True):
            assert SECRET not in json.dumps(render(item, rules, links=links, cols=cols))


@pytest.mark.parametrize(("rules", "path"), ENTRIES)
def test_every_scrub_entry_is_redacted_at_root(rules: ScrubRules, path: str) -> None:
    item = {"id": "0oa1", **nest(path, SECRET)}
    out = render(item, rules, links=False, cols=None)
    assert pick(out, path) == REDACTED
    assert out["id"] == "0oa1"
    assert_no_secret(item, rules)


@pytest.mark.parametrize(("rules", "path"), ENTRIES)
def test_every_scrub_entry_is_redacted_nested_in_embedded_arrays(
    rules: ScrubRules, path: str
) -> None:
    item = {"_embedded": {"apps": [{"id": "0oa1"}, nest(path, SECRET)]}}
    assert_no_secret(item, rules)


@pytest.mark.parametrize(("rules", "path"), ENTRIES)
def test_every_scrub_entry_matches_case_insensitively(rules: ScrubRules, path: str) -> None:
    assert_no_secret(nest(path.upper(), SECRET), rules)


@pytest.mark.parametrize("path", [".".join(p) for p in RULES.paths])
def test_scrub_paths_replace_object_and_array_values(path: str) -> None:
    for value in ({"a": SECRET}, [SECRET], None):
        out = scrub(nest(path, value), RULES)
        assert pick(out, path) == REDACTED


@pytest.mark.parametrize("path", [".".join(p) for p in RULES.strings])
def test_scrub_strings_keep_non_string_values(path: str) -> None:
    for value in ({"rotation_type": "ROTATE"}, [1], None, 30, True):
        assert scrub(nest(path, value), ScrubRules((), RULES.strings)) == nest(path, value)


def test_strings_rule_still_scrubs_inside_a_kept_object() -> None:
    rules = ScrubRules((("secret",),), (("password",),))
    item = {"settings": {"password": {"secret": SECRET, "minLength": 8}}}
    assert scrub(item, rules) == {"settings": {"password": {"secret": REDACTED, "minLength": 8}}}


def test_chained_paths_match_alone() -> None:
    rules = ScrubRules((("a", "b", "c"),))
    assert scrub({"x": {"a": {"b": {"c": SECRET, "d": 1}}}}, rules) == {
        "x": {"a": {"b": {"c": REDACTED, "d": 1}}}
    }
    assert scrub({"a": {"a": {"b": {"c": SECRET}}}}, rules) == {"a": {"a": {"b": {"c": REDACTED}}}}
    assert scrub({"b": {"c": SECRET}, "c": SECRET}, rules) == {"b": {"c": SECRET}, "c": SECRET}


def test_chains_sharing_a_first_key_each_match() -> None:
    rules = ScrubRules((("a", "b"), ("a", "c")), (("a",),))
    assert scrub({"a": {"b": SECRET, "c": SECRET, "d": 1}}, rules) == {
        "a": {"b": REDACTED, "c": REDACTED, "d": 1}
    }
    assert scrub({"a": SECRET, "x": {"A": {"C": SECRET}}}, rules) == {
        "a": REDACTED,
        "x": {"A": {"C": REDACTED}},
    }


def test_design_named_fixtures() -> None:
    idp = {
        "id": "0oa1",
        "protocol": {
            "type": "OIDC",
            "credentials": {"client": {"client_id": "abc", "client_secret": SECRET}},
        },
    }
    stream = {"id": "esc1", "delivery": {"method": "push", "authorization_header": SECRET}}
    app = {
        "id": "0oa2",
        "credentials": {"oauthClient": {"client_id": "abc", "client_secret": SECRET}},
        "settings": {"app": {"sharedSecret": SECRET}},
        "keys": [{"kid": "k1", "privateKey": SECRET}],
    }
    office365 = {
        "id": "0oa3",
        "settings": {"app": {"domain": "example.com", "adminPassword": SECRET}},
    }
    org2org = {
        "id": "0oa4",
        "settings": {"app": {"baseUrl": "https://example.okta.com", "token": SECRET}},
    }
    org2org_encrypted = {"id": "0oa5", "settings": {"app": {"tokenEncrypted": SECRET}}}
    persona = {
        "id": "0oa6",
        "protocol": {"type": "ID_PROOFING", "credentials": {"bearer": {"apiKey": SECRET}}},
    }
    smtp = {"id": "smtp1", "authType": "BASIC_SMTP_AUTH", "username": "a", "password": SECRET}
    hook = {
        "id": "who1",
        "channel": {
            "config": {
                "uri": "https://hooks.example.com",
                "headers": [{"key": "x-api-key", "value": SECRET}],
            }
        },
    }
    for item in (idp, stream, app, office365, org2org, org2org_encrypted, persona, smtp, hook):
        out = render(item, RULES, links=False, cols=None)
        assert SECRET not in json.dumps(out)
        assert out["id"] == item["id"]
    assert pick(render(idp, RULES, links=False, cols=None), "protocol.credentials.client") == {
        "client_id": "abc",
        "client_secret": REDACTED,
    }


def test_select_cannot_reach_under_a_scrubbed_value() -> None:
    item = nest("credentials.oauthClient.client_secret", {"inner": SECRET})
    assert render(
        item, RULES, links=False, cols=("credentials.oauthClient.client_secret.inner",)
    ) == [None]
    assert render(item, RULES, links=False, cols=("credentials",)) == [
        {"oauthClient": {"client_secret": REDACTED}}
    ]


def test_partial_chain_does_not_redact() -> None:
    item = {"delivery": {"method": "push"}, "authorization_header": "keep", "value": "keep"}
    assert scrub(item, RULES) == item


def test_config_objects_named_like_secrets_kept() -> None:
    item = {
        "settings": {
            "oauthClient": {"refresh_token": {"rotation_type": "ROTATE", "leeway": 30}},
            "password": {"complexity": {"minLength": 8}},
        },
        "events": [{"token": {"jti": "oar1"}}],
    }
    assert scrub(item, RULES) == item


def test_chain_breaks_on_an_intermediate_key() -> None:
    rules = ScrubRules((("a", "b"),))
    assert scrub({"a": {"x": {"b": 1}}}, rules) == {"a": {"x": {"b": 1}}}
    assert scrub({"a": [{"b": 1}]}, rules) == {"a": [{"b": REDACTED}]}


def test_scrub_does_not_mutate_input() -> None:
    item = {"secret": SECRET, "x": [{"secret": SECRET}]}
    scrub(item, RULES)
    assert item == {"secret": SECRET, "x": [{"secret": SECRET}]}


def test_redacted_survives_pruning() -> None:
    assert render({"secret": None}, RULES, links=False, cols=None) == {"secret": REDACTED}


def test_strip_links_nested() -> None:
    item = {
        "id": "00g1",
        "_links": {"self": {"href": "https://example.okta.com/api/v1/groups/00g1"}},
        "_embedded": {
            "stats": {"usersCount": 3, "_links": {"self": {}}},
            "apps": [{"id": "0oa1", "_links": {"logo": []}}],
        },
    }
    assert strip_links(item) == {
        "id": "00g1",
        "_embedded": {"stats": {"usersCount": 3}, "apps": [{"id": "0oa1"}]},
    }


def test_links_kept_when_asked() -> None:
    item = {"id": "00g1", "_links": {"self": {"href": "https://example.okta.com/x"}}}
    assert render(item, RULES, links=True, cols=None) == item
    assert render(item, RULES, links=True, cols=("_links.self.href",)) == [
        "https://example.okta.com/x"
    ]
    assert render(item, RULES, links=False, cols=("_links.self.href",)) == [None]


def test_prune() -> None:
    item = {
        "a": None,
        "b": {},
        "c": [],
        "d": "",
        "e": {"f": None, "g": {"h": []}},
        "i": [None, {}, {"j": None}, 0],
        "k": False,
        "l": 0,
    }
    assert prune(item) == {"d": "", "i": [None, {}, {}, 0], "k": False, "l": 0}


def test_columns() -> None:
    view = ("id", "profile.name")
    assert columns(None, view) == view
    assert columns(None, None) is None
    assert columns("*", view) is None
    assert columns(" * ", view) is None
    assert columns("id, profile.login ,status", view) == ("id", "profile.login", "status")
    assert columns("status,id, status,id", view) == ("status", "id")


@pytest.mark.parametrize(
    "select", ["", "id,", "id,,x", "*,id", "a..b", ".a", "a.", "profile. login", "profile .login"]
)
def test_bad_select(select: str) -> None:
    with pytest.raises(InvalidArguments, match="select"):
        columns(select, None)


def test_pick_dotted_and_arrays() -> None:
    zone = {
        "id": "nzo1",
        "profile": {"name": "HQ", "custom": {"x": 1}},
        "gateways": [{"type": "CIDR", "value": "192.0.2.0/24"}, {"type": "RANGE"}],
    }
    assert pick(zone, "profile.name") == "HQ"
    assert pick(zone, "profile.custom") == {"x": 1}
    assert pick(zone, "gateways.value") == ["192.0.2.0/24", None]
    assert pick(zone, "gateways") == zone["gateways"]
    assert pick(zone, "missing.path") is None
    assert pick(zone, "id.length") is None


def test_render_row_keeps_null_cells() -> None:
    item = {"id": "00u1", "profile": {"login": "a@example.com"}, "lastLogin": None}
    assert render(item, RULES, links=False, cols=("id", "lastLogin", "profile.login")) == [
        "00u1",
        None,
        "a@example.com",
    ]


def test_render_non_object_items() -> None:
    assert render("<EntityDescriptor/>", RULES, links=False, cols=None) == "<EntityDescriptor/>"
    assert render(["a", None], RULES, links=False, cols=None) == ["a", None]


def scrub_file(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "scrub.yaml"
    p.write_text(text)
    return p


@pytest.mark.parametrize(
    "text",
    [
        "",
        "paths: []\n",
        "paths: secret\n",
        "paths: [a, '']\n",
        "paths: ['*.secret']\n",
        "paths: [a..b]\n",
        "paths: [.a]\n",
        "paths: ['a b']\n",
        'paths: ["a\\n"]\n',
        "paths: [1]\n",
        "paths: [a]\nextra: 1\n",
        "paths: [a]\npaths: [b]\n",
        "paths: [a\n",
        "strings: [a]\n",
        "paths: [a]\nstrings: ['*.b']\n",
        "paths: [a]\nstrings: b\n",
    ],
)
def test_load_scrub_rejects(tmp_path: Path, text: str) -> None:
    with pytest.raises(ScrubError):
        load_scrub(scrub_file(tmp_path, text))


def test_load_scrub_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ScrubError):
        load_scrub(tmp_path / "nope.yaml")


def test_load_scrub_lowercases(tmp_path: Path) -> None:
    text = "paths: [Delivery.Authorization_Header, x]\nstrings: [Password]\n"
    rules = load_scrub(scrub_file(tmp_path, text))
    assert rules.paths == (("delivery", "authorization_header"), ("x",))
    assert rules.strings == (("password",),)


def test_shipped_scrub_has_design_paths() -> None:
    for path in (
        "protocol.credentials.client.client_secret",
        "delivery.authorization_header",
        "credentials.oauthClient.client_secret",
        "privateKey",
        "secret",
        "sharedSecret",
    ):
        assert tuple(path.lower().split(".")) in RULES.paths
