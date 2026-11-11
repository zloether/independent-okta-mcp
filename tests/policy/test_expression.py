# ruff: noqa: RUF001  (look-alike characters are the test)
import pytest

from okta_mcp.exec.output import ScrubRules, load_scrub
from okta_mcp.policy.expression import ATTRIBUTE, ExpressionError, attributes, scrubbed


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('profile.login eq "a@example.com"', ("profile.login",)),
        ("profile.name", ("profile.name",)),
        ("status", ("status",)),
        ('status eq "ACTIVE" and profile.department eq "Eng"', ("status", "profile.department")),
        (
            'profile.a sw "x" or (profile.b co "y" and not (profile.c ew "z"))',
            ("profile.a", "profile.b", "profile.c"),
        ),
        ('lastUpdated gt "2026-01-01T00:00:00.000Z"', ("lastUpdated",)),
        ("profile.manager pr", ("profile.manager",)),
        ("profile.level ge 5 and profile.ratio lt -1.5", ("profile.level", "profile.ratio")),
        ("profile.active eq true or profile.gone eq null", ("profile.active", "profile.gone")),
        # Operators in any case; each attribute once, as first written.
        ('type.id EQ "x" AND type.id Ne "y"', ("type.id",)),
        ('profile.a eq "1" and Profile.a eq "2"', ("profile.a", "Profile.a")),
        # An attribute compared with an attribute: both are reported.
        ("profile.a eq profile.b", ("profile.a", "profile.b")),
        # Inside a value, nothing is an attribute.
        ('profile.a eq "profile.secret sw (x) and"', ("profile.a",)),
        ('profile.a eq ""', ("profile.a",)),
        ('profile.a eq "é ' + "'" + ' ; % [0]"', ("profile.a",)),
        ('(profile.a eq "x")', ("profile.a",)),
        ('  profile.a   eq   "x"  ', ("profile.a",)),
        # Dotted names are attributes even when a segment is an operator word.
        ('profile.eq eq "x" and profile.not pr', ("profile.eq", "profile.not")),
        ("_a.b_1.c", ("_a.b_1.c",)),
        # A word that only looks like an operator is an attribute.
        ('equals eq "x" and android pr', ("equals", "android")),
    ],
)
def test_attributes(expression: str, expected: tuple[str, ...]) -> None:
    assert attributes(expression) == expected
    for a in expected:
        assert ATTRIBUTE.fullmatch(a)


@pytest.mark.parametrize(
    "expression",
    [
        "",
        " ",
        "()",
        "and or not",
        'eq "x"',
        "true",
        # Quoting: unterminated, backslashes, single quotes, a quoted name.
        'profile.a eq "x',
        'profile.a eq x"',
        'profile.a eq "x\\" or profile.secret sw "y"',
        'profile.a eq "x\\\\"',
        "profile.a eq 'x'",
        '"profile.secret" sw "a"',
        '"a" eq profile.a',
        'profile.a "x"',
        'profile.a pr "x"',
        'profile.a and "x"',
        'profile.a eq "x" "y"',
        "5 eq profile.a",
        "profile.a 5",
        # Characters outside the alphabet.
        "profile.a[0] pr",
        'profile.a eq "x";',
        'profile.a eq "x", profile.b pr',
        "urn:okta:profile.a pr",
        "profile.a=x",
        'profile.a\teq "x"',
        'profile.a\neq "x"',
        'profile.a eq "x"\n',
        "profile.a%20pr",
        "profile-a pr",
        "profile.a\x00 pr",
        # Not ASCII: a Cyrillic o, a fullwidth letter, a non-ASCII digit, a no-break space.
        "prоfile.a pr",
        "ｐrofile.a pr",
        "profile.a eq ٣",
        "profile.a pr",
        # Malformed names and numbers.
        "profile. pr",
        ".profile pr",
        "profile..a pr",
        "profile.1a pr",
        "1a pr",
        "profile.a eq 1.",
        "profile.a eq 1.2.3",
        "profile.a eq 1e5",
        "profile.a eq -",
        "profile.a eq 5x",
    ],
)
def test_refused(expression: str) -> None:
    with pytest.raises(ExpressionError):
        attributes(expression)


def test_error_text_never_repeats_the_value() -> None:
    for expression in ('profile.zzqq eq "hunter2', "zzqq[", '"zzqq" eq "hunter2"', "zzqq 5"):
        with pytest.raises(ExpressionError) as e:
            attributes(expression)
        assert "zzqq" not in str(e.value) and "hunter2" not in str(e.value)


def test_every_printable_ascii_character_is_a_value_or_refused() -> None:
    # No character outside a quoted value can be dropped without being seen.
    for code in range(32, 127):
        ch = chr(code)
        if ch in '"\\':
            continue
        assert attributes(f'profile.a eq "{ch}"') == ("profile.a",)
        try:
            found = attributes(f"profile.a pr {ch} profile.b pr")
        except ExpressionError:
            continue
        # Accepted only as a space, a parenthesis, or part of a name or number.
        assert ch in " ()" or ch.isalnum() or ch in "_.-", ch
        assert "profile.a" in found


RULES = ScrubRules(
    paths=(("secret",), ("credentials", "password", "value"), ("apikey",)),
    strings=(("token",),),
)


@pytest.mark.parametrize(
    "attribute",
    [
        "secret",
        "profile.secret",
        "profile.SECRET",
        "profile.Secret.inner",
        "a.b.secret.c.d",
        "profile.apiKey",
        "profile.token",
        "token",
        "credentials.password.value",
        "x.credentials.password.value",
        "credentials.password.value.more",
        # Stops inside a redacted chain.
        "credentials.password",
        "credentials",
        "x.credentials",
        "x.credentials.password",
    ],
)
def test_scrubbed(attribute: str) -> None:
    assert scrubbed(attribute, RULES)


@pytest.mark.parametrize(
    "attribute",
    [
        "profile.login",
        "status",
        "profile.secretary",
        "profile.secrets",
        "profile.tokenCount",
        "profile.my_secret",
        "credentials.provider.type",
        "credentials.provider",
        "password.value",
        "password",
        "value",
        "credentials.value",
        "credentials.x.password.value",
    ],
)
def test_not_scrubbed(attribute: str) -> None:
    assert not scrubbed(attribute, RULES)


def test_scrubbed_agrees_with_the_scrubber_on_the_packaged_rules() -> None:
    # Whatever `scrub` redacts under `profile`, `scrubbed` refuses to search.
    from okta_mcp.exec.output import REDACTED, scrub

    rules = load_scrub()
    keys = {key for chain, _ in rules.chains for key in chain}
    assert len(keys) > 20
    for key in sorted(keys | {k.upper() for k in keys}):
        redacted = scrub({"profile": {key: "v"}}, rules)["profile"][key] == REDACTED
        if redacted:
            assert scrubbed(f"profile.{key}", rules), key
    for chain, _ in rules.chains:
        assert scrubbed(".".join(chain), rules)
        assert scrubbed("profile." + ".".join(chain), rules)
    for plain in ("profile.login", "profile.email", "status", "id", "type", "lastUpdated"):
        assert not scrubbed(plain, rules)
