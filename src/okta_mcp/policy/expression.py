"""Which attributes an Okta filter expression names (design §9.2).

A `search` over profile attributes can read a value back one character at a time
(`profile.apiKey sw "a"`), so the policy engine has to know every attribute an expression
touches before the call is made. This is a tokenizer, not a parser for Okta's grammar: it
accepts a small alphabet, and whatever it can't place it refuses. Anything it accepts either
means to Okta what it means here, or Okta rejects it.
"""

import re

from okta_mcp.exec.output import ScrubRules

_COMPARISONS = frozenset({"eq", "ne", "gt", "ge", "lt", "le", "sw", "co", "ew"})
_LITERALS = frozenset({"true", "false", "null"})
WORDS = _COMPARISONS | _LITERALS | {"pr", "and", "or", "not"}
"""Undotted names that are never attributes. Compared lower-cased."""
# These take an attribute on their left. Held to that, an operator word can't itself be the
# attribute (`pr sw "a"`, for a custom attribute named `pr`) without being reported.
_AFTER_ATTRIBUTE = _COMPARISONS | {"pr"}

# ASCII only, spelled out: `\w` and `\d` would take letters and digits Okta might fold into
# ASCII ones. No backslash inside a string: whether `\"` ends it is Okta's choice, and a
# different one here would put an attribute name where this module sees a value.
_SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
_TOKEN = re.compile(
    rf"""
      (?P<space>\x20+)
    | (?P<paren>[()])
    | (?P<string>"[^"\\]*")
    | (?P<number>-?[0-9]+(?:\.[0-9]+)?(?![A-Za-z0-9_.]))
    | (?P<name>{_SEGMENT}(?:\.{_SEGMENT})*(?![A-Za-z0-9_.]))
    """,
    re.VERBOSE,
)
ATTRIBUTE = re.compile(rf"{_SEGMENT}(?:\.{_SEGMENT})*")
"""What `attributes` can return, for the policy loader to hold `search_attributes` to."""


class ExpressionError(ValueError):
    """The expression has something this module doesn't accept. The message is fixed text:
    it never repeats the caller's value."""


def attributes(expression: str) -> tuple[str, ...]:
    """The attribute names in `expression`, as written, in order, each once.

    A name is an attribute unless it is an undotted operator or literal word. A string or
    number must directly follow a comparison operator, so a quoted string is never in the
    place of an attribute name; a comparison operator or `pr` must directly follow an
    attribute, and what follows a comparison operator is a value, a literal or an attribute,
    so an operator word is never in an operand's place either. Raises `ExpressionError`
    otherwise, and when no attribute is named."""
    found: dict[str, None] = {}
    previous = ""
    after_attribute = False
    position = 0
    while position < len(expression):
        token = _TOKEN.match(expression, position)
        if token is None:
            raise ExpressionError(
                "expression not understood: use attribute names, the operators eq ne gt ge "
                'lt le sw co ew pr and or not, parentheses and "double-quoted" values '
                "without backslashes"
            )
        position = token.end()
        kind, text = token.lastgroup, token.group()
        if kind == "space":
            continue
        if kind in ("string", "number") and previous not in _COMPARISONS:
            raise ExpressionError("a value must follow a comparison operator (eq, sw, ...)")
        word = text.lower() if kind == "name" else ""
        if word in _AFTER_ATTRIBUTE and not after_attribute:
            raise ExpressionError("an operator must follow an attribute name")
        if previous in _COMPARISONS and (kind == "paren" or word in WORDS - _LITERALS):
            raise ExpressionError("a comparison operator must be followed by a value")
        after_attribute = kind == "name" and word not in WORDS
        if after_attribute:
            found[text] = None
        previous = word
    if not found:
        raise ExpressionError("expression names no attribute")
    return tuple(found)


def attribute(value: str) -> str:
    """`value` if it is one attribute name and nothing else (a `sortBy`). Raises
    `ExpressionError` otherwise."""
    if not ATTRIBUTE.fullmatch(value) or value.lower() in WORDS:
        raise ExpressionError("give one attribute name, like profile.name")
    return value


def scrubbed(attribute: str, rules: ScrubRules) -> bool:
    """Whether results redact `attribute`, or something inside it. Such an attribute is not
    searchable by anyone: matching on a value is reading it.

    The scrubber's own test: a rule's key chain, lower-cased, anywhere in the path. A
    `strings` rule counts whatever the value's type, which a name can't tell."""
    keys = attribute.lower().split(".")
    return any(
        tuple(keys[i : i + len(chain)]) == chain
        for chain, _ in rules.chains
        for i in range(len(keys) - len(chain) + 1)
    )
