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
_WORDS = _COMPARISONS | {"pr", "and", "or", "not", "true", "false", "null"}

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
    place of an attribute name. Raises `ExpressionError` otherwise, and when no attribute
    is named."""
    found: dict[str, None] = {}
    previous = ""
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
        if kind == "name" and text.lower() not in _WORDS:
            found[text] = None
        previous = text.lower() if kind == "name" else ""
    if not found:
        raise ExpressionError("expression names no attribute")
    return tuple(found)


def scrubbed(attribute: str, rules: ScrubRules) -> bool:
    """Whether results redact `attribute`, or something under it. Such an attribute is not
    searchable by anyone: matching on a value is reading it.

    Keys compare as the scrubber compares them (lower-cased, at any depth). An attribute that
    stops partway into a redacted chain (`credentials.password` for
    `credentials.password.value`) counts too."""
    keys = attribute.lower().split(".")
    for chain, _ in rules.chains:
        n = len(chain)
        if any(tuple(keys[i : i + n]) == chain for i in range(len(keys) - n + 1)):
            return True
        if any(tuple(keys[-k:]) == chain[:k] for k in range(1, min(n, len(keys) + 1))):
            return True
    return False
