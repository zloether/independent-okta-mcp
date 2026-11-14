"""Per-command argument schemas, synopsis lines, help text and validation (design §5.3, §6.3).

The schema is built once at load from the spec's parameter schemas with the registry's overlays,
and is the one source for the synopsis, `okta_help` text (T1 D11) and validation.
"""

import copy
import re
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft202012Validator, SchemaError, ValidationError, validators
from jsonschema.protocols import Validator

from okta_mcp.registry.model import CommandEntry, ecma_pattern
from okta_mcp.registry.spec import Operation

if TYPE_CHECKING:
    from okta_mcp.registry.loader import Command


# JSON Schema counts 5.0 as an integer; Okta should only ever get "5".
def _is_int(_: object, v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _pattern(_: object, pattern: str, instance: object, __: object) -> Iterator[ValidationError]:
    if isinstance(instance, str) and not ecma_pattern(pattern).search(instance):
        yield ValidationError(f"does not match {pattern!r}")


_Validator = cast(
    type[Validator],
    validators.extend(  # pyright: ignore[reportUnknownMemberType]
        Draft202012Validator,
        validators={"pattern": _pattern},
        type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", _is_int),
    ),
)

SYNOPSIS_MAX = 60
"""Cap on `usage + "  " + summary` (T1 D1); column padding in the tool description is extra."""
_OPTIONS_MAX = 20
QUERY_LENGTH_MAX = 4096
"""Longest string query value, or array item, in characters. Okta filter expressions and names
fit in far less, so a runaway arg is `invalid_arguments` from validation (and the bound is shown
by `okta_help`). It keeps one ASCII arg well under httpx2's 64 KiB URL limit, but not every
call: percent-encoding grows non-ASCII up to 12 times, and args add up, so for combined or
non-ASCII args the executor's `InvalidURL` catch (also `invalid_arguments`) is the expected
path."""
# Spec schema keywords that constrain a value; descriptions, examples, defaults and the spec's
# prose `format`s are dropped.
_KEEP = ("type", "enum", "pattern", "minimum", "maximum", "minLength", "maxLength", "maxItems")
_RESOLVED = "user ID (00u…) or exact login"


class InvalidArguments(Exception):
    """`invalid_arguments` (design §5.5); the message names the valid keys or values."""


def build_schema(entry: CommandEntry, op: Operation, errors: list[str]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    required: list[str] = []
    for name, arg in entry.args.items():
        param = op.params.get(arg.param)
        if param is None:
            continue  # reported by the loader's check 2
        is_required = param.required or arg.required
        if arg.required and param.required:
            errors.append(f"arg {name}: the spec already makes {arg.param} required")
        if arg.required and arg.arg_rule is not None and arg.arg_rule.forbidden:
            errors.append(f"arg {name}: required and forbidden, so no call is valid")
        if arg.allowed_values == ():
            if is_required:
                errors.append(f"arg {name}: {arg.param} is required, so it can't be hidden")
            continue
        s = _spec_schema(param.schema)
        if arg.type is not None:
            # Only fills a type the spec leaves out: replacing one could widen the argument.
            if s.get("type", arg.type) != arg.type:
                errors.append(f"arg {name}: spec type is {s['type']}, not {arg.type}")
            s["type"] = arg.type
            if arg.type == "array":
                s.setdefault("items", {"type": "string"})
        if param.location == "path":
            if s.get("type", "string") != "string":
                errors.append(f"arg {name}: path params are strings")
            s["type"] = "string"
        # Value constraints of an array argument apply to its items.
        target = s["items"] if s.get("type") == "array" else s
        if arg.pattern is not None:
            if "pattern" in target:
                errors.append(f"arg {name}: spec already sets pattern {target['pattern']}")
            target["pattern"] = arg.pattern
        if arg.allowed_values:
            extra = sorted(set(arg.allowed_values) - set(target.get("enum", arg.allowed_values)))
            if target.get("type") != "string":
                errors.append(f"arg {name}: allowed_values need a string or array of strings")
            elif extra:
                errors.append(f"arg {name}: allowed_values {extra} are not in the spec enum")
            target["enum"] = list(arg.allowed_values)
        # Query strings only: the §6.4 rule caps path values at 256; an enum bounds itself.
        if param.location == "query" and target.get("type") == "string" and "enum" not in target:
            target["maxLength"] = min(target.get("maxLength", QUERY_LENGTH_MAX), QUERY_LENGTH_MAX)
        if arg.max_items is not None:
            if s.get("type") != "array":
                errors.append(f"arg {name}: maxItems needs an array")
            s["maxItems"] = arg.max_items
        props[name] = s
        if is_required:
            required.append(name)

    schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        schema["required"] = required
    if entry.one_of_required is not None:
        if len(set(entry.one_of_required)) != len(entry.one_of_required):
            errors.append("one_of_required has duplicate args")
        for name in entry.one_of_required:
            if name not in props:
                errors.append(f"one_of_required: unknown or hidden arg {name}")
            elif name in required:
                errors.append(f"one_of_required: {name} is always required")
        schema["oneOf"] = [{"required": [name]} for name in entry.one_of_required]
    try:
        _Validator.check_schema(schema)
    except SchemaError as e:
        errors.append(f"invalid argument schema: {e.message}")
    return schema


def make_validator(schema: Mapping[str, Any]) -> Validator:
    return _Validator(schema)


def _spec_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    out = {k: copy.deepcopy(schema[k]) for k in _KEEP if k in schema}
    items = schema.get("items")
    if isinstance(items, Mapping):
        out["items"] = _spec_schema(cast(Mapping[str, Any], items))
    return out


def usage(name: str, schema: Mapping[str, Any], collapse: bool = False) -> str:
    """`get-groups <user>`, `list [filter] [search]`; `<a|b>` for `one_of_required`. With
    `collapse`, optional args become one `[options]`."""
    props = cast(Mapping[str, Any], schema["properties"])
    required = set(schema.get("required", ()))
    either = _either(schema)
    parts = [name]
    optional = False
    for arg in props:
        if arg in required:
            parts.append(f"<{arg}>")
        elif arg in either:
            if arg == next(a for a in props if a in either):
                parts.append(f"<{'|'.join(a for a in props if a in either)}>")
        elif collapse:
            optional = True
        else:
            parts.append(f"[{arg}]")
    if optional:
        parts.append("[options]")
    return " ".join(parts)


def synopsis(name: str, summary: str, schema: Mapping[str, Any], errors: list[str]) -> str:
    line = usage(name, schema)
    if len(f"{line}  {summary}") > SYNOPSIS_MAX:
        line = usage(name, schema, collapse=True)
    if len(f"{line}  {summary}") > SYNOPSIS_MAX:
        errors.append(f"synopsis line is over {SYNOPSIS_MAX} characters: {line}  {summary}")
    return line


def help_text(command: "Command") -> str:
    """Compact text help for `okta_help` (T1 D11): every constraint, none of the JSON."""
    entry, schema = command.entry, command.schema
    props = cast(Mapping[str, Mapping[str, Any]], schema["properties"])
    kind = ""
    if command.is_list:
        kind = " List, paginated." if entry.paginate != "none" else " List."
    lines = [
        f"okta_{command.domain.replace('-', '_')} {usage(command.name, schema)}",
        f"{entry.summary.rstrip('.')}.{kind}",
    ]
    width = max((len(a) for a in props), default=0)
    for name, s in props.items():
        arg = entry.args[name]
        facts = [_type(s)]
        if name in schema.get("required", ()):
            facts.append("required")
        enum = s.get("enum") or s.get("items", {}).get("enum")
        if enum:
            facts.append(f"one of: {_options(enum)}")
        facts += _bounds(s)
        facts += [f"each {f}" for f in _bounds(s.get("items", {}))]
        if "maxItems" in s:
            facts.append(f"at most {_count(s['maxItems'], 'item')}")
        param = command.operation.params[arg.param]
        desc = (
            _RESOLVED
            if arg.resolve
            else _describe(param.description or str(param.schema.get("description", "")))
        )
        line = f"  {name.ljust(width)}  {', '.join(facts)}"
        lines.append(f"{line} — {desc}" if desc else line)
    if either := _either(schema):
        lines.append(f"Exactly one of: {', '.join(either)}")
    if entry.view is not None:
        lines.append(f"Default view: {','.join(entry.view)}")
    return "\n".join(lines)


def _bounds(schema: Mapping[str, Any]) -> list[str]:
    labels = {
        "minLength": "min length",
        "maxLength": "max length",
        "minimum": "min",
        "maximum": "max",
        "pattern": "pattern",
    }
    return [f"{label} {schema[key]}" for key, label in labels.items() if key in schema]


def _type(schema: Mapping[str, Any]) -> str:
    t = str(schema.get("type", "any"))
    return f"array of {schema['items'].get('type', 'any')}" if t == "array" else t


def _describe(text: str) -> str:
    """First sentence of a spec description, without HTML tags or Markdown links."""
    text = re.sub(r"<[^>]*>", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = " ".join(text.split())
    first = re.split(r"(?<=\.)\s", text, maxsplit=1)[0]
    return first if len(first) <= 100 else first[:99] + "…"


def validate_args(command: "Command", args: object) -> None:
    """Raise `InvalidArguments` naming every problem and the valid options. Values the caller
    sent are never echoed back; unknown key names only shortened and capped."""
    if messages := schema_problems(command, args):
        raise InvalidArguments("; ".join(sorted(messages)))


def schema_problems(command: "Command", args: object) -> set[str]:
    """The messages `validate_args` would join, for callers that add their own."""
    props = cast(Mapping[str, Any], command.schema["properties"])
    errors = command.validator.iter_errors(cast(Any, args))
    return {_message(e, args, props) for e in errors}


def _key_name(key: object) -> str:
    """An unknown key as shown to the caller: quoted, cut to 40 characters. A key that isn't a
    string (args built by code, not JSON) is named by its type."""
    if not isinstance(key, str):
        return f"<{type(key).__name__} key>"
    return repr(key if len(key) <= 40 else key[:39] + "…")


def _message(e: ValidationError, args: object, props: Mapping[str, Any]) -> str:
    where = f"arg {e.path[0]!r}" if e.path else "args"
    value = cast(Any, e.validator_value)
    match e.validator:
        case "additionalProperties":
            extra = sorted(set(cast(Mapping[object, Any], args)) - set(props), key=_key_name)
            noun = "arg" if len(extra) == 1 else "args"
            names = _options(_key_name(k) for k in extra)
            return f"unknown {noun} {names}; valid: {_options(props)}"
        case "required":
            present = cast(Mapping[str, Any], args)
            missing = [r for r in cast(list[str], value) if r not in present]
            return ", ".join(f"missing required arg {r!r}" for r in missing)
        case "oneOf":
            return f"pass exactly one of: {', '.join(_either(cast(Mapping[str, Any], e.schema)))}"
        case "enum":
            return f"{where} must be one of: {_options(cast(list[str], value))}"
        case "type":
            article = "an" if str(value)[0] in "aeiou" else "a"
            return f"{where} must be {article} {value}"
        case "pattern":
            return f"{where} must match {value}"
        case "maxItems":
            return f"{where} takes at most {_count(value, 'item')}"
        case _:
            return f"{where} fails {e.validator} {value}"


def _either(schema: Mapping[str, Any]) -> list[str]:
    """The `one_of_required` args, from the schema's `oneOf: [{required: [a]}, …]`."""
    return [cast(list[str], s["required"])[0] for s in schema.get("oneOf", ())]


def _options(values: Any) -> str:
    values = [str(v) for v in values]
    shown = ", ".join(values[:_OPTIONS_MAX])
    rest = len(values) - _OPTIONS_MAX
    return f"{shown}, … (+{rest}; see okta_help)" if rest > 0 else shown


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"
