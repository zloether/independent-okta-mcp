"""Load `registry/*.yaml` and check it against the spec index (design §6.2 checks 1-6, 8-10).

Every error is collected and reported at once; any error fails the load. Check 7 (resource
guides) lands with the resources in step 3.4.
"""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import Any, cast

import yaml
from jsonschema.protocols import Validator
from pydantic import ValidationError

from okta_mcp.registry.model import CommandEntry, DomainFile, Sensitivity
from okta_mcp.registry.schema import build_schema, make_validator, synopsis
from okta_mcp.registry.spec import Operation, SpecIndex

REGISTRY = files("okta_mcp") / "data" / "registry"
# Free-form filters narrow a list; the other widening params add data to it.
_FILTERS = frozenset({"filter", "search", "q"})
_WIDENING = _FILTERS | {"expand", "discloseIdentifiers"}
# Pagination and page size belong to the server (design §7.2), never to the caller.
_RESERVED_QUERY = frozenset({"after", "limit"})


class RegistryError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Command:
    domain: str
    name: str
    entry: CommandEntry
    operation: Operation
    scope_sets: tuple[frozenset[str], ...]
    """Alternatives, as in `Operation.scope_sets`, with the resolver's scopes added to each."""
    sensitivity: Sensitivity
    """Base sensitivity; `arg_rule`s may raise it per call."""
    is_list: bool
    schema: Mapping[str, Any]
    """JSON Schema for `args` (design §6.3). Nested values are plain dicts: don't change them."""
    synopsis: str
    validator: Validator


@dataclass(frozen=True)
class Domain:
    name: str
    description: str
    commands: Mapping[str, Command]


@dataclass(frozen=True)
class Registry:
    domains: Mapping[str, Domain]


class UniqueKeyLoader(yaml.CSafeLoader):
    """PyYAML keeps the last of duplicate keys; a second `data_classes` or `arg_rule` would
    silently replace the first, so duplicates are errors."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        # Only the keys written here: a merge (`<<: *anchor`) may be overridden, and the base
        # constructor expands it and reports unhashable keys.
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = cast(Any, self.construct_object(key_node, deep=deep))  # pyright: ignore[reportUnknownMemberType]
            try:
                duplicate = key in seen
            except TypeError:
                continue
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_registry(spec: SpecIndex, directory: Traversable = REGISTRY) -> Registry:
    errors: list[str] = []
    docs: dict[str, Any] = {}
    if directory.is_dir():
        for f in sorted(directory.iterdir(), key=lambda f: f.name):
            if f.name.endswith(".yml"):
                errors.append(f"{f.name}: registry files end in .yaml")
            elif f.name.endswith(".yaml"):
                try:
                    docs[f.name] = yaml.load(f.read_bytes(), Loader=UniqueKeyLoader)  # noqa: S506
                except yaml.YAMLError as e:
                    errors.append(f"{f.name}: {e}")
    try:
        registry = build_registry(docs, spec)
    except RegistryError as e:
        raise RegistryError(errors + e.errors) from e
    if errors:
        raise RegistryError(errors)
    return registry


def build_registry(docs: Mapping[str, Any], spec: SpecIndex) -> Registry:
    """`docs` maps file name → parsed YAML."""
    errors: list[str] = []
    domains: dict[str, Domain] = {}
    for filename, doc in docs.items():
        try:
            parsed = DomainFile.model_validate(doc)
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(p) for p in err["loc"])
                errors.append(f"{filename}: {loc}: {err['msg']}")
            continue
        if filename != f"{parsed.domain}.yaml":
            errors.append(f"{filename}: domain {parsed.domain!r} must match the file name")
        if parsed.domain in domains:
            errors.append(f"{filename}: duplicate domain {parsed.domain!r}")
            continue
        commands: dict[str, Command] = {}
        for name, entry in parsed.commands.items():
            where = f"{filename}: {name}"
            cmd_errors: list[str] = []
            command = _command(parsed.domain, name, entry, spec, cmd_errors)
            errors.extend(f"{where}: {e}" for e in cmd_errors)
            if command is not None and not cmd_errors:
                commands[name] = command
        domains[parsed.domain] = Domain(
            parsed.domain, parsed.description, MappingProxyType(commands)
        )
    errors.extend(_check_shared_operations(domains))
    if errors:
        raise RegistryError(errors)
    return Registry(MappingProxyType(domains))


def _command(
    domain: str, name: str, entry: CommandEntry, spec: SpecIndex, errors: list[str]
) -> Command | None:
    if entry.handler is not None:
        errors.append("handler commands are post-v1")
        return None
    # Check 1: the operation exists and is a GET.
    if entry.operation in spec.non_get:
        method = spec.non_get[entry.operation].upper()
        errors.append(f"operation {entry.operation} is {method}; only GET is allowed")
        return None
    op = spec.operations.get(entry.operation)
    if op is None:
        errors.append(f"unknown operation {entry.operation}")
        return None
    _check_args(entry, op, errors)
    scope_sets = _scope_sets(entry, op, spec, errors)
    is_list = _check_shape(entry, op, errors)
    schema = build_schema(entry, op, errors)
    line = synopsis(name, entry.summary, schema, errors)
    return Command(
        domain,
        name,
        entry,
        op,
        scope_sets,
        entry.sensitivity,
        is_list,
        MappingProxyType(schema),
        line,
        make_validator(schema),
    )


def _check_args(entry: CommandEntry, op: Operation, errors: list[str]) -> None:
    # Check 2: path params covered, query params defined.
    used: dict[str, str] = {}
    for arg_name, arg in entry.args.items():
        param = op.params.get(arg.param)
        location = "path" if arg.path_param is not None else "query"
        if param is None or param.location != location:
            errors.append(f"arg {arg_name}: {op.operation_id} has no {location} param {arg.param}")
            continue
        if arg.param in used:
            errors.append(f"args {used[arg.param]} and {arg_name} both map to {arg.param}")
        used[arg.param] = arg_name
        if location == "query" and arg.param in _RESERVED_QUERY:
            errors.append(f"arg {arg_name}: query param {arg.param} is set by the server")
        # Check 6: arguments that can widen results need a rule.
        if arg.param in _WIDENING and arg.arg_rule is None and arg.allowed_values is None:
            errors.append(f"arg {arg_name}: {arg.param} needs an arg_rule or allowed_values")
        # `reviewed` records that a filter was looked at; it can't wave through anything else.
        if arg.arg_rule is not None and arg.arg_rule.reviewed:
            if arg.query not in _FILTERS:
                errors.append(
                    f"arg {arg_name}: arg_rule reviewed is only for free-form filters "
                    f"({', '.join(sorted(_FILTERS))}), not {arg.param}"
                )
            elif arg.query == "search" and _has_profile(op):
                # Okta's `search` on such resources matches any profile attribute, custom
                # ones included, and scrub.yaml redacts by key name: an oracle for those.
                errors.append(
                    f"arg {arg_name}: search on {op.operation_id} matches any profile "
                    "attribute, so it can't be reviewed; use forbidden"
                )
    for p in op.params.values():
        if p.required and p.name not in used and not (p.name == "limit" and entry.page_size):
            errors.append(f"required {p.location} param {p.name} has no arg")
    if entry.page_size is not None and "limit" not in op.params:
        errors.append(f"page_size set but {op.operation_id} has no limit param")
    if isinstance(entry.resumable, bool):
        return
    for a in entry.resumable.unless_args:
        if a not in entry.args:
            errors.append(f"resumable.unless_args: unknown arg {a}")


def _has_profile(op: Operation) -> bool:
    """The response, or the items of a list inside it, carry a `profile` object."""
    response = op.response
    return any(
        path.split(".")[0] == "profile"
        for fields in (response.fields, *response.item_fields.values())
        for path in fields
    )


def _scope_sets(
    entry: CommandEntry, op: Operation, spec: SpecIndex, errors: list[str]
) -> tuple[frozenset[str], ...]:
    # Check 3: derived scope sets; none at all is an error without an override.
    override = entry.okta_scopes_override
    if override is None:
        if not op.scope_sets:
            errors.append(f"{op.operation_id} declares no oauth2 scopes; add okta_scopes_override")
            return ()
        sets = op.scope_sets
    else:
        if op.scope_sets:
            errors.append("okta_scopes_override is only for operations without oauth2 scopes")
            return ()
        sets = (frozenset(override.scopes),)
    if any(a.resolve == "user_id" for a in entry.args.values()):
        resolver = spec.operations.get("getUser")
        if resolver is None or not resolver.scope_sets:
            errors.append("resolve: user_id needs getUser with oauth2 scopes in the spec")
            return ()
        sets = tuple(s | r for s in sets for r in resolver.scope_sets)
    return tuple(sorted(set(sets), key=sorted))


def _check_shape(entry: CommandEntry, op: Operation, errors: list[str]) -> bool:
    # Check 9 (items_key, paginate) and T1 D5 (views).
    response = op.response
    if entry.response_override is not None:
        if response.kind != "object":
            errors.append(f"response_override needs an object response, not {response.kind}")
            return False
        if entry.items_key is not None:
            errors.append("items_key and response_override are exclusive")
        item_fields = response.fields
    elif entry.items_key is not None:
        if entry.items_key in response.item_fields:
            item_fields = response.item_fields[entry.items_key]
        elif entry.items_key in response.scalar_lists and "after" in op.params:
            # A paged list of plain values (getIdentitySourceGroupMemberships).
            item_fields = frozenset[str]()
        else:
            keys = ", ".join(response.list_keys) or "none"
            errors.append(
                f"items_key {entry.items_key} is not an array-of-objects property of the "
                f"{op.operation_id} response (candidates: {keys}); arrays of values only "
                "on operations paged with after"
            )
            return True
    else:
        item_fields = response.fields
    is_list = (
        response.kind == "list"
        or entry.items_key is not None
        or entry.response_override is not None
    )

    # `_links.next` on a single resource is spec noise (getIdentityProviderApplicationUser);
    # `after` is not.
    if not is_list and "after" in op.params:
        errors.append(f"{op.operation_id} pages with after; set items_key")
    elif is_list and ("after" in op.params or response.links_next) and entry.paginate == "none":
        errors.append(f"{op.operation_id} paginates (after or _links.next); set paginate")
    if not is_list and entry.paginate != "none":
        errors.append("paginate set on a single-resource command")

    # Items with no declared properties have nothing to view.
    if is_list and entry.view is None and item_fields:
        errors.append("list commands need a view")
    for path in entry.view or ():
        if path.split(".")[0] == "_links":
            errors.append(f"view path {path}: _links are never in a view")
        elif path not in item_fields:
            errors.append(f"view path {path} is not in the {op.operation_id} response schema")
    if entry.view is not None and len(set(entry.view)) != len(entry.view):
        errors.append("view has duplicate paths")
    return is_list


def _check_shared_operations(domains: Mapping[str, Domain]) -> list[str]:
    # Check 5 and T1 D3: commands on one operation must share base sensitivity and may exist
    # only when their classification (data classes, arg rules) differs.
    by_op: dict[str, list[Command]] = defaultdict(list)
    for d in domains.values():
        for c in d.commands.values():
            by_op[c.operation.operation_id].append(c)
    errors: list[str] = []
    for op_id, cmds in by_op.items():
        if len(cmds) < 2:
            continue
        names = ", ".join(f"{c.domain} {c.name}" for c in cmds)
        if len({c.sensitivity for c in cmds}) > 1:
            errors.append(f"{op_id}: {names} differ in base sensitivity")
        classifications = [_classification(c) for c in cmds]
        if len(set(classifications)) < len(classifications):
            errors.append(f"{op_id}: {names} share a classification; make variants arguments")
    return errors


def _classification(c: Command) -> tuple[frozenset[str], frozenset[tuple[str, Any]]]:
    # The rule's form, not the wording of a `reviewed` reason.
    rules = frozenset(
        (a.param, a.arg_rule.model_copy(update={"reviewed": a.arg_rule.reviewed and "-"}))
        for a in c.entry.args.values()
        if a.arg_rule
    )
    return frozenset(c.entry.data_classes), rules
