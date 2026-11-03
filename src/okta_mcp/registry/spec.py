"""Index of the pinned Okta Management spec's GET operations (design §6.1).

Only what the registry loader checks against (design §6.2 checks 1-3, 9) and the argument
schemas are built from (§6.3) is kept: path template, path/query parameters with their inlined
schemas, `oauth2` scopes, tags, and the shape of the success response.

The index is frozen dataclasses over read-only mappings, but `Param.schema` holds plain dicts and
lists: copy a schema before changing it.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Literal, cast

import yaml

SPEC = files("okta_mcp") / "data" / "specs" / "management-minimal.yaml"
_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class SpecError(Exception):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    location: Literal["path", "query"]
    required: bool
    description: str
    schema: Mapping[str, Any]


@dataclass(frozen=True)
class Response:
    """`list`: top-level array. `object`: an object; `item_fields` has its array-of-object
    properties, the candidates for a wrapped list (an `items_key`). `other`: non-JSON,
    `oneOf`/`anyOf`, or no usable schema.

    `fields` are the dotted property paths of the object, or of each item of a top-level list.
    Arrays are leaves. Polymorphic schemas contribute only the paths every variant has: a
    discriminated base schema its own properties, `oneOf`/`anyOf` the intersection."""

    kind: Literal["list", "object", "other"]
    fields: frozenset[str] = frozenset()
    item_fields: Mapping[str, frozenset[str]] = field(default_factory=lambda: MappingProxyType({}))
    links_next: bool = False

    @property
    def list_keys(self) -> tuple[str, ...]:
        return tuple(self.item_fields)


@dataclass(frozen=True)
class Operation:
    operation_id: str
    path: str
    params: Mapping[str, Param]
    scope_sets: tuple[frozenset[str], ...]
    """Alternatives: each `oauth2` security entry is one, and any one granted set suffices."""
    tags: tuple[str, ...]
    response: Response


@dataclass(frozen=True)
class SpecIndex:
    version: str
    operations: Mapping[str, Operation]
    non_get: Mapping[str, str]
    """operationId → method of every non-GET operation, so the loader can say why it rejects one."""


class _Resolver:
    def __init__(self, spec: Mapping[str, Any]) -> None:
        self._spec = spec

    def deref(self, node: Any) -> Any:
        seen: set[str] = set()
        while isinstance(node, dict) and "$ref" in node:
            ref = cast(str, cast(dict[str, Any], node)["$ref"])
            if ref in seen:
                raise SpecError(f"$ref cycle: {ref}")
            seen.add(ref)
            node = self._target(ref)
        return cast(Any, node)

    def inline(self, node: Any, stack: tuple[str, ...] = ()) -> Any:
        """Copy of `node` with every $ref replaced by its target. Parameter schemas are small and
        acyclic; a cycle is an error rather than a silent truncation."""
        if isinstance(node, dict):
            obj = cast(dict[str, Any], node)
            ref = obj.get("$ref")
            if isinstance(ref, str):
                if ref in stack:
                    raise SpecError(f"$ref cycle: {ref}")
                return self.inline(self._target(ref), (*stack, ref))
            return {k: self.inline(v, stack) for k, v in obj.items()}
        if isinstance(node, list):
            return [self.inline(v, stack) for v in cast(list[Any], node)]
        return node

    def _target(self, ref: str) -> Any:
        node: Any = self._spec
        if not ref.startswith("#/"):
            raise SpecError(f"unsupported $ref: {ref}")
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise SpecError(f"dangling $ref: {ref}")
            node = cast(dict[str, Any], node)[part]
        return node

    def schema(self, node: Any) -> dict[str, Any] | None:
        """`node` dereferenced, or None when it isn't a schema object (e.g. a boolean schema)."""
        node = self.deref(node)
        return cast(dict[str, Any], node) if isinstance(node, dict) else None

    def properties(self, node: Any, stack: tuple[int, ...] = ()) -> dict[str, Any]:
        """Properties of an object schema, merged across `allOf` parts."""
        schema = self.schema(node)
        if schema is None:
            return {}
        if id(schema) in stack:
            raise SpecError("allOf cycle")
        props = dict(cast(dict[str, Any], schema.get("properties", {})))
        for part in cast(list[Any], schema.get("allOf", [])):
            props.update(self.properties(part, (*stack, id(schema))))
        return props

    def is_object(self, node: Any) -> bool:
        schema = self.schema(node)
        return schema is not None and (
            schema.get("type") == "object" or "properties" in schema or "allOf" in schema
        )

    def is_object_list(self, node: Any) -> bool:
        schema = self.schema(node)
        return (
            schema is not None
            and schema.get("type") == "array"
            and self.is_object(schema.get("items"))
        )

    def fields(self, node: Any, stack: tuple[int, ...] = ()) -> frozenset[str]:
        """Dotted property paths of an object schema (see `Response`). A schema met again on
        its own path is a leaf, so recursive schemas terminate."""
        schema = self.schema(node)
        if schema is None or id(schema) in stack:
            return frozenset()
        stack = (*stack, id(schema))
        paths: set[str] = set()
        for name, sub in self.properties(schema).items():
            paths.add(name)
            paths.update(f"{name}.{p}" for p in self.fields(sub, stack))
        alternatives = cast(list[Any], schema.get("oneOf") or schema.get("anyOf") or [])
        variants = [self.fields(v, stack) for v in alternatives]
        if variants:
            paths.update(variants[0].intersection(*variants[1:]))
        return frozenset(paths)


def _params(
    r: _Resolver, path: str, path_item: dict[str, Any], op: dict[str, Any]
) -> dict[str, Param]:
    # Operation-level parameters override path-level ones with the same name and location.
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in [*path_item.get("parameters", []), *op.get("parameters", [])]:
        p = cast(dict[str, Any], r.deref(raw))
        merged[(p["name"], p["in"])] = p
    params: dict[str, Param] = {}
    for (name, location), p in merged.items():
        if location not in ("path", "query"):
            continue
        if name in params:
            raise SpecError(f"{op['operationId']}: {name} is both a path and a query parameter")
        params[name] = Param(
            name=name,
            location=location,
            # OpenAPI requires every path parameter; the spec sometimes omits the flag.
            required=location == "path" or bool(p.get("required", False)),
            description=str(p.get("description", "")),
            schema=MappingProxyType(r.inline(p.get("schema", {}))),
        )
    template_vars = set(re.findall(r"\{([^}]*)\}", path))
    path_params = {n for n, p in params.items() if p.location == "path"}
    if template_vars != path_params:
        raise SpecError(
            f"{op['operationId']}: path template variables {sorted(template_vars)} "
            f"!= path parameters {sorted(path_params)}"
        )
    return params


def _scope_sets(op: dict[str, Any]) -> tuple[frozenset[str], ...]:
    # No fallback to spec-level `security`: an operation that declares none gets no scope sets,
    # which the registry loader rejects (fail closed). An empty `oauth2` list would be an
    # always-satisfied alternative, so it is dropped rather than kept.
    entries = cast(list[dict[str, list[str]]], op.get("security", []))
    sets = {frozenset(entry["oauth2"]) for entry in entries if entry.get("oauth2")}
    return tuple(sorted(sets, key=sorted))


def _response(r: _Resolver, op: dict[str, Any]) -> Response:
    ok = r.deref(op.get("responses", {}).get("200", {}))
    schema = r.deref(ok.get("content", {}).get("application/json", {}).get("schema"))
    if not isinstance(schema, dict):
        return Response("other")
    schema = cast(dict[str, Any], schema)
    if schema.get("type") == "array":
        return Response("list", r.fields(schema.get("items")))
    if "oneOf" in schema or "anyOf" in schema:
        return Response("other")
    if not r.is_object(schema):
        return Response("other")
    props = r.properties(schema)
    item_fields = {
        k: r.fields(cast(dict[str, Any], r.schema(v))["items"])
        for k, v in props.items()
        if r.is_object_list(v)
    }
    links_next = "next" in r.properties(props["_links"]) if "_links" in props else False
    return Response("object", r.fields(schema), MappingProxyType(item_fields), links_next)


def build_index(spec: Mapping[str, Any]) -> SpecIndex:
    try:
        return _build_index(spec)
    except (KeyError, TypeError, AttributeError) as e:
        raise SpecError(f"malformed spec: {e!r}") from e


def _build_index(spec: Mapping[str, Any]) -> SpecIndex:
    r = _Resolver(spec)
    operations: dict[str, Operation] = {}
    non_get: dict[str, str] = {}
    for path, item in cast(dict[str, dict[str, Any]], spec["paths"]).items():
        if "$ref" in item:
            raise SpecError(f"{path}: path item $ref is not supported")
        for method in _METHODS:
            op = cast(dict[str, Any] | None, item.get(method))
            if op is None:
                continue
            op_id = op.get("operationId")
            if not isinstance(op_id, str):
                raise SpecError(f"{method.upper()} {path} has no operationId")
            if op_id in operations or op_id in non_get:
                raise SpecError(f"duplicate operationId: {op_id}")
            if method != "get":
                non_get[op_id] = method
                continue
            operations[op_id] = Operation(
                operation_id=op_id,
                path=path,
                params=MappingProxyType(_params(r, path, item, op)),
                scope_sets=_scope_sets(op),
                tags=tuple(op.get("tags", [])),
                response=_response(r, op),
            )
    return SpecIndex(
        version=str(spec["info"]["version"]),
        operations=MappingProxyType(operations),
        non_get=MappingProxyType(non_get),
    )


def load_spec() -> SpecIndex:
    return build_index(yaml.load(SPEC.read_bytes(), Loader=yaml.CSafeLoader))
