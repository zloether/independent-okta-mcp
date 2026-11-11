"""MCP resources: model-facing guides and references (design §5.4, §6.2 check 7).

`resources/filters.md` and `resources/expression-language.md` are references every
authenticated caller sees. Every other `resources/<domain>.md` is the guide for that registry
domain, shown to callers with at least one permitted command in it. Loading checks that every
`okta_<tool> <command>` a file names exists. Every problem is collected and reported at once.
"""

import re
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable

from okta_mcp.auth.principal import Principal
from okta_mcp.exec.executor import tool_name
from okta_mcp.policy.engine import Engine
from okta_mcp.registry.loader import Registry

RESOURCES = files("okta_mcp") / "data" / "resources"
GUIDE_URI = "okta://guide/{domain}"
FILTERS_URI = "okta://reference/filters"
EXPRESSION_LANGUAGE_URI = "okta://reference/expression-language"

_EXTRA_TOOLS = frozenset({"okta_help", "okta_status"})
_COMMAND_REF = re.compile(r"`(okta_[A-Za-z0-9_]+) ([A-Za-z0-9-]+)`")
_TOOL_REF = re.compile(r"`(okta_[A-Za-z0-9_]+)(?=[` (])")
_REFERENCES = (
    (
        "filters.md",
        FILTERS_URI,
        "filters",
        "Okta list filtering",
        "How q, filter, search and sort work here.",
    ),
    (
        "expression-language.md",
        EXPRESSION_LANGUAGE_URI,
        "expression-language",
        "Okta Expression Language",
        "Help reading expressions found in results; the server never evaluates them.",
    ),
)


class ResourceError(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Resource:
    uri: str
    name: str
    title: str
    description: str
    text: str
    domain: str | None


def guide_problems(text: str, registry: Registry) -> list[str]:
    """Every `okta_<tool> <command>` reference in backticks must name a registry command, and
    every backticked `okta_<x>` tool name must be a domain tool or okta_help/okta_status."""
    tools = {tool_name(d): d for d in registry.domains}
    problems: list[str] = []
    reported: set[str] = set()
    for tool, command in dict.fromkeys(_COMMAND_REF.findall(text)):
        domain = tools.get(tool)
        if domain is None:
            if tool not in _EXTRA_TOOLS:
                problems.append(f"`{tool} {command}`: no tool {tool}")
                reported.add(tool)
        elif command not in registry.domains[domain].commands:
            problems.append(f"`{tool} {command}`: no command {command} in domain {domain}")
    for tool in dict.fromkeys(_TOOL_REF.findall(text)):
        if tool not in tools and tool not in _EXTRA_TOOLS and tool not in reported:
            problems.append(f"`{tool}`: not a tool of this server")
    return list(dict.fromkeys(problems))


def _read(entry: Traversable, problems: list[str]) -> str | None:
    try:
        return entry.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        problems.append(f"{entry.name}: not valid UTF-8")
    except OSError as exc:
        problems.append(f"{entry.name}: cannot be read ({exc.__class__.__name__})")
    return None


class Resources:
    """One per process, built at startup."""

    def __init__(
        self, registry: Registry, engine: Engine, directory: Traversable = RESOURCES
    ) -> None:
        self._engine = engine
        problems: list[str] = []
        entries = {e.name: e for e in directory.iterdir()}
        references: list[Resource] = []
        for filename, uri, name, title, description in _REFERENCES:
            entry = entries.pop(filename, None)
            if entry is None:
                problems.append(f"{filename}: required reference file is missing")
                continue
            text = _read(entry, problems)
            if text is None:
                continue
            problems += [f"{filename}: {p}" for p in guide_problems(text, registry)]
            references.append(Resource(uri, name, title, description, text, None))
        guides: dict[str, Resource] = {}
        for filename, entry in sorted(entries.items()):
            domain = filename.removesuffix(".md")
            if not filename.endswith(".md") or not entry.is_file():
                problems.append(f"{filename}: not a markdown file")
                continue
            if domain not in registry.domains:
                problems.append(f"{filename}: no registry domain {domain}")
                continue
            text = _read(entry, problems)
            if text is None:
                continue
            problems += [f"{filename}: {p}" for p in guide_problems(text, registry)]
            guides[domain] = Resource(
                GUIDE_URI.format(domain=domain),
                f"guide-{domain}",
                f"Okta {domain} guide",
                f"How to use and read the {tool_name(domain)} tool.",
                text,
                domain,
            )
        if problems:
            raise ResourceError(problems)
        self._references = tuple(references)
        self._guides = guides

    @property
    def guides(self) -> frozenset[str]:
        return frozenset(self._guides)

    def visible(self, principal: Principal) -> list[Resource]:
        domains = {domain for domain, _ in self._engine.permitted(principal)}
        return [*self._references, *(g for d, g in sorted(self._guides.items()) if d in domains)]

    def read(self, principal: Principal, uri: object) -> Resource | None:
        if not isinstance(uri, str):
            return None
        for resource in self.visible(principal):
            if resource.uri == uri:
                return resource
        return None
