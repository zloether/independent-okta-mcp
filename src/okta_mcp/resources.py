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
# Case-insensitive on purpose: registry names are lower case, so `okta_Groups` is an error to
# report, not text to skip.
_TOOL = re.compile(r"\bokta_[A-Za-z0-9_]+")
_SPAN = re.compile(r"`([^`\n]+)`")
_SPAN_COMMAND = re.compile(r"(okta_[A-Za-z0-9_]+) +([A-Za-z0-9][A-Za-z0-9-]*)")
_HELP_CALL = re.compile(r'okta_help\(tool="([^"]*)", *command="([^"]*)"\)')
# Ends on a letter or digit, so a sentence's comma or full stop isn't part of the URI.
_URI = re.compile(r"okta://(?:[A-Za-z0-9/_.-]*[A-Za-z0-9])?")
_GUIDE = re.compile(r"okta://guide/(.*)")
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
    """What a resource names that doesn't exist (design §6.2 check 7): every `okta_<x>` must be
    a tool of this server; a backticked `okta_<tool> <command> …` and every
    `okta_help(tool="…", command="…")` must name a registry command; every `okta://` URI must be
    a reference or the guide URI of a registry domain (whether that guide exists is checked by
    `Resources`)."""
    tools = {tool_name(d): d for d in registry.domains}
    problems: list[str] = []

    def command(tool: str, name: str, where: str) -> None:
        domain = tools.get(tool)
        if domain is None:
            return  # reported by the tool-name check below, wherever the name appears
        if name not in registry.domains[domain].commands:
            problems.append(f"{where}: no command {name} in domain {domain}")

    for tool in _TOOL.findall(text):
        if tool not in tools and tool not in _EXTRA_TOOLS:
            problems.append(f"`{tool}`: not a tool of this server")
    for span in _SPAN.findall(text):
        m = _SPAN_COMMAND.match(span)
        if m is not None and m.group(1) not in _EXTRA_TOOLS:
            command(m.group(1), m.group(2), f"`{m.group(0)}`")
    for m in _HELP_CALL.finditer(text):
        command(m.group(1), m.group(2), m.group(0))
    for uri in _URI.findall(text):
        guide = _GUIDE.fullmatch(uri)
        if uri in (FILTERS_URI, EXPRESSION_LANGUAGE_URI):
            continue
        if guide is None or guide.group(1) not in registry.domains:
            problems.append(f"{uri}: not a resource of this server")
    return list(dict.fromkeys(problems))


def guide_links(text: str) -> set[str]:
    """Domains whose guide URI the text names."""
    return {m.group(1) for uri in _URI.findall(text) if (m := _GUIDE.fullmatch(uri))}


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
        for resource in [*references, *guides.values()]:
            problems += [
                f"{resource.name}: names {GUIDE_URI.format(domain=d)}, which has no guide file"
                for d in sorted(guide_links(resource.text))
                if d in registry.domains and d not in guides
            ]
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
