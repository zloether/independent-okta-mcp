# Contributing

Issues and pull requests are welcome. For a suspected vulnerability, use [SECURITY.md](SECURITY.md) instead of a public issue.

## Before you start

- The project is pre-alpha and follows a written [plan](docs/implementation-plan.md). For anything larger than a fix, open an issue first so the change can be placed in it.
- [`AGENTS.md`](AGENTS.md) holds the rules every change follows, for people as well as coding agents: the read-only invariant, registry first, fail closed, tests with every change, and the list of trust boundaries.

## Making a change

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
uv lock --check
```

- Tests mock all HTTP. Fixtures use only `example.okta.com` and `*.example.com`; never commit a real org's hostname, IDs, tokens or response bodies. Recorded responses go through `scripts/sanitize-fixture.py`.
- A new command is a registry entry (`src/okta_mcp/data/registry/`) with its `data_classes`, a fixture and a line in the domain's guide, not code.
- A change to a trust boundary gets a security review before merge; say in the pull request which paths it touches. The [pull request template](.github/pull_request_template.md) lists the rest.
- If the change alters behavior an operator sees, update [`docs/runbook.md`](docs/runbook.md) or [`docs/okta-setup.md`](docs/okta-setup.md) with it, and add a line to [`CHANGELOG.md`](CHANGELOG.md).

## License of contributions

The project is licensed under Apache-2.0 with the Commons Clause ([LICENSE](LICENSE)). By submitting a contribution you agree that it is licensed under those same terms, as Apache-2.0 §5 provides.
