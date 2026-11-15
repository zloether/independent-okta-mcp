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

The project is licensed under Apache-2.0 with the Commons Clause ([LICENSE](LICENSE)), and the licensor may change that license later. So that a contribution never blocks such a change, by submitting one (a pull request, a patch, or text in an issue meant for inclusion) you agree that:

1. it is your own work, or you have the right to submit it under these terms;
2. it is licensed to everyone under the project's license as it stands when you submit it; and
3. you also grant the licensor named in [LICENSE](LICENSE) a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, modify, sublicense and relicense it under any terms, including terms other than the project's current license.

You keep the copyright in your contribution. If you can't agree to this, open an issue describing the change instead of sending code.
