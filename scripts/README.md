# scripts/

Tools run by hand from a checkout, never by the server. Run each from the repo root with `uv run python scripts/<name>`; each script's docstring has the full detail.

| File | Who runs it | What it does |
|---|---|---|
| [`okta-setup.py`](okta-setup.py) | Okta admin | Checks, or creates, the Okta objects the server needs |
| [`okta-setup.example.yaml`](okta-setup.example.yaml) | Okta admin | Example config for `okta-setup.py` |
| [`okta-probe.py`](okta-probe.py) | Okta admin | Shows which Okta endpoints the server's service app can read, and why not |
| [`update-spec.py`](update-spec.py) | Maintainer | Pins a newer Okta Management OpenAPI spec |
| [`gen-fixtures.py`](gen-fixtures.py) | Developer | Generates per-command test fixtures from the pinned spec |
| [`sanitize-fixture.py`](sanitize-fixture.py) | Developer | Turns a recorded dev-org response into a committable fixture |
| [`fixturelib.py`](fixturelib.py) | (library) | Host, mail and IP rewriting shared by the two fixture scripts |
| [`coverage-report.py`](coverage-report.py) | Maintainer | Writes `docs/coverage/report.md` |

Exit status, for all of them: `0` done or nothing to do, `1` work remains, drift found, or output refused, `2` error.

## okta-setup.py

Sets up the Okta side: authorization server, role groups, OIDC client apps, and the server's service app. It runs with a **Super Administrator** API token, so read [docs/okta-setup.md](../docs/okta-setup.md) first. Use this or [`terraform/okta/`](../terraform/okta/), not both, on one org.

```
cp scripts/okta-setup.example.yaml okta-setup.yaml    # edit it
export OKTA_ORG_URL=https://your-org.okta.com OKTA_SETUP_API_TOKEN=...
uv run python scripts/okta-setup.py check --config okta-setup.yaml
uv run python scripts/okta-setup.py apply --config okta-setup.yaml   # [--yes] skips the prompt
```

`check` only reads. `apply` shows its plan and asks before it creates missing objects and links. It never deletes or loosens anything; other differences are reported for you to fix by hand. The setup token is for this script only; never give it to the server.

## okta-probe.py

Sends one GET per Management API path with the server's own service app settings and code (`OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY_FILE`, `OKTA_KEY_ID`, `OKTA_SCOPES`, `OKTA_DPOP`), and prints each status with Okta's error code. Use it to check the admin role a scope needs on your org ([docs/okta-setup.md](../docs/okta-setup.md)): `E0000006` means the role is too narrow, `E0000015` that the org lacks the feature.

```
uv run python scripts/okta-probe.py /api/v1/mappings /api/v1/meta/schemas/user/default
```

It prints no token, body, field value or Okta error text. Besides the service token request, it sends only GET. Give paths percent-encoded, as they are to be sent.

## update-spec.py

Downloads the Okta Management spec from GitHub and pins it under `src/okta_mcp/data/specs/` with `PINNED.json` (commit, version, sha256). Prints the GET operations added, removed or changed since the last pin.

```
uv run python scripts/update-spec.py --check    # report only
uv run python scripts/update-spec.py [--ref REF]
```

After a re-pin, run `gen-fixtures.py` and the tests.

## gen-fixtures.py

Writes `tests/fixtures/<domain>/<command>.json` for every registry command, from the spec's response example or schema. Output is deterministic, with reserved hosts and Okta-shaped IDs. Never overwrites a recorded fixture.

```
uv run python scripts/gen-fixtures.py [--domain NAME]
uv run python scripts/gen-fixtures.py --check   # list missing, stale or orphaned fixtures
```

## sanitize-fixture.py

For endpoints where a generated fixture isn't realistic enough: record the raw response body from a dev org, then rewrite hosts, mail, IPs, Okta IDs, person fields and the org's subdomain.

```
uv run python scripts/sanitize-fixture.py recording.json --operation listJwk \
    --out tests/fixtures/<domain>/<command>.json [--replace "Acme Corp=Example Co" ...]
```

Use `--replace` for anything no rule can know (company names, custom domains). It refuses to write output that fails `tests/test_fixture_hygiene.py`, but **read the result before committing**: free text in `name` and `description` fields isn't caught.

## coverage-report.py

Compares the catalogue (`docs/coverage/catalogue.yaml`), the registry and the pinned spec, and writes `docs/coverage/report.md`: which catalogue entries have commands, registry commands outside the catalogue, and spec GET operations neither covers. Informational, not a CI gate.

```
uv run python scripts/coverage-report.py [--catalogue PATH] [--out PATH]
```
