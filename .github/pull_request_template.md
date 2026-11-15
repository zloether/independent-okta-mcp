<!-- See AGENTS.md "Working a step" and docs/implementation-plan.md "How to work a step".
     Delete lines that don't apply; don't leave a box unchecked without saying why. -->

## Step

<!-- Plan step ID and title, e.g. "7.3 Runbook". Say if the step stays ◐ and what is left. -->

## What changed

<!-- A few lines: what and why. Point to the decisions-log rows rather than repeating them. -->

## Trust boundary

<!-- Does this touch a path listed under "Trust boundaries" in AGENTS.md (🔒 steps)? Name the files, or write "None". -->

- [ ] Read-only invariant holds: no new path in `src/` that sends anything but GET to Okta
- [ ] Nothing widens access on error or missing config (fail closed)

## Reviews

- [ ] `/code-review` (level: ) — outcome recorded in the decisions log
- [ ] `/security-review` (required if a trust boundary is touched, including commits that fix review findings) — outcome recorded
- [ ] Findings fixed, or the decisions log says why not

## Checks

- [ ] `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest`
- [ ] `uv lock --check`
- [ ] The step's **Verify** block passes, or the parts that can't run here are listed below

## Docs

- [ ] Plan step status and `docs/decisions-log.md` updated
- [ ] Design doc updated in this PR if the step changes it
- [ ] Delegated work (subagents) named in the decisions log

## License

- [ ] I agree to [CONTRIBUTING.md](../CONTRIBUTING.md#license-of-contributions) for this contribution (the maintainer's own pull requests: delete this section)

## Not done here

<!-- Live or dev-org checks, manual verification, follow-ups added to the plan. "None" if nothing. -->
