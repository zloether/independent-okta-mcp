@AGENTS.md

## Claude Code: models for subagents

For "Working with subagents" in AGENTS.md. Pick by tier, using the family aliases (`haiku`, `sonnet`, `opus`, `fable`) and never a version number or full model ID, so this stays valid when versions change. Tiers run cheapest/fastest to most capable; check Anthropic's current model guidance if the lineup has changed.

- **Haiku tier** for high-volume side work where a mistake is easy to spot: searches and inventories, reading logs, running the standard checks and reporting failures.
- **Sonnet tier** for well-scoped work with a clear spec: tests for an API already written, resource and guide prose, mechanical edits across files.
- **Opus tier (the session default)** for the work you keep: trust-boundary design, decisions the plan or design doc records, judging review findings. Use it too for a subagent whose task needs that judgment, such as a review or a security pass.
- **Top tier (`fable`)** only for work that is large and cross-cutting, such as a major refactor, or for leading many parallel subagents. Don't use it for a single dependent chain or anything that fits in one context.

When a subagent's output isn't good enough, escalate in this order: add a check it can run itself (tests, lint, type check), raise effort one level, then move up a tier at lower effort than before. Prefer adjusting effort over switching models when the task is the right size for the tier.
