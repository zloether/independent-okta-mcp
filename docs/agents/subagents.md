# Working with subagents

Read before delegating. Delegate well-specified, bounded work to a lower-cost model; do it yourself when explaining it would take as long.

- **Delegate:** tests for an API already written; resource and guide prose; mechanical edits across files; searches and inventories; running checks and reporting failures.
- **Keep:** design of trust-boundary code, choices the plan or design doc records, judging review findings, anything a later step depends on.
- **Brief fully.** A subagent starts with none of your context: give the exact API or contract, design and plan refs, what to cover, and the checks to pass.
- **One owner per file.** Name the files it may create or edit; other files, the plan, the decisions log and the design doc stay yours. Subagents don't commit, push, stash, reset or check out. Parallel subagents get disjoint files.
- **No fixing around bugs.** A subagent that finds a bug in code it didn't write reports it with a failing or `xfail(strict=True)` test and leaves that code alone.
- **Review what comes back.** Read the diff, check claims about Okta and this repo against the code, rerun the checks. Its output gets the same `/code-review` and `/security-review` as yours; the decisions log says what was delegated.

## Claude Code: model tiers

Use family aliases (`haiku`, `sonnet`, `opus`, `fable`), never a version or full model ID. Check Anthropic's current model guidance if the lineup has changed.

- **Haiku:** high-volume side work where mistakes are easy to spot: searches, inventories, reading logs, running checks.
- **Sonnet:** well-scoped work with a clear spec: tests for an existing API, guide prose, mechanical edits.
- **Opus (session default):** work you keep: trust-boundary design, recorded decisions, judging findings; also review and security-pass subagents.
- **Fable:** only large cross-cutting work (a major refactor) or leading many parallel subagents; not a single dependent chain or anything that fits one context.

If output isn't good enough: add a check it can run (tests, lint, types), then raise effort one level, then move up a tier at lower effort. Prefer adjusting effort when the task suits the tier.
