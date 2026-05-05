# AGENTS.md

This repository ships a standards-compatible Agent Skill for
`bonsai-ninja` usage:

```text
.agents/skills/bonsai-ninja/SKILL.md
```

Agents that support skills should load that skill for `bonsai-ninja`.
The skill is organized around three jobs you can ask the tool to do:

1. **Understand the codebase (map it)** - entry points, architecture,
   data flow, dependencies, configs.
2. **Debug & fix issues** - reproduce bugs, trace root cause, patch
   with tests.
3. **Security review** - check auth, input validation, secrets,
   dependencies, and attack surfaces.

Each job has its own command sequence in the skill (search for "Job 1",
"Job 2", "Job 3"). The supporting commands - inspect, trace, export,
source-analysis, taint-analysis, pagination - are referenced from those
sections.

Agents that do not support skills should read `SKILLS.md` for the same
workflow guidance.

Operational defaults:

- Prefer `./target/release/bonsai-ninja` when present.
- Run `index <workspace>` before inspect, trace, security, export, or
  debug work unless the user explicitly requests a cold lazy run.
- Use `--format json --no-color --no-progress` for machine-consumed
  output.
- Use explicit text budgets such as `--context 16k` for LLM-readable
  review pages.
- Treat pagination as correctness: if a footer says more pages exist,
  continue with `--page`, `--page next`, or the printed `P:xxxxxxxx`
  cursor and report which pages were reviewed.
