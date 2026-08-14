# Contributing

Thank you for improving bonsai-ninja. Start with the complete
[contributor guide](docs/contributing/contributing.mdx) and
[review checklist](docs/contributing/review-checklist.mdx). By participating,
you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

Keep compiler syntax in language adapters, keep security and framework meaning
in rule data, and keep shared analysis language-neutral. Changes should include
the smallest positive and negative tests that prove the behavior.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Use the bug form for CLI, cache, parser, or output defects.
- Use the analysis-quality form for false positives, false negatives,
  incomplete resolution, or language-adapter gaps. Include completion metadata
  and a minimal source example that you are authorized to publish.
- Discuss broad architecture or new-language work before implementing it. A
  new frontend commits the project to a grammar, lowering contract,
  conformance fixtures, rule coverage, performance gates, and maintenance.
- Report exploitable analyzer or release-process vulnerabilities through
  [SECURITY.md](SECURITY.md), not through a public issue.

## Pull requests

Keep each pull request focused and explain the user-visible behavior it
changes. Include:

- positive and negative tests for semantic changes;
- documentation for public CLI, SDK, rule-schema, output, or cache changes;
- the exact validation commands run and their results;
- an explicit note when static evidence remains incomplete or a release gate
  could not be run.

Do not commit credentials, private corpora, generated workspace caches,
benchmark checkouts, Cargo build output, or local editor state. Do not weaken a
correctness or performance gate to make a regression pass.

Before opening a pull request, run the gates appropriate to the changed
surface. The authoritative command list and current validation status are in
[Release Readiness](docs/RELEASE_READINESS.md). At minimum, documentation-only
changes must pass:

```bash
python3 scripts/audit-docs.py
python3 scripts/sync_skill.py --check
cargo fmt --all -- --check
```

The pull-request template links the additional gates for compiler, adapter,
security, dependency, release-workflow, and large-workspace changes.
