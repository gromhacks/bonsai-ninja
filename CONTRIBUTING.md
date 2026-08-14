# Contributing

Thank you for improving bonsai-ninja. Start with the complete
[contributor guide](docs/contributing/contributing.mdx) and
[review checklist](docs/contributing/review-checklist.mdx).

Keep compiler syntax in language adapters, keep security and framework meaning
in rule data, and keep shared analysis language-neutral. Changes should include
the smallest positive and negative tests that prove the behavior.

Before opening a pull request, run the gates appropriate to the changed
surface. The authoritative command list and current validation status are in
[Release Readiness](docs/RELEASE_READINESS.md). Never commit credentials,
private source corpora, generated analysis caches, or benchmark checkouts.

Report exploitable vulnerabilities through the private process in
[SECURITY.md](SECURITY.md), not through a public issue.
