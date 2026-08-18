# Developer scripts

This directory contains source-controlled release gates, rulepack audits, and
explicit developer harnesses. Generated reports belong in the ignored
`build/` or `target/` directories; scripts must not leave analysis caches or
temporary workspaces in the source tree.

Local shell gates require Bash, Python 3, and ripgrep (`rg`). The release
workflow provisions ripgrep explicitly, and audits that depend on it fail
closed when it is unavailable.

Every direct child tool or companion data file is listed below. The
documentation audit rejects missing and stale entries so an unexplained script
cannot silently accumulate here.

## Release and architecture gates

- `audit-adapter-capabilities.sh` — verifies the documented adapter capability matrix.
- `audit-adapter-flow-events.sh` — executes typed `FlowEvent` conformance tests for every adapter.
- `audit-build-artifacts.sh` — enforces the local and CI Cargo artifact-size budget.
- `audit-cli-docs.py` — verifies documented commands and flags against the
  release binary's help surface.
- `audit-corpus-independence.py` — rejects benchmark identities and developer
  paths in production logic.
- `audit-dependency-licenses.py` — validates licenses across the locked Cargo dependency graph.
- `audit-docs.py` — checks every tracked Markdown surface, links, navigation,
  public wording, copied prose, command shapes, repository-derived counts,
  rule vocabulary, disabled-rule examples, and this script inventory.
- `audit-github-actions.sh` — enforces immutable GitHub Action references and
  release-workflow requirements.
- `audit-hardcoded.sh` — enforces the adapter/rulepack ownership boundary for
  language and security knowledge.
- `audit-layering.sh` — validates the workspace crate dependency DAG.
- `audit-loop.sh` — runs the combined rulepack, fixture, sanitizer, and taint-engine health loop.
- `audit-public-api.sh` — compares the public Rust API surface with its checked-in snapshot.
- `audit-release-metadata.py` — validates public Cargo package and repository metadata.
- `audit-release-binary.py` — rejects distributable binaries that retain the
  builder's checkout, home, or Cargo source path.
- `publish-crates.py` — audits the crates.io package graph and performs an
  explicit, resumable dependency-ordered publication when requested. Package
  verification uses disposable per-crate build storage so a workspace release
  cannot accumulate duplicate dependency graphs on the publisher runner.
- `audit-rust-duplication.py` — rejects large exact clones in shared production Rust code.
- `audit-secrets.sh` — scans reachable Git history with a checksum-pinned Gitleaks binary.
- `audit-workflows.sh` — validates GitHub Actions syntax with a checksum-pinned Actionlint binary.
- `check-parser-bundles.py` — verifies that the locked Tree-sitter parser pack
  publishes every adapter grammar and all six native release bundles.

## Rulepack quality

- `audit_logic_alignment.py` — finds semantic classification drift and unsafe
  name-only rule shapes.
- `audit_match_example_collisions.py` — executes match examples and reports
  ownership failures or rule collisions.
- `category_audit.py` — renders per-language security-category coverage into
  ignored `build/` artifacts.
- `fp_audit.py` — scores rule shapes for likely false-positive risk.
- `pack_audit.py` — reports rulepack coverage, precision, duplicates, and family consistency.
- `pattern_variants_na.yml` — records reviewed language/category variants that are not applicable.
- `rule_example_coverage.py` — verifies that rule definitions carry required match examples.
- `sanitizer_credit_audit.py` — checks sanitizer credit metadata and tag alignment.
- `validate-pattern-pack.py` — composes schema, duplicate, example, and collision checks.

## Behavior and portability harnesses

- `check-targets.sh` — checks the release targets and optional source-build target.
- `build-release.sh` — builds the optimized CLI with deterministic path
  remapping suitable for redistribution. It keeps compiler output in the
  non-personal `/tmp/bonsai-ninja-release-target` by default, copies the final
  executable to Cargo's conventional `target/.../release/` path, and enforces
  the same generated-artifact budget there. Set
  `BONSAI_RELEASE_TARGET_DIR` to choose another non-personal build directory.
- `realworld-lang-benchmark.py` — clones one disposable real-world repository
  per supported language, validates exact taint output, and removes each
  checkout by default; `--check` validates its inventory without network
  access.
- `validate-mega-cli.py` — exercises the CLI/security matrix over the
  per-language `mega_flow` fixtures.

## Maintenance

- `sync_skill.py` — synchronizes the canonical agent skill into the supported
  agent-tool directories.
