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
- `audit-corpus-independence.py` — rejects fixture identities from production
  logic and developer-home paths from production logic, rule data, and public
  documentation.
- `audit-dependency-licenses.py` — validates licenses across the locked Cargo dependency graph.
- `audit-docs.py` — checks every tracked Markdown surface, links, navigation,
  public wording, copied prose, command shapes, repository-derived counts,
  rule vocabulary, disabled-rule examples, and this script inventory.
- `audit-github-actions.sh` — enforces immutable GitHub Action references and
  release-workflow requirements.
- `audit-hardcoded.sh` — enforces the adapter/rulepack ownership boundary for
  language and security knowledge.
- `audit-layering.sh` — validates the workspace crate dependency DAG through
  Cargo metadata (including renamed, inherited, build, and platform-specific
  dependencies). Uses Python 3; `python3 scripts/tests/test_audit_layering.py` runs
  its regression checks without building crates.
- `audit-layering.py` — implements the dependency-tier checks using canonical
  Cargo package identities, including workspace-inherited and renamed edges.
- `audit-loop.sh` — runs the combined rulepack, fixture, sanitizer, taint-engine,
  CLI, and release-binary health loop. If the release binary is missing it
  bootstraps through `build-release.sh`. Correctness tests use the compact
  test profile and invoke the release CLI without replacing the distributable.
- `audit-public-api.sh` — compares crate-root public declaration lines with the
  checked-in snapshot. This lightweight check does not resolve re-exports or
  validate nested types, fields, or method signatures; keep the SDK contract
  tests and normal compilation as separate requirements.
- `audit-release-metadata.py` — validates public Cargo package and repository metadata.
- `audit-release-binary.py` — rejects distributable binaries that retain the
  builder's checkout, home, or Cargo source path.
- `publish-crates.py` — audits the crates.io package graph with the
  read-only `--check-registry` mode and performs an explicit, resumable
  dependency-ordered publication with `--publish --resume
  --confirm-version <VERSION>` when requested. The audit checks every
  publishable package's repository, owner, exact version, and production
  dependency order. Package verification uses disposable per-crate build
  storage so a workspace release cannot accumulate duplicate dependency graphs
  on the publisher runner. Registry 429 responses honor the server retry time,
  while transient connection resets and timeouts use bounded exponential
  backoff. A successful workflow run on `main` does not publish; only the
  tag-gated release job performs the upload.
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
- `pack_audit.py` — reports rulepack coverage, precision, duplicate YAML keys,
  duplicate rules, and family consistency.
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
- `validate-language-gauntlets.py` — exercises the CLI/security matrix over the
  per-language `language_gauntlet` fixtures.

## Maintenance

- `sync_skill.py` — synchronizes the canonical agent skill into the supported
  agent-tool directories.
