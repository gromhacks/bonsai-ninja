# Goal Benchmark - 2026-05-15

Benchmark run for `docs/goal.md` using `./target/release/bonsai-ninja`.

Historical note: this benchmark predates the later `index` contract change.
At the time of these measurements, default `index <workspace>` was a
structural parse/index pass. Current builds use plain `index` as the semantic
sidecar warm-up path and expose the old cheap behavior as `--structural-only`.

Full JSON reports:

- `target/goal-benchmark-examples.json`
- `target/goal-benchmark-crates.json`
- `target/goal-benchmark-large.json`

Harness commands:

```shell
python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target examples=examples \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-examples.json

python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target crates=crates \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-crates.json

python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target redis=benchmarks/redis \
  --target owasp=benchmarks/owasp-benchmark \
  --runs 1 \
  --timeout-sec 180 \
  --rss-limit-mb 2048 \
  --output target/goal-benchmark-large.json
```

All measured steps completed with `status=ok` and exit code `0`.

Direct check for the original hang report:

```shell
/usr/bin/time -l ./target/release/bonsai-ninja index crates --no-progress
```

The command completed successfully in `1.16s` real time with
`169,361,408` bytes maximum resident set size and reported `427` files.
The later 2026-06-02 verification also cleaned the polluted generated
`target/` tree that caused local Rust test harnesses to stall in `_dyld_start`;
fresh default-target harnesses launched normally and
`cargo test --workspace --no-fail-fast` completed successfully.
The same release-readiness pass reran focused real-world checks against fresh
`/tmp` clones that were deleted afterward: Redis `dump-taint` completed in
17.01s with 10,278 complete narrowed records, and OWASP Benchmark Java
completed `index` in 1.50s, production `source-analysis --all` in 19.44s
with 1,125 complete rows, and production `taint-analysis --all` in 45.80s
with 1,655 complete findings.

## Summary

| Target | Step | Wall ms | Peak RSS bytes | Rows |
| --- | ---: | ---: | ---: | ---: |
| examples | cold index | 624 | 79,724,544 | - |
| examples | cold callgraph | 926 | 103,481,344 | 5,156 |
| examples | cold export all | 1,520 | 236,765,184 | - |
| examples | cold source-analysis | 2,228 | 376,668,160 | 3,023 |
| examples | cold taint-analysis | 3,276 | 290,291,712 | 1,277 |
| examples | warm index | 613 | 79,953,920 | - |
| examples | warm callgraph | 615 | 103,809,024 | 5,156 |
| examples | warm export repeat | 1,202 | 187,629,568 | - |
| examples | warm source-analysis | 1,625 | 322,699,264 | 3,023 |
| examples | warm taint-analysis | 2,937 | 244,891,648 | 1,277 |
| crates | cold index | 1,332 | 160,366,592 | - |
| crates | cold callgraph | 3,091 | 238,583,808 | 8,521 |
| crates | cold export all | 39,364 | 829,505,536 | - |
| crates | cold source-analysis | 2,552 | 368,869,376 | 0 |
| crates | cold taint-analysis | 2,649 | 364,871,680 | 0 |
| crates | warm index | 1,316 | 161,562,624 | - |
| crates | warm callgraph | 1,285 | 241,025,024 | 8,521 |
| crates | warm export repeat | 10,101 | 635,125,760 | - |
| crates | warm source-analysis | 2,630 | 369,967,104 | 0 |
| crates | warm taint-analysis | 2,692 | 366,788,608 | 0 |
| redis | cold index | 1,407 | 185,532,416 | - |
| redis | cold callgraph | 3,185 | 285,851,648 | 6,598 |
| redis | cold export all | 11,599 | 1,681,244,160 | - |
| redis | cold source-analysis | 4,098 | 769,572,864 | 14 |
| redis | cold taint-analysis | 4,747 | 765,067,264 | 0 |
| redis | warm index | 1,613 | 192,610,304 | - |
| redis | warm callgraph | 1,630 | 282,017,792 | 6,598 |
| redis | warm export repeat | 9,739 | 1,543,520,256 | - |
| redis | warm source-analysis | 1,974 | 567,754,752 | 14 |
| redis | warm taint-analysis | 2,623 | 580,222,976 | 0 |
| owasp | cold index | 1,704 | 176,357,376 | - |
| owasp | cold callgraph | 3,421 | 279,986,176 | 7,798 |
| owasp | cold export all | 9,591 | 818,921,472 | - |
| owasp | cold source-analysis | 11,250 | 818,937,856 | 1,266 |
| owasp | cold taint-analysis | 29,673 | 895,647,744 | 8,213 |
| owasp | warm index | 1,699 | 175,063,040 | - |
| owasp | warm callgraph | 1,927 | 274,579,456 | 7,798 |
| owasp | warm export repeat | 4,157 | 662,487,040 | - |
| owasp | warm source-analysis | 6,519 | 646,545,408 | 1,266 |
| owasp | warm taint-analysis | 24,112 | 724,631,552 | 8,213 |

## Cache Evidence

| Target | Warm cache bytes | Final cache bytes |
| --- | ---: | ---: |
| examples | 8,961,207 | 8,961,207 |
| crates | 55,276,853 | 55,276,853 |
| redis | 58,908,230 | 58,908,230 |
| owasp | 50,233,092 | 50,233,092 |

The benchmark harness now keeps the raw `cache stats` JSON and derives a
compact `cache_summary` object for each run. It reports initial, warm, and
final sidecar presence and byte counts for dataflow legacy, dataflow
factstore, value-flow, flow-id, callgraph, IDG, taint-graph, and export
artifacts. It also reports `warm_speedups`, comparing warm command wall time
and RSS against the matching cold command.

Harness smoke:

```shell
python3 -m py_compile scripts/goal_benchmark.py
python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target micro=examples/python/micro \
  --runs 1 \
  --timeout-sec 60 \
  --rss-limit-mb 512 \
  --output target/goal-benchmark-cache-summary-smoke.json
jq '.targets[0].runs[0] | {cache_summary, warm_speedups}' \
  target/goal-benchmark-cache-summary-smoke.json
```

The smoke completed with `status=ok`/exit code `0`. Its derived summary showed
an empty initial cache, warm/final `callgraph` and `idg` sidecars present,
`8,111` final cache bytes, and warm-speedup entries for index, callgraph,
export-all, source-analysis, and taint-analysis.

## Precision Spot Checks

Additional semantic-only checks on the real benchmark directories:

```shell
./target/release/bonsai-ninja dump-edges crates --format json --no-color --no-progress
./target/release/bonsai-ninja dump-edges examples --format json --all --no-color --no-progress
./target/release/bonsai-ninja dump-edges benchmarks/redis --format json --all --no-color --no-progress
./target/release/bonsai-ninja dump-edges benchmarks/owasp-benchmark --format json --all --no-color --no-progress
./target/release/bonsai-ninja security benchmarks/redis taint-analysis --profile production --format json --all --no-color --no-progress
./target/release/bonsai-ninja security benchmarks/owasp-benchmark taint-analysis --profile production --format json --all --no-color --no-progress
/usr/bin/time -l ./target/release/bonsai-ninja security benchmarks/owasp-benchmark source-analysis --profile production --format json --all --no-color --no-progress
/usr/bin/time -l ./target/release/bonsai-ninja export examples --format json --all --no-color --no-progress
/usr/bin/time -l ./target/release/bonsai-ninja export crates --format json --all --no-color --no-progress
```

Observed precision counts:

| Target | Command | Precision counts |
| --- | --- | --- |
| crates | dump-edges | `17,268 narrowed` |
| examples | dump-edges | `3,386 narrowed` |
| redis | dump-edges | `30,401 narrowed` |
| owasp | dump-edges | `7,871 narrowed` |
| redis | production taint-analysis | `0 findings` |
| owasp | production taint-analysis | `838 exact`, `7,375 narrowed` |
| owasp | production source-analysis `--all` | `1,340 complete rows`, `0 omitted lineage paths` |
| examples | native export `--all` | `analysis_complete=true`, `0 chain truncations`, `0 flow-id-label truncations`, `3,386 narrowed callgraph edges` |
| crates | native export `--all` | `analysis_complete=true`, `0 chain truncations`, `0 flow-id-label truncations`, `17,268 narrowed callgraph edges` |

No `over-approximate` or `unknown` precision rows were observed in these semantic command outputs.
Post Rust path-aware import verification:

- Redis `dump-edges --all`: `30,401 narrowed`, `0` duplicate edge rows,
  `23.82s` real time, `338,395,136` bytes max RSS.
- OWASP `dump-edges --all`: `7,871 narrowed`, `0` duplicate edge rows,
  `4.41s` real time, `292,405,248` bytes max RSS.
- Redis production `source-analysis --all`: `23` complete rows,
  `214` emitted lineage paths, `0` omitted lineage paths, `3.31s` real
  time, `573,161,472` bytes max RSS.
- OWASP production `source-analysis --all`: `1,340` complete rows,
  `19,775` emitted lineage paths, `0` omitted lineage paths, `7.00s`
  real time, `622,280,704` bytes max RSS.
- Redis production `taint-analysis --all`: `0` findings, `4.52s` real
  time, `573,079,552` bytes max RSS.
- OWASP production `taint-analysis --all`: `8,213` findings
  (`838 exact`, `7,375 narrowed`), `25.03s` real time, `693,403,648`
  bytes max RSS.

Examples native export `--all` completed in `1.57s` real time with
`186,810,368` bytes max RSS and an empty `analysis_incomplete_reasons`
array.
Crates native export `--all` completed in `41.86s` real time with
`953,810,944` bytes max RSS. The exact output was `2.8G`, so validation
used streaming JSON reads; completeness fields were true/zero and callgraph
precision was semantic-only (`narrowed`).
After the typed-receiver fallback fix, `dump-edges crates` no longer
resolves local receiver chains such as `cache.funcs.get(...)` through
unaliased workspace module-path fallback; the false
`cached_export_func_render -> get` edges are gone and duplicate resolved
rows are `0`.
After the Rust path-aware import fix, flat checked-out workspaces such as
`examples/rust/micro` resolve `crate::micro::user_service::{get_user}` by
the target file path instead of by a broad leaf-name retry; the Rust micro
fixture now emits the five expected narrowed workspace edges with duplicate
edge rows at `0`.

Additional OWASP duplicate-fact check after declaration dedupe:

```shell
./target/release/bonsai-ninja defs benchmarks/owasp-benchmark --format json --all --no-color --no-progress
./target/release/bonsai-ninja dump-edges benchmarks/owasp-benchmark --format json --all --no-color --no-progress
```

Observed duplicate declaration groups: `0`. Observed duplicate edge groups
for `(caller, callee, call site, kind, precision)`: `0`. Max unique callees
per rendered call site: `2`, from minified JavaScript callback/indirect-call
shapes rather than Java OWASP servlet fan-out.

Additional OWASP debug-resolution check:

```shell
./target/release/bonsai-ninja dump-resolve benchmarks/owasp-benchmark doPost --format json --no-color --no-progress
./target/release/bonsai-ninja dump-resolve benchmarks/owasp-benchmark doPost --in-file BenchmarkTest00001.java --format json --no-color --no-progress
```

Contextless `doPost` is marked `analysis_complete: false` with
`context-required:doPost` and `2,740` inventory candidates. With
`--in-file BenchmarkTest00001.java`, it narrows to `1` candidate and
reports `analysis_complete: true`.

## Latest Examples Regression Check

After making SDK/workspace default indexing structural in the May 2026
benchmark branch and keeping semantic analysis explicit/on demand at that
time, the primary `examples/` target was rerun with:

```shell
python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target examples=examples \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-examples-latest.json
```

All measured steps completed with `status=ok` and exit code `0`.

| Step | Wall ms | Peak RSS bytes | Rows |
| --- | ---: | ---: | ---: |
| cold index | 623 | 79,577,088 | - |
| cold callgraph | 929 | 105,283,584 | 5,154 |
| cold export all | 1,524 | 234,848,256 | - |
| cold source-analysis | 2,481 | 397,295,616 | 3,473 |
| cold taint-analysis | 3,625 | 289,898,496 | 1,311 |
| warm index | 613 | 80,134,144 | - |
| warm export all build | 1,234 | 183,566,336 | - |
| warm export all repeat | 1,197 | 184,205,312 | - |
| warm callgraph | 626 | 104,480,768 | 5,154 |
| warm source-analysis | 1,887 | 350,093,312 | 3,473 |
| warm taint-analysis | 2,955 | 249,626,624 | 1,311 |

The latest examples taint-analysis precision distribution was
semantic-only: `710 exact`, `601 narrowed`, `0 over-approximate`, and
`0 unknown`.

The original hang target was also rerun as a full cold/warm benchmark:

```shell
python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target crates=crates \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-crates-latest.json
```

All measured `crates` steps completed with `status=ok` and exit code
`0`.

| Step | Wall ms | Peak RSS bytes | Rows |
| --- | ---: | ---: | ---: |
| cold index | 1,323 | 157,466,624 | - |
| cold callgraph | 4,321 | 242,941,952 | 8,589 |
| cold export all | 41,839 | 991,526,912 | - |
| cold source-analysis | 2,852 | 387,235,840 | 0 |
| cold taint-analysis | 2,573 | 373,112,832 | 0 |
| warm index | 1,349 | 161,103,872 | - |
| warm export all build | 11,304 | 784,908,288 | - |
| warm export all repeat | 11,310 | 764,461,056 | - |
| warm callgraph | 1,294 | 245,186,560 | 8,589 |
| warm source-analysis | 2,725 | 381,435,904 | 0 |
| warm taint-analysis | 2,644 | 373,489,664 | 0 |

## Current Release Verification After Cache Metadata Hardening

After replacing depth-limited dependency-metadata cache scans with the shared
unbounded walker and removing the `security deps` manifest depth cap, the
release CLI was rebuilt with:

```shell
cargo build -q --release -p bonsai_cli
```

Focused checks:

```shell
cargo fmt --all --check
git diff --check
cargo test -q -p bonsai_common dependency_metadata
cargo test -q -p bonsai_workspace --lib dependency_metadata_fingerprint_tracks_deep_nested_manifest
cargo check -q -p bonsai_lang_api
cargo check -q -p bonsai_security --lib
cargo check -q -p bonsai_security --test dependency_inventory
```

All checks above passed. At this point in the historical run, newly built
`cargo test -p bonsai_security` binaries blocked before Rust test harness
startup in macOS `dyld` (`_dyld_start` in `sample` output), while release CLI
binaries launched and ran normally. This was later resolved by cleaning the
polluted generated `target/` tree; see the later "Default target verification"
section and `docs/rule-testing.mdx`.

Current direct index timings:

| Target | Command | Real time | Max RSS bytes | Files |
| --- | --- | ---: | ---: | ---: |
| examples | `index examples --no-progress` | `0.41s` | `80,379,904` | `625` |
| crates | `index crates --no-progress` | `1.59s` | `168,214,528` | `429` |
| redis | `index benchmarks/redis --no-progress` | `1.27s` | `192,167,936` | `325` |
| owasp | `index benchmarks/owasp-benchmark --no-progress` | `1.55s` | `176,553,984` | `2,770` |

Current OWASP production taint verification:

```shell
/usr/bin/time -l ./target/release/bonsai-ninja \
  security benchmarks/owasp-benchmark taint-analysis \
  --profile production --format json --all --no-color --no-progress \
  > /tmp/owasp_taint_all_current.json
```

The command completed in `23.53s` real time with `692,125,696` bytes maximum
resident set size. It emitted `8,213` rows with semantic-only precision:
`838 exact`, `7,375 narrowed`, `0 unknown`, and `0 over-approximate`. No
`diagnostic-precision-step`, `unknown`, or over-approximation markers were
present in the full `--all` JSON output.

Current deep dependency-metadata smoke:

```shell
tmp=$(mktemp -d /tmp/bonsai-deep-deps.XXXXXX)
mkdir -p "$tmp/a/b/c/d/e/module"
printf 'sqlite3==3.0.0\n' > "$tmp/a/b/c/d/e/module/requirements.txt"
printf 'print("placeholder")\n' > "$tmp/app.py"
./target/release/bonsai-ninja security "$tmp" deps \
  --severity high --format json --all --no-color --no-progress
```

The release CLI reported a `sqlite3` dependency row with evidence from
`a/b/c/d/e/module/requirements.txt`, proving the user-facing dependency
inventory no longer misses manifests below the previous depth-4 traversal cap.

## Latest Large-Target Regression Check

After making export completeness explicit and adding dense-graph compressed
callgraph mode for full-workspace chain evidence, the Redis and OWASP targets
were rerun with:

```shell
python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target redis=benchmarks/redis \
  --target owasp=benchmarks/owasp-benchmark \
  --runs 1 \
  --timeout-sec 180 \
  --rss-limit-mb 2048 \
  --output target/goal-benchmark-large-latest.json
```

All measured large-target steps completed with `status=ok` and exit code
`0`.

| Target | Step | Wall ms | Peak RSS bytes | Rows |
| --- | --- | ---: | ---: | ---: |
| redis | cold index | 1,379 | 191,578,112 | - |
| redis | cold callgraph | 3,088 | 286,556,160 | 6,598 |
| redis | cold export all | 23,323 | 1,936,310,272 | - |
| redis | cold source-analysis | 4,060 | 750,895,104 | 23 |
| redis | cold taint-analysis | 4,728 | 758,415,360 | 0 |
| redis | warm index | 1,350 | 194,363,392 | - |
| redis | warm export all build | 21,074 | 1,669,742,592 | - |
| redis | warm export all repeat | 20,734 | 1,876,049,920 | - |
| redis | warm callgraph | 1,352 | 278,528,000 | 6,598 |
| redis | warm source-analysis | 2,169 | 592,084,992 | 23 |
| redis | warm taint-analysis | 2,914 | 593,985,536 | 0 |
| owasp | cold index | 1,679 | 175,079,424 | - |
| owasp | cold callgraph | 3,549 | 275,021,824 | 7,683 |
| owasp | cold export all | 9,182 | 794,427,392 | - |
| owasp | cold source-analysis | 11,457 | 796,655,616 | 1,340 |
| owasp | cold taint-analysis | 29,378 | 867,713,024 | 8,213 |
| owasp | warm index | 1,684 | 176,193,536 | - |
| owasp | warm export all build | 4,030 | 618,741,760 | - |
| owasp | warm export all repeat | 4,092 | 627,834,880 | - |
| owasp | warm callgraph | 2,014 | 267,730,944 | 7,683 |
| owasp | warm source-analysis | 6,035 | 636,239,872 | 1,340 |
| owasp | warm taint-analysis | 24,257 | 704,380,928 | 8,213 |

Redis `export --all` now completes without path truncation by switching dense
complete exports to an exact compressed callgraph representation instead of
materializing every simple path. A direct release smoke with
`BONSAI_DEBUG=export-phase` completed in `18.42s` with `716,816,384` bytes
maximum resident set size. The debug log reported:

```text
flow sections: chains=0 graph_nodes=6598 truncated_targets=0 mode=compressed_callgraph
taint.chains: count=0 truncated_targets=0 mode=compressed_callgraph
taint.flow_id_labels: count=0 truncated_functions=0 mode=compressed_callgraph
```

The generated Redis JSON streamed as `5,448,723,631` bytes and reported
`analysis_complete=true`, `analysis_incomplete_reasons=[]`,
`flow_chains_complete=true`, and `flow_chains_truncated_targets=0`.
Small targets such as `examples --all` still use `enumerated_paths` /
`materialized_flow_ids` and report zero truncation.

The benchmark harness now records the `export_phase_summary` from
`BONSAI_DEBUG=export-phase` for discarded large export stdout. This preserves
the chain mode, truncation counts, propagation completeness, and derived
`analysis_complete_from_phases` evidence without needing to retain multi-GB
JSON output in the benchmark report.

OWASP `export --all` remained fully complete after the guard change:
`analysis_complete=true`, `0` flow-chain truncations, `0` taint-chain
truncations, and `0` flow-id-label truncations. OWASP production
taint-analysis stayed semantic-only with `838 exact`, `7,375 narrowed`,
`0 over-approximate`, and `0 unknown` findings.

## Finding Completeness Scope Regression

The OWASP taint report previously over-propagated unresolved-call
metadata: one unresolved `ESAPI.encoder().encodeForHTML` call in a source
graph marked unrelated command-injection findings incomplete. The finding
builder now scopes unresolved-call reasons to the terminal evidence
expression and combined findings merge completeness metadata from every
member finding.

Current release verification:

```shell
./target/release/bonsai-ninja security benchmarks/owasp-benchmark \
  taint-analysis --profile production --format json --all \
  --no-color --no-progress
```

Result: `8,213` findings, `8,213` complete, `0` incomplete,
`0` nonsemantic precision markers, and command-injection rows are
`62/62` complete. Runtime was `23.77s` with `627,067,520` bytes peak
footprint in the measured run.

## Current Value-Flow Return-Lineage Check

The value-flow graph builder no longer selects one arbitrary same-name node
when wiring returned values. It now tracks a small function-local definition
environment, uses strong updates for straight-line assignments, merges branch
definitions, and emits concrete call-argument nodes so cross-call propagation
starts from the actual call-site value.

Focused unit tests were added for straight-line return definitions, branch
return merges, and branch-merged call arguments. Local Cargo test/check
commands still time out before useful harness output on this machine, so the
verified build signal is the release CLI path. Release CLI verification after
the patch:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja index crates --no-progress`: `429` files,
  completed in the fast path.
- `./target/release/bonsai-ninja export examples --format json --all`:
  `analysis_complete=true`, empty incomplete reasons, `enumerated_paths`, and
  zero chain / flow-id-label truncations.
- `python3 scripts/goal_benchmark.py --binary ./target/release/bonsai-ninja
  --target examples=examples --runs 1 --timeout-sec 120 --rss-limit-mb 2048
  --output target/goal-benchmark-examples-smoke.json`: `0` failed steps;
  cold export `1,532ms`, warm export repeat `1,213ms`, cold taint-analysis
  `1,311` rows, warm taint-analysis `1,311` rows.
- `./target/release/bonsai-ninja security examples source-analysis --format
  json --all`: `3,560` rows, `0` incomplete lineage rows.
- `./target/release/bonsai-ninja security . pack --validate --format json`:
  `6,618` rules, `valid=true`, `0` errors, `0` warnings.
- `./target/release/bonsai-ninja security benchmarks/owasp-benchmark
  taint-analysis --profile production --format json --all`: `8,213` findings,
  `8,213` complete, precision `838 exact` / `7,375 narrowed`, `0`
  nonsemantic findings, `26.83s` real time, `696,074,240` bytes max RSS.

## Complete-Mode Cap Audit

The remaining complete-mode probe guard has been removed from chain
enumeration callers. `inspect --all` and native export complete-chain mode now
pass `usize::MAX` for `max_entry_probes`; the chain enumerator uses saturating
math so `usize::MAX` is a real uncapped value rather than a large finite
stand-in. Architecture invariants now guard this behavior.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `/usr/bin/time -l ./target/release/bonsai-ninja index crates
  --no-progress`: `429` files, `2.34s` real time, `165,314,560` bytes max RSS
  (`142,689,856` peak memory footprint).
- `./target/release/bonsai-ninja inspect examples --query request --kind call
  --max-hits 1 --format json`: `hits_truncated=true`,
  `hit_truncation_reasons=["max-hits output cap"]`,
  `hit_candidates_attempted=1`, `hit_attempt_cap=5`.
- `./target/release/bonsai-ninja inspect examples --query request --kind call
  --all --format json`: `417` hits, `hits_truncated=false`,
  `flow_truncated_hits=0`.
- `./target/release/bonsai-ninja export examples --format json --all`:
  `analysis_complete=true`, empty incomplete reasons,
  `flow_chains_mode=enumerated_paths`, `flow_chains_complete=true`,
  `flow_chains_truncated_targets=0`, `taint_graph.chains_mode=enumerated_paths`,
  and `taint_graph.flow_id_labels_mode=materialized_flow_ids`.
- `./target/release/bonsai-ninja dump-taint examples --source
  examples/python/micro/gateway.py:handle_request --format json`:
  `analysis_complete=true`, empty incomplete reasons, `precision=narrowed`,
  `saturated=false`, `9` propagation records.

The earlier `dump-taint --source example_security_system` smoke was invalid
because no callable with that name exists in `examples`; it was not counted as
evidence.

## Inspect Completeness Contract

`inspect` now exposes the same top-level completeness contract as the other
flow/debug/security surfaces. Capped hit lists, capped occurrence flow evidence,
and capped decl flow evidence set `analysis_complete=false` and populate
`analysis_incomplete_reasons`; `--all` on a fully enumerated query reports
complete.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja inspect examples --query request --kind call
  --max-hits 1 --format json`: `analysis_complete=false`,
  `analysis_incomplete_reasons=["inspect hit list capped by max-hits output
  cap"]`, `hits_truncated=true`.
- `./target/release/bonsai-ninja inspect examples --query request --kind call
  --all --format json`: `analysis_complete=true`, empty incomplete reasons,
  `417` hits, `hits_truncated=false`, `flow_truncated_hits=0`.

## Paged JSON Completeness Contract

Generic paged JSON emitters now include a top-level completeness verdict. When
`--context` or `--page` returns a partial row set, the wrapper includes
`analysis_complete=false` and a continuation reason; uncapped default JSON keeps
the backward-compatible bare-array shape.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja calls examples/python/micro --format json
  --context 1`: wrapper keys are `analysis_complete`,
  `analysis_incomplete_reasons`, `page`, and `rows`;
  `analysis_complete=false`, `page.is_last=false`, `rows=1`, and the reason is
  `paged calls result incomplete: page 1 of 13; continue with --page ... or
  pass --all`.
- `./target/release/bonsai-ninja calls examples/python/micro --format json`:
  default JSON remains a bare array with `13` rows.

## Security Paged JSON Completeness Contract

Security command custom JSON wrappers now match the generic paged JSON
contract. `security source-analysis`, `security sources`/`sinks`/`sanitizers`,
and `security pack` include top-level `analysis_complete` and
`analysis_incomplete_reasons` whenever `--context` or `--page` returns a
wrapped partial row set. Source-analysis also folds row-level lineage
incomplete reasons into the top-level reasons.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja security examples/python/micro
  source-analysis --rules-dir security-patterns --source '^python\\.flask\\.'
  --trust remote --format json --context 1`: wrapper keys are
  `analysis_complete`, `analysis_incomplete_reasons`, `page`, `rows`, and
  `summary`; `analysis_complete=false`, `page.is_last=false`, `rows=1`, and
  the reason is `paged security/source-analysis result incomplete: page 1 of
  5; continue with --page ... or pass --all`.
- `./target/release/bonsai-ninja security examples/python/micro sources
  --rules-dir security-patterns --format json --context 1`:
  `analysis_complete=false`, `page.is_last=false`, `rows=1`, and the reason is
  `paged security/sources result incomplete: page 1 of 2; continue with --page
  ... or pass --all`.
- `./target/release/bonsai-ninja security . pack --rules-dir security-patterns
  --format json --context 1`: `analysis_complete=false`,
  `page.is_last=false`, `rows=1`, and the reason is `paged security/pack result
  incomplete: page 1 of 6618; continue with --page ... or pass --all`.

## Structural Paged JSON Completeness Contract

Structural wrappers that do not use the generic `{rows, page}` shape now also
publish top-level completion metadata. `inspect --format json --context/--page`
and `trace --format json --context/--page` combine their command-specific
analysis verdict with page coverage so consumers do not have to know which
nested object carries the authoritative status.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja inspect examples/python/micro --query request
  --kind call --max-hits 1 --format json --context 1`:
  `analysis_complete=false`, `analysis_incomplete_reasons=["inspect hit list
  capped by max-hits output cap"]`, `page.is_last=true`, and
  `summary.hits_truncated=true`.
- `./target/release/bonsai-ninja trace examples/python/micro handle_request
  --format json --context 1 --max-steps 1`: `analysis_complete=false`,
  `analysis_incomplete_reasons=["max-steps"]`,
  `summary.analysis_complete=false`, and `page.is_last=true`.

## Graph Export Completeness Contract

Graph database exports now surface the known scope boundary as explicit
completion metadata. The graph formats export semantic structural edges and
local flow facts; exhaustive interprocedural taint propagation records remain
native-JSON-only with `--full-propagations`. NetworkX exposes this as top-level
and graph-level `analysis_complete=false` with
`analysis_incomplete_reasons`; GraphML and Cypher carry the same properties on
the Workspace node.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja export examples --format networkx`:
  `analysis_complete=false`; graph metadata also has `analysis_complete=false`;
  both reason arrays state that exhaustive interprocedural taint propagation
  records are available in native JSON with `--full-propagations`; output
  contained `35,162` nodes and `89,978` links.
- `./target/release/bonsai-ninja export examples --format graphml`: output
  contains `analysis_complete`, `analysis_incomplete_reasons`, and
  `taint_propagations_complete`.
- `./target/release/bonsai-ninja export examples --format cypher`: output
  contains `analysis_complete`, `analysis_incomplete_reasons`, and
  `taint_propagations_complete`.

## Debug Dump Completeness Contract

Debug dumps now carry the same explicit completion contract as review-facing
commands. `dump-hir` and `dump-cfg` resolve exactly one callable or fail with
an ambiguity error; successful JSON payloads include top-level
`analysis_complete=true` and `analysis_incomplete_reasons=[]` while preserving
the existing top-level HIR/CFG fields.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja dump-hir examples handle_request --no-color
  --no-progress`: failed as ambiguous across 22 callable decls, with concrete
  path-qualified disambiguators.
- `./target/release/bonsai-ninja dump-hir examples
  examples/python/micro/gateway.py:handle_request --no-color --no-progress`:
  `analysis_complete=true`, `analysis_incomplete_reasons=[]`,
  `name="handle_request"`, and non-empty `flow_events`.
- `./target/release/bonsai-ninja dump-cfg examples
  examples/python/micro/gateway.py:handle_request --no-color --no-progress`:
  `analysis_complete=true`, `analysis_incomplete_reasons=[]`,
  `function="handle_request"`, and `2` blocks.

## Cache Freshness Regression Contract

Persisted caches are treated as performance artifacts only. A new
conformance invariant maps the goal's freshness requirements to concrete
sidecar metadata and pipeline-hash code paths so future cache work cannot
drop source-content, dependency-metadata, matcher-policy, build/pipeline, or
rule/config inputs silently.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- Added `persisted_analysis_caches_bind_all_freshness_inputs` in
  `crates/conformance/tests/architecture_invariants.rs`.
- Source probe confirmed `dataflow_pipeline_hash`,
  `value_flow_pipeline_hash`, `flow_ids_pipeline_hash`, and
  `taint_graph_pipeline_hash` bind workspace content and dependency metadata;
  the taint graph hash also binds the rule/config fingerprint.
- Source probe confirmed export cache metadata carries build/pipeline version,
  matcher policy, source fingerprint, dependency metadata, and rulepack
  fingerprint, and page-cache metadata carries binary version, matcher policy,
  source fingerprint, dependency metadata, and rulepack fingerprint.
- Attempted the targeted conformance test directly; the local `cargo test`
  process stayed silent for roughly 2.5 minutes and was terminated, so it is
  not counted as a passed test in this note.

## Historical Structural Index Regression Contract

At the time of this benchmark, default `index <workspace>` remained a
structural parse/index pass. Current builds keep default `index` on that
syntax/construct path and require `index --semantic` for whole-workspace
semantic sidecar warm-up. The historical benchmark's full-workspace dataflow
prewarm was available only through the explicit `--prewarm-dataflow` path;
cache rebuild also stayed structural and warmed only bounded reusable artifacts
such as the callgraph and IDG sidecars.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- Added `default_index_path_stays_structural_without_eager_dataflow_prewarm`
  in `crates/conformance/tests/architecture_invariants.rs`.
- Historical source probe confirmed `cmd_index` routed default runs through
  `open_project_parse_only(root)?`, while `open_project_dataflow_prewarm`
  required the explicit `prewarm_dataflow` flag.
- Historical source probe confirmed `WorkspaceOpenOptions::parse_only` had
  `load_dataflow_sidecar=false`, `prewarm_dataflow=false`,
  `save_dataflow_sidecar=false`, `load_value_flow_sidecar=false`,
  `prewarm_value_flow=false`, and `prewarm_flow_ids=false`.
- `/usr/bin/time -l ./target/release/bonsai-ninja index crates
  --no-progress`: `429` files, `429` cached decl indexes, `0` cached CFGs,
  `1.59s` wall time, and `164,675,584` byte maximum resident set size.
- Attempted the targeted conformance test with `timeout 180`; it timed out
  silently with exit code `124`, so it is not counted as a passed test.

## Call-Site Inventory Scope Contract

`calls` and `args` are syntactic call-site inventory, not resolved semantic
caller-to-callee edge surfaces. To avoid mistaking name text for callgraph
evidence, `calls` JSON rows declare `resolution_scope="syntactic-call-site"`,
`args` JSON rows declare
`resolution_scope="syntactic-call-site-argument"`, and both text tables label
the first column `callee text`. Resolved semantic call edges remain on
`dump-edges` / export callgraph surfaces, which filter to exact/narrowed
precision.

Current release verification:

- `cargo fmt --all --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `./target/release/bonsai-ninja calls examples --callee os.system
  --format json --no-color --no-progress`: first row had
  `resolution_scope="syntactic-call-site"`, `callee="os.system"`, and concrete
  file/line/caller fields.
- `./target/release/bonsai-ninja calls examples --callee os.system
  --context 1k --no-color --no-progress`: text header rendered `callee text`,
  `caller`, `location`, `code`, and `flows`; pagination showed page 1 of 30.
- `./target/release/bonsai-ninja args examples --callee os.system
  --format json --no-color --no-progress`: first row had
  `resolution_scope="syntactic-call-site-argument"`, `callee="os.system"`,
  `position=0`, `value="tmp"`, and concrete file/line fields.
- `./target/release/bonsai-ninja args examples --callee os.system
  --context 1k --no-color --no-progress`: text header rendered `callee text`,
  `pos`, `arg`, `caller`, `location`, `code`, and `flows`; pagination showed
  page 1 of 30.

## Diagnostic Precision Rejection Contract

Diagnostic precision classes remain internal troubleshooting states. Public
analysis surfaces may emit exact/narrowed semantic evidence. `dump-edges`
keeps an explicit semantic precision filter for debugging edge inventory;
`security taint-analysis` has no user-facing precision mode and always uses
the semantic taint precision ceiling.

Current release verification:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- Added conformance source guard in
  `source_and_debug_flow_surfaces_are_semantic_only` to keep `dump-edges`
  broad-precision rejection and `security taint-analysis` semantic-only
  execution in place.
- `./target/release/bonsai-ninja dump-edges examples --precision
  over-approximate --format json --no-color --no-progress`: exited `1` with
  `dump-edges is semantic-only`.
- `./target/release/bonsai-ninja security examples/python/micro
  taint-analysis --rules-dir security-patterns --precision exact --format
  json --no-color --no-progress`: exited `2` with `unexpected argument
  '--precision'`.

## Constructor Ambiguity Contract

Class-name lookup no longer picks the first constructor when class routing finds
multiple constructor candidates. The resolver keeps every constructor from the
class-member index and falls through to the existing ambiguity error path, so
trace/debug callers fail clearly instead of starting from a workspace-order
winner.

Current release verification:

- `cargo fmt --all --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- Added `class_name_lookup_rejects_duplicate_constructor_candidates` in
  `crates/workspace/tests/flow_events.rs`.
- Added `class_constructor_lookup_preserves_ambiguity` in
  `crates/conformance/tests/architecture_invariants.rs` to keep class-routed
  constructor lookup from reintroducing `.first()` / workspace-order winner
  behavior.
- A temporary Python workspace with two `Widget.__init__` declarations made
  `./target/release/bonsai-ninja trace <tmp> Widget --format json --no-color
  --no-progress` exit `1` with `trace: symbol 'Widget' is ambiguous (2
  callable decls)` and both constructor candidates listed.
- A temporary Python workspace with one `Widget.__init__` declaration made the
  same trace command exit `0`, preserving normal class-name-to-constructor
  routing.

## Receiver Type Specificity Contract

Receiver and signature type matching is now directional. A concrete actual type
may satisfy a broad expected type such as `Object`, but a broad or unknown
actual type does not prove a specific receiver class or overload. This prevents
semantic callgraph edges from being created when a call-site only says
`unknown`/`Object`/`Any`.

Current release verification:

- `cargo fmt --all --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- Added `broad_actual_type_does_not_prove_specific_dispatch_type` in
  `crates/callgraph/src/lib.rs`.
- A temporary TypeScript workspace with `function entry(x: unknown) { x.run();
  }` and `class Service { run() {} }` made `dump-edges --from entry --to run
  --format json` return `0` rows.
- A temporary TypeScript workspace with `function entry(x: Service) { x.run();
  }` and the same class made `dump-edges --from entry --to run --format json`
  return `1` row.

## Completion Metadata Audit

Reviewed production `analysis_complete=true` construction sites. The remaining
production sites are exact-local facts only:

- `crates/browse/src/dumps.rs`: `dump-hir` exposes the adapter-emitted HIR for
  one already-resolved declaration; no resolver fan-out or flow solve is
  involved.
- `crates/cfg/src/builder.rs`: `build_cfg_from_flow` is exact for the supplied
  HIR event tree.
- `crates/security/src/analysis/mod.rs`: pattern-only findings are local rule
  matches, not taint/source reachability claims.

Changed `Cfg::default()` and the serde default for legacy CFGs to incomplete so
synthetic/empty CFG values cannot claim completion.

Current release verification:

- `cargo fmt --all --check`: passed.
- `cargo build -q --release -p bonsai_cli`: passed.
- `production_analysis_complete_true_sites_are_reviewed`: passed once the
  conformance test binary was already compiled (`1 passed; 44 filtered out;
  0.15s`).
- Source probe excluding `#[cfg(test)]` modules found only the three reviewed
  production `analysis_complete=true` sites listed above.

## CLI Smoke Matrix

Broader examples smoke coverage after the completion metadata and paging fixes:

- Python focused command pass: `index`, `defs`, `calls`, `args`, `classes`,
  `search`, `inspect`, `trace`, `dump-callgraph`, `dump-edges`, `dump-hir`,
  `dump-cfg`, `dump-resolve`, `dump-taint`, `security sources`, `security
  sinks`, `security sanitizers`, `security deps`, `security source-analysis`,
  `security taint-analysis`, and `export`.
- Cross-language micro matrix passed for 22 languages (`c`, `cpp`, `csharp`,
  `dart`, `elixir`, `erlang`, `go`, `java`, `javascript`, `kotlin`, `lua`,
  `objc`, `perl`, `php`, `python`, `ruby`, `rust`, `scala`, `solidity`,
  `swift`, `typescript`): each ran structural `index`, `calls --format json
  --all`, `dump-callgraph --format json --all`, and
  `security taint-analysis --format json --all`.

Historical test-harness issue:

- `cargo test -p bonsai_conformance --test architecture_invariants --no-run`
  initially compiled in `1m37s`; the exact completion-audit test then ran in
  `0.15s`.
- `cargo test -p bonsai_cli --test paging --no-run` needed a warm second run
  to finish (`2m13s` after a timed-out first compile). The compiled
  `target/debug/deps/paging-* --list --format terse` then hung for `60s` with
  no output and no meaningful CPU use. Direct release CLI commands covering the
  same paging behavior completed in under a second, so current paging evidence
  uses CLI smokes while the test-binary startup hang remains isolated.
- After later clean rebuild attempts of the generated `paging-*` artifact,
  Rust test execution still appeared environment/toolchain-blocked in this
  historical run: direct `paging-* --help` / `--list` timed out before Rust
  harness output, and bounded `cargo test -q -p bonsai_hash --lib` plus the
  focused conformance test also timed out with zero stdout/stderr. Release CLI
  execution, release build, formatting, and benchmark commands remained
  healthy. This note is superseded by the later clean-`target/` verification,
  where fresh default-target harnesses launched normally.

## Fresh Examples Benchmark

Command:

```shell
/opt/homebrew/bin/timeout 300s python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target examples=examples \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-examples-2026-05-16.json
```

Result on a temporary copy of checked-in `examples/`:

| Step | Cold wall | Warm wall | Peak RSS |
| --- | ---: | ---: | ---: |
| `index` | 0.623s | 0.632s | 76.2 MB |
| `dump-callgraph` | 0.933s | 0.626s | 100.5 MB |
| `export --all` | 1.553s | 1.225s | 221.7 MB cold / 175.9 MB warm |
| `security source-analysis` | 2.446s | 1.903s | 379.9 MB cold / 334.4 MB warm |
| `security taint-analysis` | 3.625s | 3.002s | 273.6 MB cold / 234.3 MB warm |

Cache evidence:

- Initial cache: no `.bonsai` artifacts.
- Warm/final cache: callgraph sidecar (`313,418` bytes) and IDG factstore
  (`7,550,514` bytes), `7,863,932` bytes total.
- Warm speedups: callgraph `1.491x`, export `1.268x`, source-analysis
  `1.285x`, taint-analysis `1.208x`; in this historical run, index was
  intentionally structural and roughly unchanged (`0.987x`).

## Redis Benchmark

Command:

```shell
/opt/homebrew/bin/timeout 1200s python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target redis=benchmarks/redis \
  --runs 1 \
  --in-place \
  --timeout-sec 300 \
  --rss-limit-mb 2048 \
  --output target/goal-benchmark-redis-2026-05-16.json
```

Result on local `benchmarks/redis`:

| Step | Cold wall | Warm wall | Peak RSS |
| --- | ---: | ---: | ---: |
| `index` | 1.342s | 1.303s | 184.1 MB warm |
| `dump-callgraph` | 3.174s | 1.313s | 269.4 MB cold / 265.9 MB warm |
| `export --all` | 18.124s | 16.137s | 787.6 MB cold / 658.8 MB warm |
| `security source-analysis` | 5.846s | 3.745s | 691.8 MB cold / 552.6 MB warm |
| `security taint-analysis` | 6.216s | 4.442s | 697.4 MB cold / 541.6 MB warm |

Finding/count evidence:

- Production `source-analysis --format json --all`: `23` rows.
- Production `taint-analysis --format json --all`: `0` rows.
- All benchmarked commands exited `0` within the 300s per-command guard and
  below the 2GB RSS guard.

Cache evidence:

- Initial cache already had an IDG artifact from prior local work; each cold
  phase still began with `cache clear`.
- Warm/final cache: callgraph sidecar (`1,733,468` bytes) and IDG factstore
  (`41,225,215` bytes), `42,958,683` artifact bytes total.
- Warm speedups: callgraph `2.417x`, export `1.123x`, source-analysis
  `1.561x`, taint-analysis `1.399x`, index `1.030x`.

## Java OWASP Benchmark

Target: local `benchmarks/owasp-benchmark` at git `557a68412867`.

Command:

```shell
/opt/homebrew/bin/timeout 1800s python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target owasp=benchmarks/owasp-benchmark \
  --runs 1 \
  --in-place \
  --timeout-sec 600 \
  --rss-limit-mb 3072 \
  --output target/goal-benchmark-owasp-2026-05-16.json
```

Result:

| Step | Cold wall | Warm wall | Peak RSS |
| --- | ---: | ---: | ---: |
| `index` | 1.656s | 1.733s | 168.4 MB cold / 166.9 MB warm |
| `dump-callgraph` | 3.554s | 2.008s | 266.9 MB cold / 263.5 MB warm |
| `export --all` | 9.205s | 4.189s | 734.5 MB cold / 592.5 MB warm |
| `security source-analysis` | 11.922s | 6.514s | 737.8 MB cold / 600.7 MB warm |
| `security taint-analysis` | 29.882s | 24.644s | 807.9 MB cold / 657.6 MB warm |

Finding/count evidence:

- `dump-callgraph --format json --all`: `7,683` functions.
- Production `source-analysis --format json --all`: `1,340` rows.
- Production `taint-analysis --format json --all`: `8,213` rows.
- All benchmarked commands exited `0` within the 600s per-command guard and
  below the 3GB RSS guard.

Resolved-callgraph over-fan check:

```shell
./target/release/bonsai-ninja dump-edges benchmarks/owasp-benchmark \
  --format json --all --no-color --no-progress
```

- Resolved semantic edges: `7,871`.
- Diagnostic precision in edge output: `0` over-approximate/unknown edges.
- `dump-callgraph` total outgoing count: `7,771`; maximum outgoing count for
  any function: `11`.
- Hottest functions by outgoing edges were bounded (`init` at `11`,
  `initClassicData`, `__module__`, and `createBasePartition` at `8`), which is
  evidence against the previous OWASP-wide over-fanning failure mode.

Cache evidence:

- Warm/final cache: callgraph sidecar (`987,348` bytes) and IDG factstore
  (`42,151,515` bytes), `43,138,863` artifact bytes total.
- Warm speedups: callgraph `1.770x`, export `2.198x`, source-analysis
  `1.830x`, taint-analysis `1.213x`; in this historical run, index was
  structural and roughly unchanged (`0.956x`).

## Post Semantic-Fix Verification

After the exact callable-alias, function-clause, Rust import-path, and Erlang
parameter-pattern fixes, the release CLI was rebuilt with:

```shell
cargo build -q --release -p bonsai_cli
```

Current Rust coverage:

- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- `cargo test -q -p bonsai_resolve -p bonsai_callgraph -p bonsai_taint --lib --tests`:
  passed. This included `bonsai_resolve` (`26` lib tests), `bonsai_callgraph`
  (`31` lib tests), `bonsai_taint` lib/tests including the interprocedural
  constructs suite (`79` tests), taint matrix (`1,366` tests), coverage report
  (`4` tests), and the remaining taint integration suites.
- Focused adapter regressions passed for C/ObjC function-pointer aliases, Perl
  coderef aliases, Erlang fun-reference aliases, Kotlin function references,
  Elixir short clause-name parsing, Erlang zero-arity clauses, and Erlang
  list-cons parameter-pattern bindings.

Fresh examples benchmark with the current release binary:

```shell
/opt/homebrew/bin/timeout 300s python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target examples=examples \
  --runs 1 \
  --timeout-sec 120 \
  --rss-limit-mb 1024 \
  --output target/goal-benchmark-examples-post-semantic-2026-05-16.json
```

All measured steps completed with `status=ok` and exit code `0`.

| Step | Cold wall | Warm wall | Peak RSS |
| --- | ---: | ---: | ---: |
| `index` | 0.631s | 0.623s | 80.7 MB |
| `dump-callgraph` | 0.909s | 0.626s | 106.6 MB warm |
| `export --all` | 1.531s | 1.214s | 232.8 MB cold / 185.8 MB warm |
| `security source-analysis` | 2.492s | 1.862s | 408.6 MB cold / 356.7 MB warm |
| `security taint-analysis` | 3.505s | 2.847s | 289.7 MB cold / 248.5 MB warm |

Finding/count evidence:

- `dump-callgraph --format json --all`: `5,154` rows.
- `security source-analysis --format json --all`: `3,569` rows.
- `security taint-analysis --format json --all`: `1,370` findings with
  semantic-only precision (`741 exact`, `629 narrowed`, `0 unknown`,
  `0 over-approximate`).
- Native export phase summary reported `analysis_complete_from_phases=true`,
  `propagations_complete=true`, `flow_chains_truncated_targets=0`,
  `taint_chains_truncated_targets=0`, and
  `flow_id_labels_truncated_functions=0`.

Cache evidence:

- Initial cache: no `.bonsai` artifacts.
- Warm/final cache: callgraph sidecar (`314,270` bytes) and IDG factstore
  (`7,586,457` bytes), `7,900,727` artifact bytes total.
- Warm speedups: callgraph `1.453x`, export `1.261x`, source-analysis
  `1.338x`, taint-analysis `1.231x`; in this historical run, index remained
  structural and roughly unchanged (`1.013x`).

Current examples CLI smoke:

- `./target/release/bonsai-ninja index examples --no-progress --no-color`:
  `625` files, `625` cached declaration indexes, `0` cached CFGs, exit `0`.
- Production-profile examples `source-analysis` and `taint-analysis` returned
  complete zero-row results because the production profile intentionally
  excludes example/test paths.
- No-profile examples `source-analysis` returned `3,216` rows in the default
  bare-array JSON shape; no-profile `taint-analysis` returned `1,370`
  findings.
- `dump-taint examples --source erlang/complex/advanced.erl:27:process_batch
  --seed _Arg0 --format json` returned `analysis_complete=true`, no
  incomplete reasons, `saturated=false`, `pairs_analyzed=6`, precision
  `narrowed`, and `8` propagation records.

Current large-target benchmark with the same release binary:

```shell
/opt/homebrew/bin/timeout 2400s python3 scripts/goal_benchmark.py \
  --binary ./target/release/bonsai-ninja \
  --target redis=benchmarks/redis \
  --target owasp=benchmarks/owasp-benchmark \
  --runs 1 \
  --in-place \
  --timeout-sec 600 \
  --rss-limit-mb 3072 \
  --output target/goal-benchmark-large-post-semantic-2026-05-16.json
```

All measured Redis and OWASP steps completed with `status=ok` and exit code
`0`.

| Target | Step | Cold wall | Warm wall | Peak RSS |
| --- | --- | ---: | ---: | ---: |
| redis | `index` | 1.373s | 1.602s | 196.3 MB cold / 189.9 MB warm |
| redis | `dump-callgraph` | 3.073s | 1.574s | 280.7 MB cold / 276.4 MB warm |
| redis | `export --all` | 17.619s | 16.218s | 840.5 MB cold / 697.6 MB warm |
| redis | `security source-analysis` | 5.005s | 3.405s | 720.5 MB cold / 571.6 MB warm |
| redis | `security taint-analysis` | 5.975s | 4.163s | 733.9 MB cold / 579.1 MB warm |
| owasp | `index` | 1.716s | 1.730s | 178.0 MB cold / 179.0 MB warm |
| owasp | `dump-callgraph` | 3.528s | 1.996s | 285.4 MB cold / 279.5 MB warm |
| owasp | `export --all` | 9.498s | 4.346s | 761.4 MB cold / 621.1 MB warm |
| owasp | `security source-analysis` | 12.104s | 6.524s | 792.1 MB cold / 622.4 MB warm |
| owasp | `security taint-analysis` | 29.674s | 24.815s | 870.4 MB cold / 703.5 MB warm |

Current large-target finding/count evidence:

- Redis `dump-callgraph --format json --all`: `6,598` rows.
- Redis production `source-analysis --format json --all`: `23` rows.
- Redis production `taint-analysis --format json --all`: `0` rows.
- OWASP `dump-callgraph --format json --all`: `7,683` rows.
- OWASP production `source-analysis --format json --all`: `1,339` rows.
- OWASP production `taint-analysis --format json --all`: `8,707` findings
  with semantic-only precision (`1,332 exact`, `7,375 narrowed`, `0 unknown`,
  `0 over-approximate`).

Current large-target cache evidence:

- Redis warm/final cache: callgraph sidecar (`1,580,704` bytes) and IDG
  factstore (`41,099,879` bytes), `42,680,583` artifact bytes total.
- Redis warm speedups: callgraph `1.953x`, export `1.086x`,
  source-analysis `1.470x`, taint-analysis `1.435x`.
- OWASP warm/final cache: callgraph sidecar (`987,244` bytes) and IDG
  factstore (`42,790,627` bytes), `43,777,871` artifact bytes total.
- OWASP warm speedups: callgraph `1.767x`, export `2.185x`,
  source-analysis `1.855x`, taint-analysis `1.196x`.

Current large-target semantic edge checks:

- Redis `dump-edges --format json --all`: `27,468` rows, all `narrowed`,
  `0 unknown`, `0 over-approximate`, and maximum callees for a concrete call
  site was `7`.
- OWASP `dump-edges --format json --all`: `7,869` rows, all `narrowed`,
  `0 unknown`, `0 over-approximate`, `7,867` concrete call sites, maximum
  callees for a concrete call site was `2`, and `0` call sites had more than
  `20` callees. The only 2-callee sites were minified JavaScript
  callback/indirect-call shapes, not Java servlet over-fan.

## Type-Alias Fallback Fix - 2026-05-17

Issue fixed: local type aliases such as Java `String value` no longer let a
member call rewrite from `value.equals` to `String.equals` and then retry a
workspace-wide bare `equals` lookup. Type aliases now require class/member
semantic evidence. Module and member imports can still use a bare-tail retry,
but only when the candidate remains inside the alias target.

Focused over-fan checks after clearing the affected caches:

- Synthetic OWASP-shape fixture: `dump-edges --from doPost --to equals`
  returned `0` rows.
- Java OWASP Benchmark: `dump-edges --from doPost --to equals --all` returned
  `0` rows.
- Java OWASP Benchmark: `dump-edges --from doPost --to getName --all` returned
  `0` rows.

Fresh examples benchmark with `target/goal-benchmark-examples-2026-05-17-type-alias-fix.json`:

| Target | Step | Cold wall | Warm wall | Peak RSS |
| --- | --- | ---: | ---: | ---: |
| examples | `index` | 0.648s | 0.628s | 81.4 MB cold / 81.3 MB warm |
| examples | `dump-callgraph` | 0.947s | 0.644s | 106.5 MB cold / 105.0 MB warm |
| examples | `export --all` | 1.557s | 1.243s repeat | 231.1 MB cold / 188.7 MB warm |
| examples | `security source-analysis` | 2.460s | 2.132s | 396.8 MB cold / 359.7 MB warm |
| examples | `security taint-analysis` | 3.658s | 3.405s | 287.4 MB cold / 249.9 MB warm |

Examples row counts: `5,154` callgraph rows, `3,604` source-analysis rows, and
`1,382` taint findings.

Fresh Redis/OWASP benchmark with
`target/goal-benchmark-large-2026-05-17-type-alias-fix.json`:

| Target | Step | Cold wall | Warm wall | Peak RSS |
| --- | --- | ---: | ---: | ---: |
| redis | `index` | 1.590s | 1.329s | 194.1 MB cold / 194.0 MB warm |
| redis | `dump-callgraph` | 2.834s | 1.579s | 285.8 MB cold / 280.1 MB warm |
| redis | `export --all` | 17.783s | 16.120s repeat | 815.9 MB cold / 709.4 MB warm |
| redis | `security source-analysis` | 5.312s | 3.679s | 735.5 MB cold / 572.3 MB warm |
| redis | `security taint-analysis` | 6.302s | 4.124s | 740.5 MB cold / 581.8 MB warm |
| owasp | `index` | 1.726s | 1.578s | 178.2 MB cold / 177.2 MB warm |
| owasp | `dump-callgraph` | 3.855s | 1.958s | 276.2 MB cold / 278.4 MB warm |
| owasp | `export --all` | 9.568s | 4.360s repeat | 771.9 MB cold / 627.1 MB warm |
| owasp | `security source-analysis` | 11.912s | 6.740s | 774.2 MB cold / 637.5 MB warm |
| owasp | `security taint-analysis` | 30.131s | 24.649s | 852.6 MB cold / 706.4 MB warm |

Fresh large-target counts and cache evidence:

- Redis: `6,598` callgraph rows, `23` production source rows, `0` production
  taint findings, final cache `42,500,615` bytes.
- OWASP: `7,683` callgraph rows, `1,339` production source rows, `8,707`
  production taint findings, final cache `44,015,907` bytes.
- Direct OWASP production source-analysis completed in `11.76s` with peak RSS
  `765,902,848` bytes and `1,339` rows.
- Direct OWASP production taint-analysis completed in `23.59s` with peak RSS
  `699,793,408` bytes and `8,707` findings.

Current Rust verification status:

- Passing: `cargo build --release -q -p bonsai_cli`,
  `cargo check -q -p bonsai_resolve -p bonsai_callgraph --tests`,
  `cargo test -q -p bonsai_resolve -p bonsai_callgraph --no-run`,
  `cargo fmt --all --check`, `git diff --check`, and
  `cargo clippy -q -p bonsai_resolve -p bonsai_callgraph --all-targets -- -D warnings`.
- Isolated target verification: focused runtime regressions pass when compiled
  into a fresh target dir (`/tmp/bonsai-ninja-test-target-focused`):
  `bonsai_resolve::tests::type_alias_member_call_does_not_fall_back_to_bare_method`
  and
  `bonsai_callgraph::tests::typed_external_receiver_method_does_not_fall_back_to_workspace_method`.
- Local target isolation detail: the old `target/debug` tree had grown to
  `59G` under `target/debug/deps` and `27G` under `target/debug/incremental`.
  Its stale `bonsai_resolve` and `bonsai_callgraph` test executables timed out
  on `--list` before test bodies ran, while the same tests built and ran in the
  fresh target directory.
- Default target verification after removing the polluted `target/debug` tree:
  `cargo test -q -p bonsai_resolve -p bonsai_callgraph -- --nocapture` passed
  with `38` callgraph tests and `27` resolver tests.
- Architecture invariants after the same cleanup:
  `cargo test -q -p bonsai_conformance --test architecture_invariants -- --nocapture`
  passed with `45` tests.
- Rulepack verification:
  `./target/release/bonsai-ninja security . pack --validate --format json --no-color --no-progress`
  returned `valid=true`, `errors=0`, `warnings=0`, and `6,618` rules;
  `cargo test -q -p bonsai_security --test rulepack_conformance -- --nocapture`
  passed with `26` tests.
- Release CLI smoke after cleanup/rebuild:
  `./target/release/bonsai-ninja index examples --no-progress --no-color`
  returned `625` files, `625` cached declaration indexes, `0` cached CFGs,
  and `625` reparsed files; `security examples source-analysis --format json
  --all` returned `1,730` rows.

Current code-hygiene audit:

- Temporary debug hooks from the callgraph investigation are absent:
  `BONSAI_DEBUG_CALLGRAPH` and `debug_candidate_names` have no matches.
- `TODO`/`FIXME` matches under `crates/` are intentional marker-scanner/help
  text, not dangling implementation notes in analysis code.
- Production `analysis_complete=true` construction remains limited to the
  audited exact-local sites in CFG, browse dumps, and security analysis; the
  conformance allowlist documents these sites.
- Unit-test bodies are kept in separate files through `mod tests;` submodules.
  The new regression tests live in `crates/resolve/src/tests.rs` and
  `crates/callgraph/src/tests.rs`.

## Command And Language Verification - 2026-05-17

Latest full-command and supported-language verification after the cache
freshness and receiver-type fixes:

- Command coverage and language CLI matrix:
  `cargo test -q -p bonsai_cli --test command_coverage --test per_lang_cli_matrix
  --test security_commands --test taint_engine_e2e --test export_schema_drift
  --test name_resolution_drift -- --nocapture` passed with `28` command
  coverage tests, `866` per-language CLI cases, `35` security command tests,
  and `120` taint engine e2e tests.
- Supported-language adapter sweep:
  `cargo test -q` across all `bonsai_lang_*` adapter crates passed for the
  `21` supported languages advertised by the CLI: Python, JavaScript,
  TypeScript, Java, Kotlin, C#, Swift, Scala, Go, Rust, PHP, Ruby, C, C++,
  Perl, Dart, Lua, Elixir, Erlang, Objective-C, and Solidity.
- Conformance and architecture invariants:
  `cargo test -q -p bonsai_conformance --test architecture_invariants --test
  flow_event_conformance --test capability_matrix --test async_yield_coverage
  --test coverage_baseline -- --nocapture` passed with `45 + 1 + 1 + 2 + 1`
  tests. These include the allowlist for reviewed production
  `analysis_complete=true` sites and the test-layout/architecture guardrails.
- Formatting, whitespace, clippy, release build, and rulepack validation
  passed: `cargo fmt --all --check`, `git diff --check`,
  `cargo clippy -q -p bonsai_lang_api -p bonsai_lang_go -p bonsai_workspace
  -p bonsai_cli --all-targets -- -D warnings`, `cargo build --release -q
  -p bonsai_cli`, and
  `./target/release/bonsai-ninja security . pack --validate --format json
  --no-color --no-progress`.
- Rulepack validation returned `valid=true`, `rule_count=6618`,
  `enabled_rule_count=5468`, `errors=0`, and `warnings=0`.

Two concrete regressions were found and fixed during this verification pass:

- Stale IDG sidecars could decode after semantic stitching changes and hide
  current C mega-flow behavior. `IDG_STITCHING_SEMANTIC_VERSION` was bumped to
  reject older `idg.v*.factstore` files whose layout still decoded but whose
  edge lineage was no longer equivalent. The release C mega-flow smoke now
  returns `analysis_complete=true`, empty incomplete reasons, and the narrowed
  chain `main -> orchestrate -> persist -> run -> execute` for
  `c.input.argv_param -> c.cmdi.system`.
- Go field-chain receiver evidence now stays semantic without changing the
  global projection rule. The Go adapter adds projected receiver aliases only
  when the root is a declared typed alias and the projection is an identifier
  field chain, so `r.Header.Get(...)` inherits the exact root `Request` type.
  The shared helper remains tuple-field-only, preserving the Rust guard that
  `request.get_cookies().len()` must not inherit `Request` as the receiver
  type for the returned `Cookies` value. Focused `bonsai_lang_api`,
  `bonsai_lang_go`, and `bonsai_lang_rust` tests passed with `17 + 2 + 9`
  tests.

Fresh release smoke on `examples`:

- `./target/release/bonsai-ninja index examples --no-progress` completed with
  `625` files, `625` cached declaration indexes, `0` cached CFGs, and `625`
  reparsed files.
- A final OS process-table check after the release smokes showed no lingering
  `bonsai-ninja`, `cargo`, `rustc`, release/debug target, or timeout processes
  beyond the just-finished check command itself.

## Current Goal Evidence Audit

Mapping of `docs/goal.md` requirements to current evidence:

| Requirement | Evidence |
| --- | --- |
| User-visible analysis facts are semantic; no name-only or unresolved fan-out is reported as accurate. | Public precision filters reject `over-approximate`/`unknown`; Redis and OWASP `dump-edges --all` are all `narrowed`; the post-fix OWASP `doPost -> equals` and `doPost -> getName` checks both return `0` rows; unsupported dynamic cells are explicitly deferred in `docs/TAINT_COVERAGE_MATRIX.md` instead of forced through unsafe broad matching. |
| Partial, capped, timed-out, stale, or approximate analysis is not presented as complete. | Completion metadata audit reviewed remaining production `analysis_complete=true` sites; paged/security/inspect/trace/export/debug wrappers now surface incomplete reasons; examples/large export phase summaries report complete chain/propagation coverage with zero truncation. |
| Flow, taint, source, security, export, and debug commands compute requested exact scope before rendering. | Examples, Redis, and OWASP `source-analysis`, `taint-analysis`, `export --all`, `dump-edges --all`, and `dump-taint` smokes completed with semantic precision and explicit completion metadata. |
| Historical May 2026 default `index <workspace>` was structural and fast, not an eager full-workspace taint solve. Current builds keep default `index` structural and use `index --semantic` for explicit sidecar warm-up. | Historical `index examples`: `625` files, `0` cached CFGs, `0.631s`; historical `index crates`: previously measured `429` files, `0` cached CFGs, `1.59s`; direct original hang target no longer hangs. |
| Avoid duplicated work through reusable indexes/callgraphs/IDG/value-flow caches with correct invalidation. | Warm benchmarks show valid callgraph/IDG sidecars and speedups across examples, Redis, and OWASP; the latest Redis final cache is `42,500,615` bytes and the latest OWASP final cache is `44,015,907` bytes. |
| Keep memory bounded and avoid retaining every full per-entry graph. | Current runs stay below guards: examples under `397 MB`, Redis under `816 MB`, OWASP under `853 MB`; Redis dense export uses compressed complete callgraph mode rather than materializing multi-GB path sets in memory. |
| Expensive audit/export/prewarm work is explicit, observable, and exact. | Full `export --all` and benchmark harness capture phase summaries including chain mode, truncation counts, and propagation completeness; at benchmark time, default index remained structural. |
| Caches never determine correctness or hide stale facts. | Cache freshness invariant covers source, dependency metadata, matcher policy, rule/config, and pipeline versions; callgraph/dataflow/IDG/value-flow/taint/flow-id cache versions were bumped for the current semantic changes. |
| Regression tests prove accuracy, cache behavior, and the cheap structural-only index path. | Compile-time Rust coverage passes through `cargo check --tests` and `cargo test --no-run`; focused runtime regressions pass from a fresh target dir; after cleaning polluted `target/debug`, default-target test harnesses launch normally and `cargo test --workspace --no-fail-fast` passes, including rulepack conformance `28/28`, architecture invariants `45/45`, the 21-language CLI/security matrices, SARIF checks, doc tests, and cache/hot-reload coverage. Current builds test `--structural-only` for the cheap path. |
| Benchmarks cover `examples/`, Redis, and Java OWASP Benchmark with cold/warm time, RSS, cache, and finding counts. | Current examples, Redis, and OWASP sections above document cold/warm timings, RSS, row/finding counts, cache artifact bytes, and warm behavior, including the 2026-05-17 post-fix runs. |
| Code remains scoped, deterministic, and professional. | `cargo fmt --all --check`, `git diff --check`, and focused `cargo clippy` pass; changes are confined to analysis semantics, tests, and documentation. |

Conclusion: the current release binary satisfies the active project goal's
semantic over-fan, benchmark, memory, cache, test, rulepack, and cleanliness
evidence requirements. The prior Rust runtime test hang was isolated to a
polluted local `target/debug` tree and resolved by removing that tree; reliable
default-target full-workspace test execution is restored.
