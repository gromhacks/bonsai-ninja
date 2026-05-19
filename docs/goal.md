Make bonsai-ninja a production-grade, highly accurate, fast code review and SAST tool.

  Primary objective:
  The tool must produce maximally accurate code intelligence, source analysis, taint analysis, flow evidence, exports, and security findings while staying fast, memory-
  conscious, deterministic, and cleanly engineered. Accuracy is non-negotiable.

  Core principles:
  - All user-visible analysis facts must be semantic. A reported flow, taint edge, source path, call edge, export fact, or debug dataflow fact must be backed by exact or narrowed resolver evidence tied to language semantics such as typed receivers, alias/import maps, module/build identity, signatures, or CFG/value-flow state.
  - Do not emit name-only matches, unresolved multi-candidate fan-out, broad fallback edges, or heuristic caps as accurate analysis. If the analyzer cannot semantically resolve a fact, omit it from analysis output and expose the unresolved/capped condition as incomplete metadata or a clear failure.
  - Do not present partial, capped, timed-out, stale, or approximate analysis as complete.
  - Any command that reports flows, taint, source reachability, security findings, debug taint data, or exported analysis facts must compute its requested scope exactly to
  completion before returning.
  - `index <workspace>` should be a fast structural index pass, not an eager exact taint solve for every callable.
  - Avoid duplicated work through reusable structural indexes, call graphs, summaries, SCC solving, IDG/value-flow facts, and correctly invalidated persisted factstores.
  - Keep memory bounded by streaming large artifacts and avoiding retention of every full per-entry graph in RAM.
  - Expensive full-workspace audit/export/prewarm work is allowed when the command scope requires it, but it must be explicit, observable, exact, and engineered to avoid
  repeated work.
  - Caches are performance artifacts only. They must never determine correctness, hide incompleteness, or reuse stale facts.

  Taint and flow behavior:
  - Security, source-analysis, taint-analysis, inspect, trace, dump-taint, read-file flow context, flow columns, export, and debug commands must compute exact required flow
  facts before rendering.
  - "Exact required flow facts" means exact within the declared semantic scope (`exact` / `narrowed`). `over-approximate` and `unknown` are diagnostic precision states, not acceptable evidence for findings or reviewed flows.
  - Use scope-driven exact analysis: each command determines its required analysis scope from its query/profile/export mode, computes that scope to fixpoint, and only then
  reports results.
  - Full-workspace export or full-workspace audit modes must be complete for the requested workspace/profile.
  - If exact analysis cannot complete, fail clearly or mark the result incomplete. Never silently degrade accuracy.

  Performance targets:
  - The checked-in `examples/` directory is the primary regression target and should be lightning fast.
  - The architecture must scale to large real projects such as Redis and the Java OWASP Benchmark without hangs, unbounded memory growth, or repeated whole-program
  recomputation.
  - Benchmark cold and warm runs separately.
  - Track parse/index time, callgraph time, summary/taint time, peak RSS where feasible, cache hit/miss behavior, and finding counts.

  Cache and invalidation requirements:
  - Sidecars and caches must be validated by source content, rulepack content, matcher policy, pipeline version, and dependency metadata.
  - Changed files must invalidate affected facts and dependent summaries precisely.
  - Watch/refresh mode must not accidentally recompute the entire workspace unless the command scope requires it.
  - Warm runs must be faster because they reuse valid facts, not because they skip required analysis.

  Implementation approach:
  1. Audit current indexing, dataflow, value-flow, IDG, cache, refresh, export, debug, and security-analysis paths.
  2. Remove accidental eager exact full-workspace taint work from default `index` and ordinary open/watch paths.
  3. Build or strengthen reusable compositional summaries and SCC-based solving so exact command scopes avoid recomputing the same callees repeatedly.
  4. Ensure all taint/source/security/export/debug commands compute their requested scopes exactly before rendering.
  5. Fix cache freshness and invalidation for source content, rulepack content, matcher policy, pipeline versions, and file dependencies.
  6. Make expensive rebuild/prewarm/audit operations explicit, observable, and exact.
  7. Add regression tests proving default indexing is fast/structural, exact analysis remains accurate, caches are not stale, and repeated work is avoided.
  8. Run targeted tests for affected crates and CLI smoke/regression commands against `examples/`.
  9. When available locally, test Redis and Java OWASP Benchmark and document commands, timings, memory behavior, and finding counts.
  10. Keep changes scoped, deterministic, professional, and consistent with the existing codebase.

  Important starting note:
  Before editing, run `git status` and inspect any existing WIP diff. There may be partial indexing/dataflow changes already present from prior work; preserve useful parts,
  revise anything that conflicts with this goal, and do not discard unrelated user changes.
