## Summary

Describe the user-visible behavior and why this is the smallest correct change.

## Evidence

List the positive and negative cases that prove the behavior. For compiler or
analysis changes, identify the language/runtime semantics and the exact typed
facts involved.

## Validation

- [ ] I ran the smallest focused tests for this change.
- [ ] I ran the applicable gates from [Release Readiness][release-readiness].
- [ ] I updated public documentation for CLI, SDK, rule-schema, output, cache,
      or behavior changes.
- [ ] I followed all output pages/cursors before making a completeness claim.
- [ ] I did not add semantic caps, guessed edges, private corpus knowledge, or
      security API inventories to shared analysis.
- [ ] I did not commit credentials, private source, generated workspace caches,
      benchmark checkouts, or Cargo build artifacts.

## Remaining limits

State any unresolved diagnostics, unsupported runtime behavior, skipped gate,
or follow-up work. Write `None` only when the change is fully verified.

[release-readiness]: https://github.com/gromhacks/bonsai-ninja/blob/main/docs/RELEASE_READINESS.md
