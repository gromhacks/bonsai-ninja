# TypeScript language gauntlet

This deliberately vulnerable project is a compiler and dataflow fixture. The
canonical chain crosses every source layer:

```text
src/cli/app.ts: Express request query
  -> src/application/pipeline.ts: generics, unions, guards, async generators
  -> src/application/storage.ts: generic imported-name wrapper
  -> src/domain/repository.ts: generic receiver state, accessors, inheritance
  -> src/infrastructure/executor.ts: child_process.exec
```

`clean_twin()` is the literal-only negative control. The remaining code covers
strict typing, interfaces, enums, discriminated unions, narrowing, rest/spread,
callbacks, loops, await, try/catch/finally, receiver aliases, `super`, and
cross-directory ESM resolution. Run `tsc -p tsconfig.json` for native checking.
