# JavaScript language gauntlet

This deliberately vulnerable project is a compiler and dataflow fixture, not
an application template. Its canonical flow is:

```text
cli/app.js: Express request query
  -> application/pipeline.js: async generators, callbacks, aliases, branches
  -> application/storage.js: imported-name wrapper
  -> domain/repository.js: constructor state, getter/setter, inheritance, super
  -> infrastructure/executor.js: child_process.exec
```

`clean_twin()` is the negative control: the same endpoint receives only a
literal. The project also covers CommonJS destructuring, dynamic import,
object spread/rest, optional chaining, nullish coalescing, loops, try/catch,
closures, generator returns, receiver aliases, and cross-directory exports.
