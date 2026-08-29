# Python language gauntlet

This deliberately vulnerable Flask project is a compiler and dataflow fixture.
Its canonical flow is:

```text
entrypoints/http.py: request.args.get
  -> application/pipeline.py: coroutine + async-generator orchestration
  -> domain/transformers.py + validators.py: comprehensions, closures, match/case
  -> infrastructure/storage.py: constructor and property-backed receiver state
  -> infrastructure/executor.py: os.system
```

`clean_twin()` is the literal-only negative control. Supporting modules add a
decorator factory, context manager, partial/callable dispatch, nested closures,
aliases, tuple returns, inheritance, class/static methods, exceptions, loops,
yield/yield-from, and imports across nested packages. `app.py` is the normal
project launcher; the source-bearing route remains in `entrypoints/http.py`.
