# PHP language gauntlet

This deliberately vulnerable project is a compiler and dataflow fixture. Its
canonical flow is:

```text
public/app.php: $_GET['cmd']
  -> src/Application/pipeline.php: generators, closures, match, aliases
  -> src/Application/storage.php: include facade
  -> src/Domain/storage.php: promoted constructor state and inheritance
  -> src/Infrastructure/executor.php: shell_exec
```

`cleanTwin()` is the literal-only negative control. The fixture also covers
traits, interfaces, abstract classes, static factories, chained receivers,
array destructuring/spread, arrow functions, variadics, loops, and
try/catch/finally. `app.php` is the conventional root launcher.
