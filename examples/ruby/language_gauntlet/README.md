# Ruby language gauntlet

This deliberately vulnerable project is a compiler and dataflow fixture. Its
canonical flow is:

```text
app/controllers/commands_controller.rb: Rails params
  -> lib/application/pipeline.rb: blocks, procs, pattern branches, aliases
  -> lib/application/storage.rb: relative-require facade
  -> lib/domain/storage.rb: instance-variable state, mixins, inheritance
  -> lib/infrastructure/executor.rb: Kernel#system
```

`clean_twin()` is the literal-only negative control. The fixture also exercises
keyword/hash spread, block forwarding, `yield`, closures, Enumerable callbacks,
safe navigation, heredocs, `super`, receiver aliases, and rescue/ensure. The
Root `app.rb` is the conventional launcher; the controller remains under the
production application tree so the default security profile reviews it.
