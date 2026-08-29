# Conventional root launcher. The source-bearing entry point is deliberately
# nested so the first callgraph edge also proves relative-import resolution.
require_relative 'app/controllers/commands_controller'
