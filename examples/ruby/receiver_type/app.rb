# Receiver-type audit fixture (Ruby).
# YAML.load with tainted input. Ruby uses constant-as-receiver, so
# `[YAML, load]` is a class-name receiver shape; the deser rule
# fires when the matcher resolves YAML correctly.
require 'yaml'

def handle
  # POSITIVE
  tainted = STDIN.gets
  YAML.load(tainted)
end
