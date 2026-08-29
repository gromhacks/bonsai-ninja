# Language-specific syntax audit (Ruby).
# Tests Ruby-special forms:
#   - backticks: `cmd #{var}` (Kernel#``)
#   - %x{} — backtick equivalent
#   - exec/system with string interpolation
def handle_backtick
  # POSITIVE: backtick + interp = shell exec.
  tainted = STDIN.gets
  out = `ping -c 1 #{tainted}`
  out
end

def handle_percent_x
  # POSITIVE: %x{...} alternate backtick syntax.
  tainted = STDIN.gets
  out = %x{ping -c 1 #{tainted}}
  out
end

def handle_eval_string
  # POSITIVE: eval with tainted string.
  expr = STDIN.gets
  eval expr
end
