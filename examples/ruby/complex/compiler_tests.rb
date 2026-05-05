# Compiler architecture test cases for the tree-sitter-sast flow engine.
#
# Each section tests a specific capability with both positive (flow expected)
# and negative (no flow expected) scenarios.

require 'open3'

# ---------------------------------------------------------------------------
# 1. BRANCH-AWARE KILL ANALYSIS
# ---------------------------------------------------------------------------

# [NO FLOW EXPECTED] Both branches sanitize
def branch_kill_both_paths(user_input)
  if user_input.length > 100
    cmd = "default_command"
  else
    cmd = "safe_fallback"
  end
  system(cmd) # safe: both paths overwrite
end

# [FLOW EXPECTED] Only one branch kills taint
def branch_kill_one_path(user_input)
  cmd = user_input
  if cmd.length > 100
    cmd = "truncated"
  end
  # else: cmd still holds user_input
  system(cmd) # tainted
end

# [FLOW EXPECTED] Case without else
def branch_kill_case(user_input)
  query = user_input
  case query[0]
  when "a"
    query = "SELECT * FROM a"
  when "b"
    query = "SELECT * FROM b"
    # no else: query keeps user_input
  end
  system("sqlite3 db.sqlite \"#{query}\"")
end


# ---------------------------------------------------------------------------
# 2. INTERPROCEDURAL KILL (2+ levels deep)
# ---------------------------------------------------------------------------

def sanitize(value)
  value.gsub(/[';--]/, "")
end

def wrap_sanitize(value)
  sanitize(value)
end

# [NO FLOW EXPECTED] Sanitizer applied
def interprocedural_kill_direct(user_input)
  clean = sanitize(user_input)
  system("sqlite3 db.sqlite \"SELECT * FROM t WHERE x = '#{clean}'\"")
end

# [NO FLOW EXPECTED] Sanitizer 2 levels deep
def interprocedural_kill_two_levels(user_input)
  clean = wrap_sanitize(user_input)
  system("sqlite3 db.sqlite \"SELECT * FROM t WHERE x = '#{clean}'\"")
end

# [FLOW EXPECTED] No sanitizer
def interprocedural_no_kill(user_input)
  system("sqlite3 db.sqlite \"SELECT * FROM t WHERE x = '#{user_input}'\"")
end


# ---------------------------------------------------------------------------
# 3. FIELD-SENSITIVE TRACKING
# ---------------------------------------------------------------------------

class Config
  attr_accessor :command, :label

  def initialize
    @command = ""
    @label = ""
  end
end

# [FLOW EXPECTED] Tainted field flows to sink
def field_sensitive_tainted(user_input)
  cfg = Config.new
  cfg.command = user_input
  cfg.label = "safe_label"
  system(cfg.command) # tainted
end

# [NO FLOW EXPECTED] Only safe field used
def field_sensitive_safe(user_input)
  cfg = Config.new
  cfg.command = user_input
  cfg.label = "safe_label"
  system(cfg.label) # safe
end

# [NO FLOW EXPECTED] Tainted field overwritten
def field_sensitive_overwrite(user_input)
  cfg = Config.new
  cfg.command = user_input
  cfg.command = "hardcoded_safe"
  system(cfg.command) # safe: overwritten
end


# ---------------------------------------------------------------------------
# 4. EXCEPTION CHAIN TAINT
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] Taint flows through exception message
def exception_taint(user_input)
  begin
    raise "Invalid: #{user_input}"
  rescue RuntimeError => e
    system(e.message) # tainted
  end
end


# ---------------------------------------------------------------------------
# 5. IMPLICIT RETURN (Ruby-specific)
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] Last expression is implicit return
def process_input(user_input)
  "cmd: #{user_input}" # implicit return
end

def implicit_return_sink(user_input)
  cmd = process_input(user_input)
  system(cmd) # tainted
end


# ---------------------------------------------------------------------------
# 6. BLOCK/PROC TAINT
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] Taint flows through block
def with_transform(value, &block)
  block.call(value)
end

def block_taint(user_input)
  with_transform(user_input) do |v|
    system(v) # tainted
  end
end


# ---------------------------------------------------------------------------
# 7. TYPE-TRACKED CALL RESOLUTION
# ---------------------------------------------------------------------------

class SafeExecutor
  def execute(cmd)
    puts "Would execute: #{cmd}" # safe
  end
end

class UnsafeExecutor
  def execute(cmd)
    system(cmd) # dangerous
  end
end

# [FLOW EXPECTED]
def type_tracked_unsafe(user_input)
  executor = UnsafeExecutor.new
  executor.execute(user_input)
end

# [NO FLOW EXPECTED]
def type_tracked_safe(user_input)
  executor = SafeExecutor.new
  executor.execute(user_input)
end


# ---------------------------------------------------------------------------
# 8. PARAMETER SOURCE SYNTHESIS
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] External entry point
def handle_webhook(payload, signature)
  system("process #{payload}")
end


# ---------------------------------------------------------------------------
# 9. CROSS-METHOD CLASS FIELD TAINT
# ---------------------------------------------------------------------------

class Pipeline
  def initialize
    @data = ""
  end

  def ingest(raw)
    @data = raw
  end

  def process
    system(@data) # tainted if ingest() called with tainted input
  end
end

# [FLOW EXPECTED]
def cross_method_field_taint(user_input)
  p = Pipeline.new
  p.ingest(user_input)
  p.process
end


# ---------------------------------------------------------------------------
# 10. ENUMERABLE CHAIN TAINT
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] Taint flows through enumerable chain
def enumerable_chain_taint(user_input)
  items = [user_input, "safe"]
  result = items.select { |s| s.length > 0 }.join(" ")
  system(result)
end


# ---------------------------------------------------------------------------
# 11. STRING INTERPOLATION CHAIN
# ---------------------------------------------------------------------------

# [FLOW EXPECTED] Taint in string interpolation
def interpolation_chain(user_input)
  query = "SELECT * FROM users WHERE name = '#{user_input}'"
  system("sqlite3 db.sqlite \"#{query}\"")
end


# ---------------------------------------------------------------------------
# 12. SPLAT ARGUMENT TAINT
# ---------------------------------------------------------------------------

def run_command(*args)
  system(args.join(" "))
end

# [FLOW EXPECTED] Taint through splat
def splat_taint(user_input)
  run_command("echo", user_input)
end
