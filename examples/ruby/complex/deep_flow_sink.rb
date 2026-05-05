# deep_flow_sink.rb -- Final stage: format and execute the command.
# Tainted user input from ENV/gets reaches system()/backticks after
# flowing through the full pipeline. All types prefixed with Dfc.

# Steps 26-29: DfcCommandFormatter -- wraps command for shell execution
class DfcCommandFormatter
  # Step 26: Add timeout wrapper
  def add_timeout(ctx)
    ctx.formatted_command = "timeout #{ctx.timeout_sec} #{ctx.formatted_command}"
  end

  # Step 27: Add directory change prefix
  def add_directory_prefix(ctx)
    ctx.formatted_command = "cd #{ctx.working_dir} && #{ctx.formatted_command}"
  end

  # Step 28: Escape for shell (incomplete -- single quotes not handled)
  def shell_escape(cmd)
    escaped = cmd.gsub('"', '\\"')
    escaped
  end

  # Step 29: Wrap in shell invocation
  def add_shell_wrapper(ctx)
    escaped = shell_escape(ctx.formatted_command)
    ctx.formatted_command = "/bin/sh -c \"#{escaped}\""
  end

  def format(ctx)
    return false if ctx.formatted_command.empty?
    add_timeout(ctx)
    add_directory_prefix(ctx)
    add_shell_wrapper(ctx)
    true
  end
end

# Steps 30-32: DfcPipelineExecutor -- runs the command
class DfcPipelineExecutor
  # Step 30: Execute with system() and capture status
  def execute_captured(command)
    # SINK: tainted data reaches system()
    result = system(command)
    result
  end

  # Step 31: Execute with backticks and capture output
  def execute_direct(command)
    # SINK: tainted data reaches backtick execution
    output = `#{command}`
    output
  end

  # Step 32: Try system(), fall back to backticks
  def execute(ctx)
    if ctx.dry_run
      puts "[DRY RUN] Would execute: #{ctx.formatted_command}"
      return 0
    end

    puts "[EXEC] Running: #{ctx.formatted_command}"

    result = execute_captured(ctx.formatted_command)
    unless result
      $stderr.puts "[WARN] system() execution failed, trying backticks"
      output = execute_direct(ctx.formatted_command)
      if output
        puts "[OUTPUT] #{output}"
        return 0
      end
      return 1
    end

    0
  end
end
