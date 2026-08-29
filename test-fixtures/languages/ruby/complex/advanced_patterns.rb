require 'ostruct'
require 'json'
require 'open-uri'

# --------------------------------------------------------------------------
# advanced_patterns.rb
# Exercises Ruby-specific syntax patterns with tainted data flows.
# Each VULN comment explains the full source-to-sink chain.
# --------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

module Loggable
  def log(message)
    File.open("/var/log/app.log", "a") { |f| f.puts(message) }
  end

  def log_error(error)
    log("ERROR: #{error}")
  end
end

module Configurable
  def load_config(path)
    data = File.read(path)
    JSON.parse(data, symbolize_names: true)
  end

  def apply_setting(key, value)
    @settings ||= {}
    @settings[key] = value
  end
end

module Executable
  # VULN 1: Module mixin + block/yield + string interpolation chain
  # Chain: ENV["CMD_PREFIX"] -> prefix -> string interpolation -> system(cmd)
  # Source: ENV["CMD_PREFIX"]
  # Sink: system(cmd)
  def run_with_prefix(task)
    prefix = ENV["CMD_PREFIX"]
    cmd = "#{prefix} #{task}"
    system(cmd)
  end

  def capture_output(command)
    system(command)
  end
end

# ---------------------------------------------------------------------------
# Chain 1: Block/yield with tainted data -> command injection
# ---------------------------------------------------------------------------

class TaskRunner
  include Executable

  def execute_user_task(task_name)
    # VULN 2: Block/yield -> string interpolation -> system
    # Chain: ARGV[0] -> task_name -> yield block builds "run #{prefix} #{task}"
    #        -> run_with_prefix calls system(cmd)
    # Source: ARGV[0] (passed as task_name from caller)
    # Sink: system(cmd) in Executable#run_with_prefix
    run_with_prefix(task_name) do |prefix, task|
      "run #{prefix} #{task}"
    end
  end

  def execute_from_argv
    task = ARGV[0]
    execute_user_task(task)
  end
end

# ---------------------------------------------------------------------------
# Chain 2: Proc/Lambda taint propagation -> eval
# ---------------------------------------------------------------------------

class ExpressionEngine
  # VULN 3: ENV source -> eval injection
  # Chain: ENV["EXPRESSION"] -> expr -> eval(expr)
  # Source: ENV["EXPRESSION"]
  # Sink: eval(expr)
  def build_evaluator
    -> (expression) { eval(expression) }
  end

  def run_interactive
    expr = ENV["EXPRESSION"]
    eval(expr)
  end

  # VULN 4: Proc.new + string interpolation -> system execution
  # Chain: ENV["TOOL_PATH"] -> tool_path -> cmd interpolation -> system(cmd)
  # Source: ENV["TOOL_PATH"]
  # Sink: system(cmd)
  def build_command_runner
    tool_path = ENV["TOOL_PATH"]
    cmd = "#{tool_path}/process data.txt"
    system(cmd)
  end

  def process_file(filename)
    build_command_runner
  end
end

# ---------------------------------------------------------------------------
# Chain 3: Symbol-to-proc (&:method_name) + map chain
# ---------------------------------------------------------------------------

class DataProcessor
  include Loggable

  def initialize(db)
    @db = db
  end

  # VULN 5: ENV source + Enumerable chain -> SQL injection
  # Chain: ENV["IDS"] -> raw_ids -> split -> join -> SQL interpolation -> execute
  # Source: ENV["IDS"]
  # Sink: system(sql)
  def find_records_by_ids(params)
    raw_ids = ENV["IDS"]
    id_list = raw_ids.split(",").map(&:strip).map(&:to_s)
    sql = "sqlite3 mydb.db \"SELECT * FROM records WHERE id IN ('#{id_list.join("','")}')\""
    system(sql)
  end

  # Safe version
  def find_records_by_ids_safe(params)
    raw_ids = params[:ids]
    id_list = raw_ids.split(",").map(&:strip).map(&:to_i)
    placeholders = id_list.map { "?" }.join(",")
    @db.execute("SELECT * FROM records WHERE id IN (#{placeholders})", id_list)
  end
end

# ---------------------------------------------------------------------------
# Chain 4: Splat operator (*args) propagation -> command injection
# ---------------------------------------------------------------------------

class BatchExecutor
  # VULN 6: Splat args -> command assembly -> IO.popen
  # Chain: ARGV -> *commands (splat) -> each builds "run #{cmd}"
  #        -> IO.popen(full_cmd) reads output
  # Source: ARGV
  # Sink: IO.popen(full_cmd)
  def run_batch(*commands)
    results = []
    commands.each do |cmd|
      full_cmd = "run #{cmd}"
      IO.popen(full_cmd) do |io|
        results << io.read
      end
    end
    results
  end

  def run_from_args
    run_batch(*ARGV)
  end

  # VULN 7: Splat + collect -> File.open (path traversal)
  # Chain: paths splat -> collect builds full path -> File.open reads each
  # Source: caller-provided *paths
  # Sink: File.open(full_path)
  def read_files(*paths)
    paths.collect do |p|
      full_path = "/var/data/#{p}"
      File.open(full_path, "r") { |f| f.read }
    end
  end
end

# ---------------------------------------------------------------------------
# Chain 5: String interpolation multi-hop chain -> command injection
# ---------------------------------------------------------------------------

class ReportBuilder
  include Loggable

  # VULN 8: Multi-hop string interpolation -> system
  # Chain: ENV["REPORT_USER"] -> user -> "report_#{user}" -> base_name
  #        -> "#{base_name}_#{timestamp}" -> filename
  #        -> "/tmp/#{filename}.pdf" -> output_path
  #        -> "wkhtmltopdf /tmp/input.html #{output_path}" -> system
  # Source: ENV["REPORT_USER"]
  # Sink: system(cmd)
  def generate_report
    user = ENV["REPORT_USER"]
    timestamp = Time.now.to_i
    base_name = "report_#{user}"
    filename = "#{base_name}_#{timestamp}"
    output_path = "/tmp/#{filename}.pdf"
    cmd = "wkhtmltopdf /tmp/input.html #{output_path}"
    system(cmd)
  end

  # Safe version
  def generate_report_safe
    user = ENV["REPORT_USER"].to_s.gsub(/[^a-zA-Z0-9_-]/, "")
    timestamp = Time.now.to_i
    output_path = "/tmp/report_#{user}_#{timestamp}.pdf"
    system("wkhtmltopdf", "/tmp/input.html", output_path)
  end
end

# ---------------------------------------------------------------------------
# Chain 6: Enumerable chain (.map.select.inject) -> SQL injection
# ---------------------------------------------------------------------------

class AnalyticsService
  def initialize(db)
    @db = db
  end

  # VULN 9: ENV source + Enumerable chain -> inject builds SQL -> system
  # Chain: ENV["FILTERS"] -> split -> map(&:strip) -> select -> inject
  #        -> SQL interpolation -> system
  # Source: ENV["FILTERS"]
  # Sink: system(query)
  def query_with_filters(params)
    raw_filters = ENV["FILTERS"]
    conditions = raw_filters
      .split(";")
      .map(&:strip)
      .select { |f| !f.empty? }
      .inject("") { |acc, f| acc.empty? ? f : "#{acc} AND #{f}" }
    query = "sqlite3 mydb.db \"SELECT * FROM analytics WHERE #{conditions}\""
    system(query)
  end

  # Safe version
  def query_with_filters_safe(params)
    allowed = %w[date country browser]
    raw_filters = params[:filters].split(";").map(&:strip)
    conditions = raw_filters
      .select { |f| allowed.any? { |a| f.start_with?(a) } }
      .map { "?" }
      .join(" AND ")
    @db.execute("SELECT * FROM analytics WHERE #{conditions}", raw_filters)
  end
end

# ---------------------------------------------------------------------------
# Chain 7: Rescue/retry with tainted exception data -> log injection
# ---------------------------------------------------------------------------

class HttpFetcher
  include Loggable

  MAX_RETRIES = 3

  # VULN 10: Tainted URL -> exception message -> log file write
  # Chain: ENV["WEBHOOK_URL"] -> url -> URI.open raises error
  #        -> rescue captures error.message (contains tainted URL)
  #        -> log_error writes to /var/log/app.log via File.open
  # Source: ENV["WEBHOOK_URL"]
  # Sink: File.open (via Loggable#log)
  def fetch_webhook_data
    url = ENV["WEBHOOK_URL"]
    retries = 0
    begin
      data = URI.open(url).read
      data
    rescue StandardError => e
      retries += 1
      log_error("Failed to fetch #{url}: #{e.message}")
      retry if retries < MAX_RETRIES
      nil
    end
  end
end

# ---------------------------------------------------------------------------
# Chain 8: OpenStruct with tainted fields -> command injection
# ---------------------------------------------------------------------------

class DeploymentManager
  # VULN 11: OpenStruct fields carry taint -> exec
  # Chain: ENV["DEPLOY_TARGET"] -> target -> OpenStruct.new(target: target)
  #        -> config.target -> "deploy --host #{config.target}" -> exec(cmd)
  # Source: ENV["DEPLOY_TARGET"]
  # Sink: exec(cmd)
  def deploy
    target = ENV["DEPLOY_TARGET"]
    branch = ENV["DEPLOY_BRANCH"] || "main"
    config = OpenStruct.new(
      target: target,
      branch: branch,
      timestamp: Time.now.to_i
    )
    cmd = "deploy --host #{config.target} --branch #{config.branch}"
    exec(cmd)
  end

  # Safe version
  def deploy_safe
    allowed_targets = %w[staging production]
    target = ENV["DEPLOY_TARGET"]
    return unless allowed_targets.include?(target)
    exec("deploy", "--host", target, "--branch", "main")
  end
end

# ---------------------------------------------------------------------------
# Chain 9: tap/then chain -> eval
# ---------------------------------------------------------------------------

class PipelineProcessor
  # VULN 12: tap/then chain carries taint through -> eval
  # Chain: gets.chomp -> input -> then { |s| s.strip }
  #        -> tap { |s| log s } -> then { |s| "puts #{s}" }
  #        -> eval(code)
  # Source: gets.chomp
  # Sink: eval(code)
  def process_interactive
    print "Enter value: "
    code = gets.chomp
      .then { |s| s.strip }
      .tap { |s| $stderr.puts("Processing: #{s}") }
      .then { |s| "puts #{s}" }
    eval(code)
  end

  # VULN 13: then chain -> IO.popen
  # Chain: ENV["PIPELINE_CMD"] -> raw_cmd -> then strip -> then prepend prefix
  #        -> IO.popen(final_cmd)
  # Source: ENV["PIPELINE_CMD"]
  # Sink: IO.popen(final_cmd)
  def run_pipeline
    final_cmd = ENV["PIPELINE_CMD"]
      .then { |c| c.strip }
      .then { |c| "/usr/local/bin/#{c}" }
    IO.popen(final_cmd) { |io| io.read }
  end
end

# ---------------------------------------------------------------------------
# Chain 10: Conditional assignment (||=) -> command injection
# ---------------------------------------------------------------------------

class CacheManager
  def initialize
    @cache = {}
  end

  # VULN 14: ENV source -> string interpolation -> system
  # Chain: ENV["CACHE_DIR"] -> cache_dir -> path interpolation -> system(cmd)
  # Source: ENV["CACHE_DIR"]
  # Sink: system(cmd)
  def clear_cache(namespace)
    cache_dir = ENV["CACHE_DIR"]
    path = "#{cache_dir}/#{namespace}"
    cmd = "rm -rf #{path}"
    system(cmd)
  end

  # Safe version
  def clear_cache_safe(namespace)
    @default_dir ||= "/var/cache/app"
    safe_ns = namespace.gsub(/[^a-zA-Z0-9_-]/, "")
    path = File.join(@default_dir, safe_ns)
    FileUtils.rm_rf(path) if path.start_with?(@default_dir)
  end
end

# ---------------------------------------------------------------------------
# Chain 11: Implicit return -> caller uses tainted value
# ---------------------------------------------------------------------------

class ConfigLoader
  include Configurable

  # Implicit return: last expression is the return value
  # The tainted value flows to callers without an explicit return statement
  def load_user_setting(key)
    raw = ENV[key]
    raw.strip
  end

  # VULN 15: Implicit return carries taint -> system
  # Chain: ENV[key] -> load_user_setting (implicit return of raw.strip)
  #        -> shell_path -> "#{shell_path}/run.sh" -> system
  # Source: ENV[key]
  # Sink: system(cmd)
  def execute_configured_script
    shell_path = load_user_setting("SCRIPT_DIR")
    cmd = "#{shell_path}/run.sh"
    system(cmd)
  end

  # Safe version
  def execute_configured_script_safe
    shell_path = load_user_setting("SCRIPT_DIR")
    allowed = %w[/opt/scripts /usr/local/scripts]
    return unless allowed.include?(shell_path)
    system(File.join(shell_path, "run.sh"))
  end
end

# ---------------------------------------------------------------------------
# Entry point exercising multiple chains
# ---------------------------------------------------------------------------

def main
  db = Object.new

  # Chain 1 - block/yield
  runner = TaskRunner.new
  runner.execute_from_argv

  # Chain 2 - lambda
  engine = ExpressionEngine.new
  engine.run_interactive

  # Chain 3 - symbol-to-proc
  processor = DataProcessor.new(db)
  processor.find_records_by_ids({ ids: "1, 2, 3" })

  # Chain 4 - splat
  batch = BatchExecutor.new
  batch.run_from_args

  # Chain 5 - multi-hop interpolation
  builder = ReportBuilder.new
  builder.generate_report

  # Chain 6 - enumerable chain
  analytics = AnalyticsService.new(db)
  analytics.query_with_filters({ filters: "status = 'active'" })

  # Chain 7 - rescue/retry
  fetcher = HttpFetcher.new
  fetcher.fetch_webhook_data

  # Chain 8 - OpenStruct
  deployer = DeploymentManager.new
  deployer.deploy

  # Chain 9 - tap/then
  pipeline = PipelineProcessor.new
  pipeline.run_pipeline

  # Chain 10 - conditional assignment
  cache = CacheManager.new
  cache.clear_cache("session")

  # Chain 11 - implicit return
  config = ConfigLoader.new
  config.execute_configured_script
end

# ============================================================
# ADDITIONAL PATTERNS - Metaprogramming, Fibers, Pattern matching
# ============================================================

# Metaprogramming: define_method with taint
class DynamicHandler
  %w[exec system].each do |method_name|
    define_method("handle_#{method_name}") do |input|
      send(method_name, input)  # taint through dynamic method
    end
  end
end

# method_missing dispatch
class FlexibleHandler
  def method_missing(name, *args)
    if name.to_s.start_with?("run_")
      system(args.first)  # taint through method_missing
    else
      super
    end
  end
end

# Fiber flow
def fiber_flow(input)
  fiber = Fiber.new do
    cmd = Fiber.yield  # receives tainted data via resume
    system(cmd)
  end
  fiber.resume
  fiber.resume(input)  # taint flows into fiber
end

# Pattern matching (Ruby 3.0+)
def pattern_match_flow(data)
  case data
  in { command: String => cmd }
    system(cmd)  # taint from hash pattern
  in [String => first, *rest]
    eval(first)  # taint from array pattern
  else
    nil
  end
end

# Refinements
module StringExec
  refine String do
    def execute!
      system(self)  # taint through refinement method
    end
  end
end
