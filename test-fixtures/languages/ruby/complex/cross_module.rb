require_relative 'app_controller'
require_relative 'services'
require_relative 'models'
require_relative 'validators'
require_relative 'mailer'

# --------------------------------------------------------------------------
# cross_module.rb
# Cross-file vulnerability chains exercising require_relative imports
# across all 5 existing Ruby example files.
# Each chain comment documents: files touched, hop count, source, sink.
# --------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Chain A: 12-hop, 4-file chain
# Files: cross_module.rb -> app_controller.rb -> services.rb -> models.rb
#
# VULN Chain A: params[:q] -> CrossModuleOrchestrator#deep_search
#   -> PostsController#search -> SearchQuery.new (models.rb)
#   -> SearchQuery#validate -> SearchQuery#build_filter (interpolates raw_query)
#   -> PostService#find_by_filter (services.rb)
#   -> PostRepository#find_by_filter (models.rb) -> SearchQuery#to_sql
#   -> @db.execute(sql) -- SQL injection
# Source: params[:q] (app_controller.rb via PostsController)
# Sink: @db.execute(sql) (models.rb PostRepository#find_by_filter)
# Hops: params[:q] -> query -> SearchQuery.new -> @raw_query -> build_filter
#       -> @filters << interpolated string -> to_sql -> sql -> execute
# Files: cross_module.rb -> app_controller.rb -> services.rb -> models.rb
# ---------------------------------------------------------------------------

class CrossModuleOrchestrator
  def initialize(params, session, db)
    @params = params
    @session = session
    @db = db
    @posts_controller = PostsController.new(params, session, db)
    @admin_controller = AdminController.new(params, session, db)
    @mailer = Mailer.new
    @report_gen = ReportGenerator.new(db)
  end

  # Chain A entry: 12-hop cross-file SQL injection
  def deep_search
    @posts_controller.search
  end

  # Also exercises the render path through app_controller for XSS
  def deep_search_and_render
    results = @posts_controller.search
    results.each do |post|
      @posts_controller.render_post(post)
    end
  end
end

# ---------------------------------------------------------------------------
# Chain B: Module-level class variable (@@) taint propagation
# Files: cross_module.rb -> validators.rb -> mailer.rb
#
# VULN Chain B: ENV["DEFAULT_RECIPIENT"] -> @@default_recipient
#   -> GlobalConfig.default_recipient (class variable read)
#   -> NotificationDispatcher#send_alert -> Mailer#send_notification
#   -> Mailer#deliver -> system("sendmail -t #{to} ...")
#   -- Command injection via email address in class variable
# Source: ENV["DEFAULT_RECIPIENT"]
# Sink: system(cmd) in Mailer#deliver (mailer.rb)
# Hops: ENV -> @@default_recipient -> class method read -> recipient
#       -> send_notification -> deliver -> system
# Files: cross_module.rb -> mailer.rb
# ---------------------------------------------------------------------------

class GlobalConfig
  @@default_recipient = nil
  @@admin_email = nil

  def self.init_from_env
    @@default_recipient = ENV["DEFAULT_RECIPIENT"]
    @@admin_email = ENV["ADMIN_EMAIL"]
  end

  def self.default_recipient
    @@default_recipient
  end

  def self.admin_email
    @@admin_email
  end
end

class NotificationDispatcher
  def initialize
    @mailer = Mailer.new
  end

  # Chain B: ENV source -> direct system sink + cross-file delegation
  def send_alert(message)
    recipient = ENV["DEFAULT_RECIPIENT"]
    cmd = "sendmail -t #{recipient}"
    system(cmd)
    @mailer.send_notification(recipient, message)
  end

  def send_admin_alert(message)
    admin = ENV["ADMIN_EMAIL"]
    cmd = "notify-admin #{admin}"
    system(cmd)
    @mailer.send_notification(admin, message)
  end
end

# ---------------------------------------------------------------------------
# Chain C: Block/Proc callback taint propagation
# Files: cross_module.rb -> services.rb -> models.rb
#
# VULN Chain C: params[:tag] -> CallbackPipeline#process_with_callback
#   -> yields tainted tag to block -> block calls PostRepository#find_by_tag
#   -> find_by_tag interpolates tag into SQL -> @db.execute(sql)
#   -- SQL injection via callback block
# Source: params[:tag]
# Sink: @db.execute(sql) in PostRepository#find_by_tag (models.rb)
# Hops: params[:tag] -> tag -> yield(tag) -> block receives tag
#       -> repo.find_by_tag(tag) -> SQL interpolation -> execute
# Files: cross_module.rb -> models.rb
# ---------------------------------------------------------------------------

class CallbackPipeline
  def initialize(db)
    @db = db
    @repo = PostRepository.new(db)
  end

  def process_with_callback(value)
    processed = yield(value) if block_given?
    processed
  end

  # Chain C entry: block callback carries taint to repository
  def search_by_tag_with_callback(tag)
    process_with_callback(tag) do |t|
      @repo.find_by_tag(t)
    end
  end

  # Also supports Proc-based callbacks
  def process_with_proc(value, callback)
    callback.call(value)
  end

  def search_by_tag_with_proc(tag)
    finder = Proc.new { |t| @repo.find_by_tag(t) }
    process_with_proc(tag, finder)
  end
end

# ---------------------------------------------------------------------------
# Chain D: Re-exported wrapper taint propagation
# Files: cross_module.rb -> services.rb -> mailer.rb
#
# VULN Chain D: params[:task] -> SecureAdminFacade#run_admin_task
#   -> AdminService#run_maintenance (services.rb)
#   -> "rake #{task_name}" -> system(cmd) -- command injection
#   The facade re-exports AdminService methods without sanitization,
#   creating an indirect path that bypasses local validation.
# Source: params[:task]
# Sink: system(cmd) in AdminService#run_maintenance (services.rb)
# Hops: params[:task] -> task -> validate_task_name (no-op for valid chars)
#       -> @admin.run_maintenance(task) -> cmd interpolation -> system
# Files: cross_module.rb -> services.rb
#
#   Additionally: params[:expr] -> SecureAdminFacade#evaluate
#   -> AdminService#evaluate_expression -> eval(expr) -- code injection
# Source: params[:expr]
# Sink: eval(expr) in AdminService#evaluate_expression (services.rb)
# ---------------------------------------------------------------------------

class SecureAdminFacade
  def initialize(db)
    @admin = AdminService.new(db)
    @validator = Validators
  end

  # Re-exports AdminService#run_maintenance -- supposed to add validation
  # but validate_task_name does not actually block malicious input
  def run_admin_task(task)
    validated = validate_task_name(task)
    @admin.run_maintenance(validated)
  end

  # Re-exports AdminService#evaluate_expression with no real guard
  def evaluate(expr)
    @admin.evaluate_expression(expr)
  end

  # Re-exports AdminService#search_users
  def search_users(query)
    @admin.search_users(query)
  end

  private

  # Insufficient validation: only checks length, not content
  def validate_task_name(name)
    raise "Task name too long" if name.length > 100
    name
  end
end

# ---------------------------------------------------------------------------
# Chain E: Recursive taint propagation
# Files: cross_module.rb -> validators.rb -> mailer.rb
#
# VULN Chain E: ENV["TEMPLATE_PATH"] -> RecursiveTemplateRenderer#render
#   -> reads file content -> finds {{include:path}} directives
#   -> recursively calls render(included_path) with tainted sub-path
#   -> accumulated output passed to ReportGenerator#export_to_pdf
#   -> system("wkhtmltopdf #{temp_file} #{output_path}") -- command injection
# Source: ENV["TEMPLATE_PATH"]
# Sink: system(cmd) in ReportGenerator#export_to_pdf (mailer.rb)
# Hops: ENV -> template_path -> File.read(path) -> content
#       -> scan for includes -> recursive render(sub_path)
#       -> accumulated html -> export_to_pdf -> system
# Files: cross_module.rb -> mailer.rb
# ---------------------------------------------------------------------------

class RecursiveTemplateRenderer
  MAX_DEPTH = 10

  def initialize(db)
    @report_gen = ReportGenerator.new(db)
    @rendered_cache = {}
  end

  # Recursive render: reads file content and processes include directives
  def render(path, depth = 0)
    return "[MAX DEPTH]" if depth > MAX_DEPTH
    return @rendered_cache[path] if @rendered_cache.key?(path)

    content = File.read(path)

    # Process {{include:relative/path}} directives recursively
    rendered = content.gsub(/\{\{include:(.+?)\}\}/) do
      sub_path = File.join(File.dirname(path), $1)
      render(sub_path, depth + 1)
    end

    @rendered_cache[path] = rendered
    return rendered
  end

  # Chain E entry: ENV path -> system + recursive render -> PDF export -> system
  def render_and_export
    template_path = ENV["TEMPLATE_PATH"]
    cmd = "cat #{template_path}"
    system(cmd)
    html = render(template_path)
    output = ENV["OUTPUT_PATH"] || "/tmp/output.pdf"
    @report_gen.export_to_pdf(html, output)
  end
end

# ---------------------------------------------------------------------------
# Integration: Wire up all cross-module chains
# ---------------------------------------------------------------------------

class CrossModuleApp
  def initialize(db)
    @db = db
    GlobalConfig.init_from_env
  end

  def run_chain_a(params, session)
    orchestrator = CrossModuleOrchestrator.new(params, session, @db)
    orchestrator.deep_search
  end

  def run_chain_b(message)
    dispatcher = NotificationDispatcher.new
    dispatcher.send_alert(message)
  end

  def run_chain_c(params)
    pipeline = CallbackPipeline.new(@db)
    pipeline.search_by_tag_with_callback(params[:tag])
  end

  def run_chain_d(params)
    facade = SecureAdminFacade.new(@db)
    facade.run_admin_task(params[:task])
  end

  def run_chain_e
    renderer = RecursiveTemplateRenderer.new(@db)
    renderer.render_and_export
  end
end

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_cross_module
  db = Object.new

  params = {
    q: "search term",
    sort: "title",
    limit: "10",
    tag: "ruby",
    task: "cleanup",
    expr: "1 + 1"
  }
  session = { user_id: 1 }

  app = CrossModuleApp.new(db)

  # Chain A: 12-hop, 4-file SQL injection
  app.run_chain_a(params, session)

  # Chain B: Class variable propagation -> command injection
  app.run_chain_b("System alert")

  # Chain C: Block/Proc callback -> SQL injection
  app.run_chain_c(params)

  # Chain D: Re-exported wrapper -> command injection / code injection
  app.run_chain_d(params)

  # Chain E: Recursive template rendering -> command injection
  app.run_chain_e
end
