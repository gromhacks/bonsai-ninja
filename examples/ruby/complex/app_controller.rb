require_relative 'models'
require_relative 'services'
require_relative 'mailer'
require_relative 'validators'

class ApplicationController
  attr_reader :params, :session, :db

  def initialize(params, session, db)
    @params = params
    @session = session
    @db = db
  end
end

class PostsController < ApplicationController
  def initialize(params, session, db)
    super
    @post_service = PostService.new(db)
    @user_service = UserService.new(db)
  end

  # VULN: SQL injection via search - Deep Chain
  def search
    query = params[:q]
    sort_by = params[:sort] || "created_at"
    limit = params[:limit] || "20"
    search_query = SearchQuery.new(query, sort_by, limit)
    search_query.validate
    search_query.build_filter
    @post_service.find_by_filter(search_query)
  end

  # Safe version
  def search_safe
    query = params[:q]
    sort_by = params[:sort] || "created_at"
    @post_service.find_by_filter_safe(query, sort_by)
  end

  def index
    page = (params[:page] || 1).to_i
    @post_service.list_posts(page)
  end

  def show
    id = params[:id]
    @post_service.get_post(id)
  end

  def create
    title = params[:title]
    content = params[:content]
    user_id = session[:user_id]
    @post_service.create_post(title, content, user_id)
  end

  def update
    id = params[:id]
    title = params[:title]
    content = params[:content]
    @post_service.update_post(id, title, content)
  end

  def destroy
    id = params[:id]
    @post_service.delete_post(id)
  end

  # VULN: XSS via raw output
  def render_post(post)
    html = "<article>"
    html += "<h1>#{post[:title]}</h1>"
    html += "<div>#{post[:content]}</div>"
    html += "<p>By: #{post[:author_name]}</p>"
    html += "</article>"
    raw(html)
  end

  # Safe version
  def render_post_safe(post)
    html = "<article>"
    html += "<h1>#{ERB::Util.html_escape(post[:title])}</h1>"
    html += "<div>#{ERB::Util.html_escape(post[:content])}</div>"
    html += "</article>"
    html
  end
end

class UsersController < ApplicationController
  def initialize(params, session, db)
    super
    @user_service = UserService.new(db)
  end

  def login
    username = params[:username]
    password = params[:password]
    user = @user_service.authenticate(username, password)
    if user
      session[:user_id] = user[:id]
      { status: "success", user: user }
    else
      { status: "error", message: "Invalid credentials" }
    end
  end

  def register
    username = params[:username]
    email = params[:email]
    password = params[:password]
    @user_service.create_user(username, email, password)
  end

  def profile
    user_id = params[:id]
    @user_service.get_profile(user_id)
  end

  def update_profile
    user_id = session[:user_id]
    # VULN: Mass assignment
    @user_service.update_user(user_id, params)
  end

  # Safe version
  def update_profile_safe
    user_id = session[:user_id]
    allowed = params.slice(:name, :bio, :avatar_url)
    @user_service.update_user(user_id, allowed)
  end
end

class AdminController < ApplicationController
  def initialize(params, session, db)
    super
    @admin_service = AdminService.new(db)
  end

  # VULN: SQL injection in admin search
  def search_users
    query = params[:query]
    @admin_service.search_users(query)
  end

  # VULN: Command injection
  def run_task
    task_name = params[:task]
    @admin_service.run_maintenance(task_name)
  end

  # VULN: XSS in admin dashboard
  def dashboard
    search = params[:search] || ""
    html = "<html><body>"
    html += "<h1>Admin Panel</h1>"
    html += "<p>Search: #{search}</p>"
    html += "</body></html>"
    raw(html)
  end

  # Safe version
  def dashboard_safe
    search = ERB::Util.html_escape(params[:search] || "")
    "<html><body><h1>Admin Panel</h1><p>Search: #{search}</p></body></html>"
  end

  def stats
    @admin_service.get_stats
  end
end

class MessagesController < ApplicationController
  def send_message
    to_user = params[:to]
    content = params[:content]
    from_user = session[:user_id]
    message_service = MessageService.new(db)
    message_service.send(from_user, to_user, content)
  end

  def inbox
    user_id = session[:user_id]
    message_service = MessageService.new(db)
    message_service.get_inbox(user_id)
  end
end

class UploadsController < ApplicationController
  # VULN: Path traversal
  def download
    filename = params[:filename]
    path = File.join("/var/app/uploads", filename)
    File.read(path)
  end

  # Safe version
  def download_safe
    filename = File.basename(params[:filename])
    path = File.join("/var/app/uploads", filename)
    unless File.expand_path(path).start_with?(File.expand_path("/var/app/uploads"))
      raise "Invalid path"
    end
    File.read(path)
  end
end

def raw(html)
  html
end
