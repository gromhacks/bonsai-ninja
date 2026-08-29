require_relative 'models'

class PostService
  def initialize(db)
    @db = db
    @repo = PostRepository.new(db)
  end

  def find_by_filter(search_query)
    @repo.find_by_filter(search_query)
  end

  def find_by_filter_safe(query, sort_by)
    @repo.find_by_filter_safe(query, sort_by)
  end

  def list_posts(page, per_page = 20)
    offset = (page - 1) * per_page
    @db.execute("SELECT * FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?", [per_page, offset])
  end

  def get_post(id)
    @repo.find_by_id(id)
  end

  def create_post(title, content, author_id)
    @repo.create(title, content, author_id)
  end

  def update_post(id, title, content)
    @repo.update(id, title, content)
  end

  def delete_post(id)
    @repo.delete(id)
  end
end

class UserService
  def initialize(db)
    @db = db
    @repo = UserRepository.new(db)
  end

  def authenticate(username, password)
    user = @repo.find_by_username(username)
    return nil unless user
    return nil unless User.verify_password(password, user[:password_hash])
    user
  end

  def create_user(username, email, password)
    password_hash = User.hash_password(password)
    @repo.create(username, email, password_hash)
  end

  def get_profile(user_id)
    @repo.find_by_id(user_id)
  end

  def update_user(user_id, attrs)
    @repo.update(user_id, attrs)
  end
end

class AdminService
  def initialize(db)
    @db = db
  end

  # VULN: SQL injection
  def search_users(query)
    sql = "SELECT * FROM users WHERE username LIKE '%#{query}%'"
    @db.execute(sql)
  end

  # Safe version
  def search_users_safe(query)
    @db.execute("SELECT * FROM users WHERE username LIKE ?", ["%#{query}%"])
  end

  # VULN: Command injection
  def run_maintenance(task_name)
    cmd = "rake #{task_name}"
    system(cmd)
  end

  # Safe version
  def run_maintenance_safe(task_name)
    allowed = %w[cleanup optimize backup]
    return unless allowed.include?(task_name)
    system("rake", task_name)
  end

  def get_stats
    users = @db.execute("SELECT COUNT(*) as cnt FROM users").first[:cnt]
    posts = @db.execute("SELECT COUNT(*) as cnt FROM posts").first[:cnt]
    { users: users, posts: posts }
  end

  # VULN: Code injection via eval
  def evaluate_expression(expr)
    eval(expr)
  end

  # VULN: Template injection
  def render_notification(template, data)
    erb = ERB.new(template)
    erb.result_with_hash(data)
  end

  # VULN: Deserialization
  def restore_session(data)
    decoded = Base64.decode64(data)
    Marshal.load(decoded)
  end
end

class MessageService
  def initialize(db)
    @db = db
  end

  def send(from_id, to_id, content)
    @db.execute("INSERT INTO messages (from_id, to_id, content) VALUES (?, ?, ?)", [from_id, to_id, content])
  end

  def get_inbox(user_id)
    @db.execute("SELECT * FROM messages WHERE to_id = ? ORDER BY created_at DESC", [user_id])
  end

  def mark_read(message_id)
    @db.execute("UPDATE messages SET read = 1 WHERE id = ?", [message_id])
  end

  # VULN: SQL injection in message search
  def search_messages(keyword)
    sql = "SELECT * FROM messages WHERE content LIKE '%#{keyword}%'"
    @db.execute(sql)
  end
end

class ImageService
  UPLOAD_DIR = "/var/app/uploads"

  # VULN: Command injection via filename
  def process_image(filename, width, height)
    cmd = "convert #{UPLOAD_DIR}/#{filename} -resize #{width}x#{height} #{UPLOAD_DIR}/thumb_#{filename}"
    system(cmd)
  end

  # Safe version
  def process_image_safe(filename, width, height)
    safe_name = File.basename(filename)
    safe_width = width.to_i
    safe_height = height.to_i
    system("convert", "#{UPLOAD_DIR}/#{safe_name}", "-resize", "#{safe_width}x#{safe_height}", "#{UPLOAD_DIR}/thumb_#{safe_name}")
  end

  # VULN: SSRF via image URL
  def download_image(url)
    require 'open-uri'
    data = URI.open(url).read
    data
  end
end
