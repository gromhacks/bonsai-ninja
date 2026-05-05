require 'digest'
require 'securerandom'

class SearchQuery
  attr_reader :raw_query, :sort_field, :limit, :filters

  def initialize(query, sort_by, limit)
    @raw_query = query
    @sort_field = sort_by
    @limit = limit
    @filters = []
  end

  def validate
    raise "Query too long" if @raw_query && @raw_query.length > 500
  end

  # VULN: SQL injection in filter building
  def build_filter
    if @raw_query && !@raw_query.empty?
      @filters << "title LIKE '%#{@raw_query}%'"
    end
    if @sort_field
      @filters << "ORDER BY #{@sort_field}"
    end
  end

  def to_sql
    sql = "SELECT * FROM posts"
    unless @filters.empty?
      sql += " WHERE " + @filters.join(" AND ")
    end
    sql += " LIMIT #{@limit}" if @limit
    sql
  end
end

class User
  attr_accessor :id, :username, :email, :password_hash, :name, :bio, :role

  def initialize(attrs = {})
    attrs.each { |k, v| send("#{k}=", v) if respond_to?("#{k}=") }
  end

  def self.hash_password(password)
    salt = SecureRandom.hex(16)
    hash = Digest::SHA256.hexdigest(salt + password)
    "#{salt}:#{hash}"
  end

  def self.verify_password(password, stored)
    salt, hash = stored.split(":", 2)
    Digest::SHA256.hexdigest(salt + password) == hash
  end
end

class Post
  attr_accessor :id, :title, :content, :author_id, :created_at, :tags

  def initialize(attrs = {})
    attrs.each { |k, v| send("#{k}=", v) if respond_to?("#{k}=") }
  end
end

class Comment
  attr_accessor :id, :post_id, :author_id, :content, :created_at

  def initialize(attrs = {})
    attrs.each { |k, v| send("#{k}=", v) if respond_to?("#{k}=") }
  end
end

class Message
  attr_accessor :id, :from_id, :to_id, :content, :read, :created_at

  def initialize(attrs = {})
    attrs.each { |k, v| send("#{k}=", v) if respond_to?("#{k}=") }
  end
end

class PostRepository
  def initialize(db)
    @db = db
  end

  # VULN: SQL injection - Deep Chain sink
  def find_by_filter(search_query)
    sql = search_query.to_sql
    @db.execute(sql)
  end

  # Safe version
  def find_by_filter_safe(query, sort_by)
    allowed_sorts = %w[created_at title author_id]
    safe_sort = allowed_sorts.include?(sort_by) ? sort_by : "created_at"
    @db.execute("SELECT * FROM posts WHERE title LIKE ? ORDER BY #{safe_sort}", ["%#{query}%"])
  end

  def find_by_id(id)
    @db.execute("SELECT * FROM posts WHERE id = ?", [id]).first
  end

  def create(title, content, author_id)
    @db.execute("INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)", [title, content, author_id])
  end

  def update(id, title, content)
    @db.execute("UPDATE posts SET title = ?, content = ? WHERE id = ?", [title, content, id])
  end

  def delete(id)
    @db.execute("DELETE FROM posts WHERE id = ?", [id])
  end

  def find_by_author(author_id)
    @db.execute("SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC", [author_id])
  end

  # VULN: SQL injection in tag search
  def find_by_tag(tag)
    sql = "SELECT * FROM posts WHERE tags LIKE '%#{tag}%'"
    @db.execute(sql)
  end
end

class UserRepository
  def initialize(db)
    @db = db
  end

  def find_by_username(username)
    @db.execute("SELECT * FROM users WHERE username = ?", [username]).first
  end

  def find_by_id(id)
    @db.execute("SELECT * FROM users WHERE id = ?", [id]).first
  end

  def create(username, email, password_hash)
    @db.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", [username, email, password_hash])
  end

  def update(id, attrs)
    sets = attrs.map { |k, _v| "#{k} = ?" }.join(", ")
    values = attrs.values + [id]
    @db.execute("UPDATE users SET #{sets} WHERE id = ?", values)
  end

  # VULN: SQL injection in user search
  def search(query)
    sql = "SELECT * FROM users WHERE username LIKE '%#{query}%' OR email LIKE '%#{query}%'"
    @db.execute(sql)
  end
end
