require 'sqlite3'

module AuthService
  def self.verify_token(token)
    db = SQLite3::Database.new("auth.db")
    query = "SELECT user_id FROM tokens WHERE token = '#{token}'"
    row = db.execute(query) # sink: SQL injection
    row.first&.first
  end

  def self.run_admin_command(user_id, cmd)
    if user_id
      system("notify-admin " + cmd) # sink: command injection
    end
  end
end
