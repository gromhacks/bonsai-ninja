# Ruby sanitizer-fixture — parallel handlers per sink family.
require 'cgi'
require 'shellwords'
require 'sqlite3'

class Handlers
  def initialize(db)
    @db = db
  end

  # --- Command injection --------------------------------------------------

  def cmd_raw(user_input)
    system("ping #{user_input}")
  end

  def cmd_safe(user_input)
    safe = Shellwords.escape(user_input)
    system("ping #{safe}")
  end

  # --- SQL injection ------------------------------------------------------

  def sql_raw(user_id)
    @db.execute("SELECT * FROM users WHERE id = '#{user_id}'")
  end

  def sql_safe(user_id)
    @db.execute("SELECT * FROM users WHERE id = ?", [user_id])
  end

  # --- XSS ----------------------------------------------------------------

  def xss_raw(name)
    "<p>Hello, #{name}</p>"
  end

  def xss_safe(name)
    safe = CGI.escapeHTML(name)
    "<p>Hello, #{safe}</p>"
  end
end
