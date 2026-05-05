class Mailer
  def initialize(smtp_host = "localhost", smtp_port = 25)
    @smtp_host = smtp_host
    @smtp_port = smtp_port
  end

  def send_welcome(user_email, username)
    subject = "Welcome to SocialApp, #{username}!"
    body = "Hello #{username},\n\nWelcome to our platform."
    deliver(user_email, subject, body)
  end

  def send_notification(user_email, message)
    deliver(user_email, "New Notification", message)
  end

  def send_password_reset(user_email, token)
    subject = "Password Reset"
    body = "Click here to reset your password: https://app.example.com/reset?token=#{token}"
    deliver(user_email, subject, body)
  end

  # VULN: Command injection via email
  def deliver(to, subject, body)
    cmd = "sendmail -t #{to} -s '#{subject}'"
    system(cmd)
  end

  # Safe version
  def deliver_safe(to, subject, body)
    require 'net/smtp'
    message = <<~MSG
      From: noreply@app.example.com
      To: #{to}
      Subject: #{subject}

      #{body}
    MSG
    Net::SMTP.start(@smtp_host, @smtp_port) do |smtp|
      smtp.send_message(message, "noreply@app.example.com", to)
    end
  end
end

class NotificationService
  def initialize(db)
    @db = db
  end

  def create_notification(user_id, type, message)
    @db.execute(
      "INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)",
      [user_id, type, message]
    )
  end

  def get_notifications(user_id, unread_only = false)
    if unread_only
      @db.execute("SELECT * FROM notifications WHERE user_id = ? AND read = 0 ORDER BY created_at DESC", [user_id])
    else
      @db.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", [user_id])
    end
  end

  def mark_read(notification_id)
    @db.execute("UPDATE notifications SET read = 1 WHERE id = ?", [notification_id])
  end

  def mark_all_read(user_id)
    @db.execute("UPDATE notifications SET read = 1 WHERE user_id = ?", [user_id])
  end

  def count_unread(user_id)
    result = @db.execute("SELECT COUNT(*) as cnt FROM notifications WHERE user_id = ? AND read = 0", [user_id])
    result.first[:cnt]
  end
end

class ReportGenerator
  def initialize(db)
    @db = db
  end

  def generate_user_report(user_id)
    user = @db.execute("SELECT * FROM users WHERE id = ?", [user_id]).first
    posts = @db.execute("SELECT COUNT(*) as cnt FROM posts WHERE author_id = ?", [user_id]).first[:cnt]
    {
      user: user,
      post_count: posts,
      generated_at: Time.now.to_s
    }
  end

  # VULN: Command injection in PDF export
  def export_to_pdf(content, output_path)
    temp_file = "/tmp/report_#{Time.now.to_i}.html"
    File.write(temp_file, content)
    cmd = "wkhtmltopdf #{temp_file} #{output_path}"
    system(cmd)
  end

  # Safe version
  def export_to_pdf_safe(content, output_name)
    temp_file = "/tmp/report_#{Time.now.to_i}.html"
    File.write(temp_file, content)
    safe_name = File.basename(output_name)
    output_path = "/var/app/reports/#{safe_name}"
    system("wkhtmltopdf", temp_file, output_path)
  end
end
