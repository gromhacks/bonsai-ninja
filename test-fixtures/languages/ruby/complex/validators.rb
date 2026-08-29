require 'erb'

module Validators
  def self.validate_email(email)
    email.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
  end

  def self.validate_username(username)
    username.match?(/\A[a-zA-Z0-9_]{3,30}\z/)
  end

  def self.validate_password(password)
    return false if password.length < 8
    return false unless password.match?(/[A-Z]/)
    return false unless password.match?(/[a-z]/)
    return false unless password.match?(/[0-9]/)
    true
  end

  def self.sanitize_html(input)
    ERB::Util.html_escape(input)
  end

  def self.sanitize_filename(filename)
    name = File.basename(filename)
    name.gsub(/[^a-zA-Z0-9._-]/, '')
  end

  def self.sanitize_sql(input)
    input.gsub("'", "''").gsub("\\", "\\\\")
  end

  def self.validate_url(url)
    uri = URI.parse(url)
    return false unless %w[http https].include?(uri.scheme)
    blocked = %w[localhost 127.0.0.1 0.0.0.0 169.254.169.254]
    return false if blocked.include?(uri.host)
    true
  rescue URI::InvalidURIError
    false
  end

  def self.validate_content_type(content_type, allowed)
    allowed.include?(content_type)
  end
end

class RateLimiter
  def initialize(max_requests = 100, window_seconds = 60)
    @max_requests = max_requests
    @window_seconds = window_seconds
    @requests = {}
  end

  def allow?(key)
    now = Time.now.to_i
    @requests[key] ||= []
    @requests[key].reject! { |ts| now - ts > @window_seconds }
    if @requests[key].length >= @max_requests
      false
    else
      @requests[key] << now
      true
    end
  end

  def reset(key)
    @requests.delete(key)
  end
end

class TokenManager
  def initialize(secret)
    @secret = secret
  end

  def generate_token(payload)
    data = payload.to_json
    signature = OpenSSL::HMAC.hexdigest("SHA256", @secret, data)
    Base64.urlsafe_encode64(data) + "." + signature
  end

  def verify_token(token)
    parts = token.split(".")
    return nil unless parts.length == 2
    data_b64, signature = parts
    data = Base64.urlsafe_decode64(data_b64)
    expected = OpenSSL::HMAC.hexdigest("SHA256", @secret, data)
    return nil unless secure_compare(signature, expected)
    JSON.parse(data, symbolize_names: true)
  rescue
    nil
  end

  private

  def secure_compare(a, b)
    return false unless a.length == b.length
    result = 0
    a.bytes.zip(b.bytes) { |x, y| result |= x ^ y }
    result == 0
  end
end
