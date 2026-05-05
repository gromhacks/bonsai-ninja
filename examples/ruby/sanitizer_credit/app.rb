require 'shellwords'

def unsanitized
  t = STDIN.gets
  system(t)
end

def sanitized
  t = STDIN.gets
  safe = Shellwords.escape(t)
  system(safe)
end
