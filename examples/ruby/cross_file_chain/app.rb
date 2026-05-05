# Cross-file argument flow audit fixture (Ruby).
require_relative 'pipeline'

def handler
  # POSITIVE
  user = STDIN.gets
  run_pipeline(user)
end

def handler_split
  # POSITIVE
  user = STDIN.gets
  flag = STDIN.gets
  run_pipeline("#{user}:#{flag}")
end
