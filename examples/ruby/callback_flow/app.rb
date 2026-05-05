def executor(cmd)
  system(cmd)
end

def run_cb(cb, value)
  cb.call(value)
end

def pass_to_callback
  t = STDIN.gets
  run_cb(method(:executor), t)
end
