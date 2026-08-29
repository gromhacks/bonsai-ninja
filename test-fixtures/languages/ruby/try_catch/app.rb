def tainted_through_try
  t = begin
    STDIN.gets
  rescue StandardError
    ""
  end
  system(t)
end
