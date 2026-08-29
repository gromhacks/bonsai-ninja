def taint_one_leg(cond)
  x = cond ? STDIN.gets : "safe-static"
  system(x)
end

def taint_overwritten(cond)
  x = STDIN.gets
  x = cond ? "clean-then" : "clean-else"
  system(x)
end
