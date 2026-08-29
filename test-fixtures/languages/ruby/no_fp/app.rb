CONST_OK = "ls /tmp".freeze

def decoy
  _unused = STDIN.gets
  system(CONST_OK)
end

def unrelated_chain
  a = "hello"
  a.upcase
end
