# Assignment-chain audit fixture (Ruby).
require_relative 'executor'

CONST_OK = "ls /tmp"

def passthrough(x); x; end
def wrap(x); "wrapped:#{x}"; end
def combine(acc, item); "#{acc}:#{item}"; end

class Bag
  attr_accessor :payload
  def initialize; @payload = ""; end
end

def chain_simple(params)
  # POSITIVE
  tmp = params["c1"]
  system(tmp)
end

def chain_multi_hop(params)
  # POSITIVE
  t1 = params["c2"]
  t2 = passthrough(t1)
  t3 = wrap(t2)
  t4 = passthrough(t3)
  system(t4)
end

def chain_branch_join(params, cond)
  # POSITIVE
  if cond
    t = params["c3"]
  else
    t = "safe-static"
  end
  system(t)
end

def chain_loop_carried(params, items)
  # POSITIVE
  acc = params["c4"]
  items.each do |item|
    acc = combine(acc, item)
  end
  system(acc)
end

def chain_field_write(params)
  # POSITIVE
  bag = Bag.new
  bag.payload = params["c5"]
  system(bag.payload)
end

def chain_subscript_write(params)
  # POSITIVE
  cmds = {}
  cmds["x"] = params["c6"]
  system(cmds["x"])
end

def chain_clean_constant(params)
  # NEGATIVE
  _unused = params["ignored"]
  system(CONST_OK)
end

def chain_cross_file(params)
  # POSITIVE
  t = params["c9"]
  run_in_other_file(t)
end
