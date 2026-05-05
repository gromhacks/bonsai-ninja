# mega_flow Ruby entry — reads one tainted stdin line, then dispatches
# it through a pipeline that exercises every idiomatic Ruby flow
# construct (blocks, procs/lambdas, keyword args, case/in pattern
# matching, begin/rescue/ensure, modules + mixins, Enumerable chaining,
# yield, heredocs, safe-navigation, splat).
require_relative 'pipeline'

def handle_request
  # SOURCE — Kernel#gets reads one tainted stdin line.
  # Matched by ruby.source.stdin_gets (call-kind, name=gets).
  raw = gets.to_s
  user = ENV.fetch('USER', 'anon')

  envelope = {
    kind: :run,
    cmd: "#{raw}",
    user: user,
    length: raw&.length || 0,
    extras: [raw.dup],
  }

  Pipeline.orchestrate(envelope)
end

handle_request
