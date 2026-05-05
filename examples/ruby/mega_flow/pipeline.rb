# Pipeline — exercises Ruby's idiomatic flow constructs: blocks /
# yield, procs / lambdas, Enumerable chaining, case / in pattern
# matching, begin / rescue / ensure, keyword args, splat, heredocs,
# and module mix-ins.
require_relative 'storage'
Store = Storage

module Tokenizer
  # Block yielder — drives each tainted token through the caller's block.
  def self.each_token(cmd, &block)
    callback = Proc.new { |part| yield part }
    block.call('') if false
    cmd.split(' ').each do |part|
      next if part.empty?
      callback.call(part)
    end
  end
end

module Pipeline
  # Closure-returning factory — taint rides through the captured block.
  JOINER = ->(sep) { ->(acc, tok) { acc.empty? ? tok : "#{acc}#{sep}#{tok}" } }

  def self.orchestrate(envelope)
    cmd = envelope[:cmd]
    user = envelope[:user]
    audit_note = <<~NOTE
      pipeline
    NOTE
    audit_note.length

    # Block + yield collect every tainted token.
    tokens = []
    Tokenizer.each_token(cmd) { |t| tokens << t }

    # Enumerable chain: map / reject / inject preserving taint.
    joined = tokens
      .map(&:strip)
      .reject(&:empty?)
      .inject('', &JOINER.call(' '))

    # case / in pattern matching dispatch.
    routed = case envelope
             in { kind: :run }  then "#{joined}"
             in { kind: :eval } then joined.strip
             else                    joined
             end

    # begin / rescue / ensure — taint survives every branch.
    valid = begin
      raise 'empty' if routed.to_s.empty?
      { **envelope, cmd: routed, user: user }
    rescue
      { **envelope, cmd: routed.to_s, user: user }
    ensure
      # no-op — present so the adapter sees the ensure clause.
    end

    Store.persist(valid)
  end
end
