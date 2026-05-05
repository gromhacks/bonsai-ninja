# deep_flow_chain.rb -- Entry point: reads user command from ENV or gets.
# Flow: ENV/gets -> parse -> validate -> transform -> format -> system()
# 30+ steps across 3 files. All types prefixed with Dfc.

require_relative 'deep_flow_helpers'
require_relative 'deep_flow_sink'

class DfcCommandToken
  attr_accessor :verb, :target, :priority

  def initialize
    @verb = ''
    @target = ''
    @priority = 0
  end
end

class DfcPipelineRequest
  attr_accessor :raw_input, :parsed_command, :validated, :auth_level, :token

  def initialize
    @raw_input = ''
    @parsed_command = ''
    @validated = false
    @auth_level = 0
    @token = DfcCommandToken.new
  end
end

class DfcExecutionContext
  attr_accessor :formatted_command, :working_dir, :env_vars,
                :timeout_sec, :dry_run

  def initialize
    @formatted_command = ''
    @working_dir = ''
    @env_vars = ''
    @timeout_sec = 60
    @dry_run = false
  end
end

class DfcCommandParser
  def self.read_user_input
    input = ENV['CMD']
    if input.nil? || input.empty?
      print "Enter command> "
      input = gets
    end
    input
  end

  def self.split_input(input)
    parts = input.strip.split(' ', 2)
    { verb: parts[0] || '', target: parts[1] || '' }
  end

  def self.tokenize(verb, target)
    tok = DfcCommandToken.new
    tok.verb = verb
    tok.target = target
    tok.priority = (verb == 'deploy') ? 10 : 1
    tok
  end
end

def dfc_run_pipeline
  raw_input = DfcCommandParser.read_user_input
  return 1 if raw_input.nil? || raw_input.empty?

  parsed = DfcCommandParser.split_input(raw_input)
  tok = DfcCommandParser.tokenize(parsed[:verb], parsed[:target])
  parsed_cmd = "#{tok.verb} #{tok.target}"

  builder = DfcRequestBuilder.new
  req = builder.build(raw_input, tok)
  req.parsed_command = parsed_cmd

  validator = DfcRequestValidator.new
  return 1 unless validator.validate(req)

  transformer = DfcRequestTransformer.new
  return 1 unless transformer.transform(req)

  ctx_builder = DfcContextBuilder.new
  ctx = ctx_builder.build(req)
  return 1 if ctx.nil?

  middleware = DfcMiddlewareChain.new
  return 1 unless middleware.apply(ctx, req)

  formatter = DfcCommandFormatter.new
  return 1 unless formatter.format(ctx)

  executor = DfcPipelineExecutor.new
  executor.execute(ctx)
end

dfc_run_pipeline
