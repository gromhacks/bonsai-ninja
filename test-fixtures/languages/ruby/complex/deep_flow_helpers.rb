# deep_flow_helpers.rb -- Middleware: validation, transformation pipeline.
# All types prefixed with Dfc.

class DfcRequestBuilder
  def build(raw, tok)
    req = DfcPipelineRequest.new
    req.raw_input = raw
    req.token = tok
    req
  end
end

class DfcRequestValidator
  def check_length(req)
    len = req.raw_input.length
    len > 0 && len < 900
  end

  def check_verb(req)
    allowed = %w[run deploy status exec build]
    allowed.include?(req.token.verb)
  end

  def validate(req)
    return false unless check_length(req)
    return false unless check_verb(req)
    req.validated = true
    req.auth_level = 1
    true
  end
end

class DfcRequestTransformer
  def normalize_whitespace(input)
    input.gsub(/\s+/, ' ').strip
  end

  def transform(req)
    return false unless req.validated
    req.parsed_command = normalize_whitespace(req.parsed_command)
    true
  end
end

class DfcContextBuilder
  def build(req)
    ctx = DfcExecutionContext.new
    ctx.formatted_command = req.parsed_command
    ctx.working_dir = "/var/run/pipeline/#{req.token.target}"
    ctx.env_vars = "PIPELINE_CMD=#{req.token.verb}"
    ctx.timeout_sec = req.token.priority >= 10 ? 300 : 60
    ctx
  end
end

class DfcMiddlewareChain
  def audit_trail(ctx, req)
    ctx.formatted_command += " --audit-level=#{req.auth_level}"
  end

  def prepend_env(ctx)
    ctx.formatted_command = "#{ctx.env_vars} #{ctx.formatted_command}"
  end

  def apply(ctx, req)
    audit_trail(ctx, req)
    prepend_env(ctx)
    true
  end
end
