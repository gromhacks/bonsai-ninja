<?php
/* deep_flow_helpers.php -- Middleware: validation, transformation pipeline.
 * All types prefixed with Dfc.
 */

class DfcRequestBuilder {
    public function build(string $raw, DfcCommandToken $tok): DfcPipelineRequest {
        $req = new DfcPipelineRequest();
        $req->raw_input = $raw;
        $req->token = $tok;
        return $req;
    }
}

class DfcRequestValidator {
    private function checkLength(DfcPipelineRequest $req): bool {
        $len = strlen($req->raw_input);
        return $len > 0 && $len < 900;
    }

    private function checkVerb(DfcPipelineRequest $req): bool {
        $allowed = ['run', 'deploy', 'status', 'exec', 'build'];
        return in_array($req->token->verb, $allowed, true);
    }

    public function validate(DfcPipelineRequest $req): bool {
        if (!$this->checkLength($req)) return false;
        if (!$this->checkVerb($req)) return false;
        $req->validated = true;
        $req->auth_level = 1;
        return true;
    }
}

class DfcRequestTransformer {
    private function normalizeWhitespace(string $input): string {
        return preg_replace('/\s+/', ' ', trim($input));
    }

    public function transform(DfcPipelineRequest $req): bool {
        if (!$req->validated) return false;
        $req->parsed_command = $this->normalizeWhitespace($req->parsed_command);
        return true;
    }
}

class DfcContextBuilder {
    public function build(DfcPipelineRequest $req): ?DfcExecutionContext {
        $ctx = new DfcExecutionContext();
        $ctx->formatted_command = $req->parsed_command;
        $ctx->working_dir = '/var/run/pipeline/' . $req->token->target;
        $ctx->env_vars = 'PIPELINE_CMD=' . $req->token->verb;
        $ctx->timeout_sec = ($req->token->priority >= 10) ? 300 : 60;
        return $ctx;
    }
}

class DfcMiddlewareChain {
    private function auditTrail(DfcExecutionContext $ctx, DfcPipelineRequest $req): void {
        $ctx->formatted_command .= ' --audit-level=' . $req->auth_level;
    }

    private function prependEnv(DfcExecutionContext $ctx): void {
        $ctx->formatted_command = $ctx->env_vars . ' ' . $ctx->formatted_command;
    }

    public function apply(DfcExecutionContext $ctx, DfcPipelineRequest $req): bool {
        $this->auditTrail($ctx, $req);
        $this->prependEnv($ctx);
        return true;
    }
}
