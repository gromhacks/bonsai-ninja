<?php
/* deep_flow_chain.php -- Entry point: reads user command from $_GET.
 * Flow: $_GET -> parse -> validate -> transform -> format -> exec()
 * 30+ steps across 3 files. All types prefixed with Dfc.
 */

require_once __DIR__ . '/deep_flow_helpers.php';
require_once __DIR__ . '/deep_flow_sink.php';

class DfcCommandToken {
    public string $verb = '';
    public string $target = '';
    public string $options = '';
    public int $priority = 0;
}

class DfcPipelineRequest {
    public string $raw_input = '';
    public string $parsed_command = '';
    public bool $validated = false;
    public int $auth_level = 0;
    public ?DfcCommandToken $token = null;

    public function __construct() {
        $this->token = new DfcCommandToken();
    }
}

class DfcExecutionContext {
    public string $formatted_command = '';
    public string $working_dir = '';
    public string $env_vars = '';
    public int $timeout_sec = 60;
    public bool $dry_run = false;
}

function dfc_read_user_input(): string {
    $input = $_GET['cmd'] ?? '';
    return $input;
}

function dfc_split_input(string $input): array {
    $parts = explode(' ', trim($input), 2);
    $verb = $parts[0] ?? '';
    $target = $parts[1] ?? '';
    return ['verb' => $verb, 'target' => $target];
}

function dfc_tokenize(string $verb, string $target): DfcCommandToken {
    $tok = new DfcCommandToken();
    $tok->verb = $verb;
    $tok->target = $target;
    $tok->priority = ($verb === 'deploy') ? 10 : 1;
    return $tok;
}

function dfc_run_pipeline(): int {
    $raw_input = dfc_read_user_input();
    if (empty($raw_input)) return 1;

    $parsed = dfc_split_input($raw_input);
    $tok = dfc_tokenize($parsed['verb'], $parsed['target']);
    $parsed_cmd = $tok->verb . ' ' . $tok->target;

    $builder = new DfcRequestBuilder();
    $req = $builder->build($raw_input, $tok);
    $req->parsed_command = $parsed_cmd;

    $validator = new DfcRequestValidator();
    if (!$validator->validate($req)) return 1;

    $transformer = new DfcRequestTransformer();
    if (!$transformer->transform($req)) return 1;

    $ctx_builder = new DfcContextBuilder();
    $ctx = $ctx_builder->build($req);
    if ($ctx === null) return 1;

    $middleware = new DfcMiddlewareChain();
    if (!$middleware->apply($ctx, $req)) return 1;

    $formatter = new DfcCommandFormatter();
    if (!$formatter->format($ctx)) return 1;

    $executor = new DfcPipelineExecutor();
    return $executor->execute($ctx);
}

dfc_run_pipeline();
