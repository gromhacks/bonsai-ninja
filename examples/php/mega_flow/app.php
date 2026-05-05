<?php
// mega_flow PHP entry — reads one tainted stdin line, then dispatches
// through a pipeline that exercises every idiomatic PHP flow
// construct (closures, arrow fns, match expressions, null-coalescing,
// spread, variadic, try/catch/finally, generators, traits).
require_once __DIR__ . '/pipeline.php';

function handle_request(): string {
    // SOURCE — readline() reads one tainted stdin line.
    // Matched by php.source.readline_stdin (call-kind, name=readline).
    $raw = readline("cmd: ") ?: "";
    $user = $_SERVER['USER'] ?? "anon";

    $envelope = [
        'kind' => 'run',
        'cmd' => "{$raw}",
        'user' => $user,
        'length' => strlen($raw ?? ''),
        'extras' => [$raw],
    ];

    return Pipeline::orchestrate($envelope);
}

echo handle_request();
