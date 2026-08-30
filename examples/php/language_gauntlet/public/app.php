<?php
// language_gauntlet PHP entry — reads one tainted HTTP query value, then dispatches
// through a pipeline that exercises every idiomatic PHP flow
// construct (closures, arrow fns, match expressions, null-coalescing,
// spread, variadic, try/catch/finally, generators, traits).
require_once dirname(__DIR__) . '/src/Application/pipeline.php';

function handle_request(): string {
    // SOURCE — the request query string is remote attacker input.
    $raw = $_GET['cmd'] ?? "";
    $user = $_SERVER['REMOTE_USER'] ?? "anon";

    $envelope = [
        'kind' => 'run',
        'cmd' => "{$raw}",
        'user' => $user,
        'length' => strlen($raw ?? ''),
        'extras' => [$raw],
    ];

    return Pipeline::orchestrate($envelope);
}

// Execute the deliberately vulnerable command flow, but keep the HTTP response
// literal so this gauntlet has one intentional sink rather than also becoming
// an unrelated reflected-XSS fixture.
handle_request();
echo "ok";
