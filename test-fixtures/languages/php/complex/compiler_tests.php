<?php
/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

// [NO FLOW EXPECTED] Both branches sanitize
function branch_kill_both_paths(string $user_input): void {
    if (strlen($user_input) > 100) {
        $cmd = "default_command";
    } else {
        $cmd = "safe_fallback";
    }
    system($cmd); // safe: both paths overwrite
}

// [FLOW EXPECTED] Only one branch kills taint
function branch_kill_one_path(string $user_input): void {
    $cmd = $user_input;
    if (strlen($cmd) > 100) {
        $cmd = "truncated";
    }
    // else: $cmd still holds $user_input
    system($cmd); // tainted
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

function sanitize_input(string $value): string {
    return str_replace(["'", ";", "--"], "", $value);
}

function wrap_sanitize(string $value): string {
    return sanitize_input($value);
}

// [NO FLOW EXPECTED] Sanitizer applied
function interprocedural_kill_direct(string $user_input): void {
    $clean = sanitize_input($user_input);
    $conn = new mysqli("localhost", "root", "", "test");
    $conn->query("SELECT * FROM t WHERE x = '$clean'");
}

// [NO FLOW EXPECTED] Sanitizer 2 levels deep
function interprocedural_kill_two_levels(string $user_input): void {
    $clean = wrap_sanitize($user_input);
    $conn = new mysqli("localhost", "root", "", "test");
    $conn->query("SELECT * FROM t WHERE x = '$clean'");
}

// [FLOW EXPECTED] No sanitizer
function interprocedural_no_kill(string $user_input): void {
    $conn = new mysqli("localhost", "root", "", "test");
    $conn->query("SELECT * FROM t WHERE x = '$user_input'");
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

class Config {
    public string $command = "";
    public string $label = "";
}

// [FLOW EXPECTED] Tainted field flows to sink
function field_sensitive_tainted(string $user_input): void {
    $cfg = new Config();
    $cfg->command = $user_input;
    $cfg->label = "safe_label";
    system($cfg->command); // tainted
}

// [NO FLOW EXPECTED] Only safe field used
function field_sensitive_safe(string $user_input): void {
    $cfg = new Config();
    $cfg->command = $user_input;
    $cfg->label = "safe_label";
    system($cfg->label); // safe
}

// [NO FLOW EXPECTED] Tainted field overwritten
function field_sensitive_overwrite(string $user_input): void {
    $cfg = new Config();
    $cfg->command = $user_input;
    $cfg->command = "hardcoded_safe";
    system($cfg->command); // safe: overwritten
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through exception message
function exception_taint(string $user_input): void {
    try {
        throw new RuntimeException("Invalid: " . $user_input);
    } catch (RuntimeException $e) {
        system($e->getMessage()); // tainted
    }
}


// ---------------------------------------------------------------------------
// 5. SUPERGLOBAL SOURCE (PHP-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] $_GET is a taint source
function superglobal_source(): void {
    $name = $_GET['name'];
    system("echo $name"); // tainted
}

// [FLOW EXPECTED] $_POST source
function post_source(): void {
    $cmd = $_POST['command'];
    system($cmd); // tainted
}


// ---------------------------------------------------------------------------
// 6. FOREACH REFERENCE WRITE-BACK (PHP-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Reference write-back taints array
function foreach_ref_writeback(string $user_input): void {
    $items = ["a", "b", "c"];
    foreach ($items as &$val) {
        $val = $user_input;
    }
    system($items[0]); // tainted: write-back modified array
}


// ---------------------------------------------------------------------------
// 7. TYPE-TRACKED CALL RESOLUTION
// ---------------------------------------------------------------------------

interface Executor {
    public function execute(string $cmd): void;
}

class SafeExecutor implements Executor {
    public function execute(string $cmd): void {
        echo "Would execute: $cmd\n"; // safe
    }
}

class UnsafeExecutor implements Executor {
    public function execute(string $cmd): void {
        system($cmd); // dangerous
    }
}

// [FLOW EXPECTED]
function type_tracked_unsafe(string $user_input): void {
    $executor = new UnsafeExecutor();
    $executor->execute($user_input);
}

// [NO FLOW EXPECTED]
function type_tracked_safe(string $user_input): void {
    $executor = new SafeExecutor();
    $executor->execute($user_input);
}


// ---------------------------------------------------------------------------
// 8. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] External entry point
function handle_webhook(string $payload, string $signature): void {
    system("process $payload");
}


// ---------------------------------------------------------------------------
// 9. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    private string $data = "";

    public function ingest(string $raw): void {
        $this->data = $raw;
    }

    public function process(): void {
        system($this->data); // tainted if ingest() called with tainted input
    }
}

// [FLOW EXPECTED]
function cross_method_field_taint(string $user_input): void {
    $p = new Pipeline();
    $p->ingest($user_input);
    $p->process();
}


// ---------------------------------------------------------------------------
// 10. MATCH EXPRESSION (PHP 8)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through match expression
function match_expression_taint(string $user_input): void {
    $action = match($user_input[0]) {
        'r' => "read $user_input",
        'w' => "write $user_input",
        default => $user_input,
    };
    system($action); // tainted in all branches
}


// ---------------------------------------------------------------------------
// 11. STRING INTERPOLATION
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Complex interpolation
function string_interpolation_taint(string $user_input): void {
    $query = "SELECT * FROM users WHERE name = '{$user_input}'";
    $conn = new mysqli("localhost", "root", "", "test");
    $conn->query($query); // tainted
}


// ---------------------------------------------------------------------------
// 12. CONTAINER APPEND
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through array_push
function container_append_tainted(string $user_input): void {
    $parts = [];
    array_push($parts, $user_input);
    $query = implode(" ", $parts);
    $conn = new mysqli("localhost", "root", "", "test");
    $conn->query($query);
}
