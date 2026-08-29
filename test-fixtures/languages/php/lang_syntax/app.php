<?php
// Language-specific syntax audit (PHP).
// Tests PHP-special forms:
//   - include $tainted — language construct (parses as
//     include_expression in tree-sitter, not a call)
//   - require_once $tainted — same
//   - backtick `cmd` — runs shell

function handle_include() {
    // POSITIVE
    $tainted = $_GET['file'];
    include $tainted;
}

function handle_require_once() {
    // POSITIVE
    $tainted = $_GET['file'];
    require_once $tainted;
}

function handle_backtick() {
    // POSITIVE: backtick shell.
    $tainted = $_GET['cmd'];
    $out = `ping -c 1 $tainted`;
    return $out;
}
