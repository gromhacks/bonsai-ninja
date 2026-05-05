<?php
// Assignment-chain audit fixture (PHP).
// Each `// POSITIVE: ...` and `// NEGATIVE: ...` marks expected reports.

require_once __DIR__ . '/executor.php';

const CONST_OK = "ls /tmp";

function passthrough($x) { return $x; }
function wrap($x) { return "wrapped:" . $x; }
function combine($acc, $item) { return $acc . ":" . $item; }

class Bag {
    public string $payload = "";
}

function chain_simple() {
    // POSITIVE: simplest tmp = source(); sink(tmp).
    $tmp = $_GET['c1'];
    shell_exec($tmp);
}

function chain_multi_hop() {
    // POSITIVE: 4-hop assignment chain.
    $t1 = $_GET['c2'];
    $t2 = passthrough($t1);
    $t3 = wrap($t2);
    $t4 = passthrough($t3);
    shell_exec($t4);
}

function chain_branch_join($cond) {
    // POSITIVE: tainted leg fires; clean leg is a twin.
    if ($cond) {
        $t = $_GET['c3'];
    } else {
        $t = "safe-static";
    }
    shell_exec($t);
}

function chain_loop_carried($items) {
    // POSITIVE: accumulator carries taint across iterations.
    $acc = $_GET['c4'];
    foreach ($items as $item) {
        $acc = combine($acc, $item);
    }
    shell_exec($acc);
}

function chain_field_write() {
    // POSITIVE: object field write/read.
    $bag = new Bag();
    $bag->payload = $_GET['c5'];
    shell_exec($bag->payload);
}

function chain_subscript_write() {
    // POSITIVE: array subscript write/read.
    $cmds = [];
    $cmds["x"] = $_GET['c6'];
    shell_exec($cmds["x"]);
}

function chain_clean_constant() {
    // NEGATIVE: source value never reaches sink.
    $_unused = $_GET['ignored'];
    shell_exec(CONST_OK);
}

function chain_cross_file() {
    // POSITIVE: cross-file argument flow.
    $t = $_GET['c9'];
    run_in_other_file($t);
}
