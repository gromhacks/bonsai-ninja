<?php
// Cross-file argument flow audit fixture (PHP).
require_once __DIR__ . '/pipeline.php';

function handler() {
    // POSITIVE
    $user = $_GET['cmd'];
    run_pipeline($user);
}

function handler_split() {
    // POSITIVE
    $user = $_GET['from'];
    $flag = $_GET['flag'];
    run_pipeline($user . ':' . $flag);
}
