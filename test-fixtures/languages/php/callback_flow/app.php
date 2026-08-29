<?php
function executor($cmd) { shell_exec($cmd); }
function run_cb(callable $cb, $value) { $cb($value); }

function pass_to_callback() {
    $t = $_GET['cmd'];
    run_cb('executor', $t);
}
