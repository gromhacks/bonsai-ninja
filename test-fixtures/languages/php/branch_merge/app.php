<?php
function taint_one_leg($cond) {
    if ($cond) { $x = $_GET['cmd']; }
    else { $x = "safe-static"; }
    shell_exec($x);
}

function taint_overwritten($cond) {
    $x = $_GET['cmd'];
    if ($cond) { $x = "clean-then"; }
    else { $x = "clean-else"; }
    shell_exec($x);
}
