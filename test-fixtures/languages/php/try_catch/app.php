<?php
function tainted_through_try() {
    try {
        $t = $_GET['cmd'];
    } catch (Exception $e) {
        $t = "";
    }
    shell_exec($t);
}
