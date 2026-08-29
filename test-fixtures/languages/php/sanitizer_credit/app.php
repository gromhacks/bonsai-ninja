<?php
function unsanitized() {
    $t = $_GET['cmd'];
    shell_exec($t);
}

function sanitized() {
    $t = $_GET['cmd'];
    $safe = escapeshellarg($t);
    shell_exec($safe);
}
