<?php
// Receiver-type audit fixture (PHP).
// `unserialize($_GET['data'])` — class-free function call, so this
// is the simplest receiver-type case (no receiver at all). The
// existing rule fires.

function handle() {
    // POSITIVE
    $tainted = $_GET['data'];
    $obj = unserialize($tainted);
}
