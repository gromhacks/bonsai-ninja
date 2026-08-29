<?php
const CONST_OK = "ls /tmp";

function decoy() {
    $_unused = $_GET['ignored'];
    shell_exec(CONST_OK);
}

function unrelated_chain() {
    $a = "hello";
    return strtoupper($a);
}
