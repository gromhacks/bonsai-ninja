<?php
function redirect_raw() {
    header('Location: ' . $_GET['next']);
}
function command_control() {
    system($_GET['cmd']);
}
function command_escaped() {
    system(escapeshellcmd($_GET['cmd']));
}
function sql_exec(PDO $db) {
    $db->exec($_GET['sql']);
}
function sql_query(PDO $db) {
    $db->query($_GET['sql']);
}
function allowed_tags() {
    echo strip_tags($_GET['html'], '<a>');
}
