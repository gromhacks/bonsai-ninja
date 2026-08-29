<?php

function verify_token($token) {
    $conn = new mysqli("localhost", "root", "", "auth");
    $query = "SELECT user_id FROM tokens WHERE token = '" . $token . "'";
    $result = $conn->query($query); // sink: SQL injection
    if ($row = $result->fetch_assoc()) {
        return $row['user_id'];
    }
    $conn->close();
    return null;
}

function run_admin_command($user_id, $cmd) {
    if ($user_id !== null) {
        exec("notify-admin " . $cmd); // sink: command injection
    }
}
