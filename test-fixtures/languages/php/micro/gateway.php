<?php

require_once __DIR__ . '/user_service.php';

function handle_request() {
    $token = $_GET['token'];    // source: user input
    $action = $_GET['action'];  // source: user input

    $user = get_user($token);         // flows to SQL injection
    $result = update_user($token, $action); // flows to command injection

    header('Content-Type: application/json');
    echo json_encode(['user' => $user, 'result' => $result]);
}

handle_request();
