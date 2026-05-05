<?php

require_once __DIR__ . '/auth_service.php';

function get_user($token) {
    $user_id = verify_token($token);
    return ['id' => $user_id, 'token' => $token];
}

function update_user($token, $action) {
    $user_id = verify_token($token);
    if ($user_id !== null) {
        run_admin_command($user_id, $action);
    }
    return $user_id;
}
