<?php
require_once __DIR__ . '/executor.php';

function transform_and_forward($value) {
    $upper = strtoupper($value);
    execute($upper);
}
