<?php
require_once __DIR__ . '/transformer.php';

function run_pipeline($payload) {
    $wrapped = "[" . $payload . "]";
    transform_and_forward($wrapped);
}
