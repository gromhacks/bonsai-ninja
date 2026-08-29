<?php
// Cross-file sink target for the assign_chain fixture.
function run_in_other_file($cmd) {
    // POSITIVE (cross-file): caller passes tainted value; sink consumes.
    shell_exec($cmd);
}
