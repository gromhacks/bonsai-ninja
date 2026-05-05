<?php
class Executor {
    // SINK — shell_exec · php.cmdi.shell_exec · CWE-78
    public static function execute(string $cmd): string {
        shell_exec($cmd);
        return $cmd;
    }

    public static function cleanTwin(): string {
        // NEGATIVE — same sink kind with a constant argument must not report.
        shell_exec('echo clean');
        return 'clean';
    }
}
