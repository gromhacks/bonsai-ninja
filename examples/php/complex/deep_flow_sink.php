<?php
/* deep_flow_sink.php -- Final stage: format and execute the command.
 * Tainted user input from $_GET reaches exec()/shell_exec() after
 * flowing through the full pipeline. All types prefixed with Dfc.
 */

/* Steps 26-29: DfcCommandFormatter -- wraps command for shell execution */
class DfcCommandFormatter {
    /* Step 26: Add timeout wrapper */
    private function addTimeout(DfcExecutionContext $ctx): void {
        $ctx->formatted_command = 'timeout ' . $ctx->timeout_sec . ' ' .
                                  $ctx->formatted_command;
    }

    /* Step 27: Add directory change prefix */
    private function addDirectoryPrefix(DfcExecutionContext $ctx): void {
        $ctx->formatted_command = 'cd ' . $ctx->working_dir . ' && ' .
                                  $ctx->formatted_command;
    }

    /* Step 28: Escape for shell (incomplete -- does not handle all cases) */
    private function shellEscape(string $cmd): string {
        $escaped = str_replace('"', '\\"', $cmd);
        return $escaped;
    }

    /* Step 29: Wrap in shell invocation */
    private function addShellWrapper(DfcExecutionContext $ctx): void {
        $escaped = $this->shellEscape($ctx->formatted_command);
        $ctx->formatted_command = '/bin/sh -c "' . $escaped . '"';
    }

    public function format(DfcExecutionContext $ctx): bool {
        if (empty($ctx->formatted_command)) {
            return false;
        }
        $this->addTimeout($ctx);
        $this->addDirectoryPrefix($ctx);
        $this->addShellWrapper($ctx);
        return true;
    }
}

/* Steps 30-32: DfcPipelineExecutor -- runs the command */
class DfcPipelineExecutor {
    /* Step 30: Execute with exec() and capture output */
    private function executeCaptured(string $command): int {
        $output = [];
        $return_code = 0;
        /* SINK: tainted data reaches exec() */
        exec($command, $output, $return_code);
        foreach ($output as $line) {
            echo "[OUTPUT] " . $line . "\n";
        }
        return $return_code;
    }

    /* Step 31: Execute with shell_exec() as fallback */
    private function executeDirect(string $command): string|false {
        /* SINK: tainted data reaches shell_exec() */
        $result = shell_exec($command);
        return $result;
    }

    /* Step 32: Try captured, fall back to direct */
    public function execute(DfcExecutionContext $ctx): int {
        if ($ctx->dry_run) {
            echo "[DRY RUN] Would execute: " . $ctx->formatted_command . "\n";
            return 0;
        }

        echo "[EXEC] Running: " . $ctx->formatted_command . "\n";

        $result = $this->executeCaptured($ctx->formatted_command);
        if ($result !== 0) {
            error_log("[WARN] Captured execution failed, trying direct");
            $direct_output = $this->executeDirect($ctx->formatted_command);
            if ($direct_output !== false) {
                echo "[OUTPUT] " . $direct_output;
                return 0;
            }
            return 1;
        }

        return $result;
    }
}
