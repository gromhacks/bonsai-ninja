import java.io.*;
import java.util.*;

/**
 * Deep cross-file flow chain: Plugin executor (contains dangerous sinks).
 *
 * Receives processed command strings and executes them via Runtime.exec().
 * The taint chain terminates here.
 *
 * Contains: DfcPluginExecutor, DfcExecutionConfig, DfcCommandRunner
 */

/**
 * DfcPluginExecutor executes plugin commands after final preparation.
 */
class DfcPluginExecutor {
    private String handlerName;
    private DfcExecutionConfig config;

    // Step 25 (from caller): store handler name
    public DfcPluginExecutor(String handlerName) {
        this.handlerName = handlerName;
        this.config = new DfcExecutionConfig();
    }

    public String prepareAndRun(String execString, Map<String, String> metadata) {
        // Step 27: build the shell prefix
        String shellPrefix = this.config.getPrefix();
        // Step 28: combine handler name into command
        String handlerCmd = this.handlerName + " " + execString;
        // Step 29: apply metadata-based transformations
        if ("true".equals(metadata.get("transformed"))) {
            handlerCmd = handlerCmd + " --transformed";
        }
        // Step 30: wrap in shell invocation
        String fullShellCmd = shellPrefix + " -c '" + handlerCmd + "'";
        // Step 31: pass to the runner
        DfcCommandRunner runner = new DfcCommandRunner();
        String result = runner.execute(fullShellCmd);
        return result;
    }

    public List<String> prepareBatch(List<String> commands, Map<String, String> metadata) {
        List<String> results = new ArrayList<>();
        for (String cmd : commands) {
            String combined = this.handlerName + " " + cmd;
            if ("cli".equals(metadata.get("origin"))) {
                combined = combined + " --interactive";
            }
            DfcCommandRunner runner = new DfcCommandRunner();
            String res = runner.execute(combined);
            results.add(res);
        }
        return results;
    }
}

/**
 * DfcExecutionConfig holds configuration for the execution environment.
 */
class DfcExecutionConfig {
    private String shell;
    private int timeout;
    private Map<String, String> envVars;

    public DfcExecutionConfig() {
        this.shell = "/bin/bash";
        this.timeout = 30;
        this.envVars = new HashMap<>();
    }

    // Step 27: returns the shell path used as command prefix
    public String getPrefix() {
        String prefix = this.shell;
        return prefix;
    }

    public void setTimeout(int seconds) {
        this.timeout = seconds;
    }
}

/**
 * DfcCommandRunner actually runs shell commands (contains the SINK).
 */
class DfcCommandRunner {
    private int lastExitCode;
    private String lastOutput;

    public DfcCommandRunner() {
        this.lastExitCode = 0;
        this.lastOutput = "";
    }

    public String execute(String commandString) {
        // Step 32: log the command
        String logEntry = "Executing: " + commandString;
        System.out.println(logEntry);
        // Step 33: format for execution
        String formatted = commandString.trim();
        // Step 34: final variable before sink
        String finalCmd = formatted;
        try {
            // Step 35: SINK -- tainted data reaches Runtime.exec()
            Process process = Runtime.getRuntime().exec(finalCmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            this.lastExitCode = process.waitFor();
            this.lastOutput = output.toString();
        } catch (Exception e) {
            this.lastExitCode = 1;
            this.lastOutput = "error: " + e.getMessage();
        }
        return this.lastOutput;
    }
}
