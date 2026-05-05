/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
import java.sql.*;
import java.util.*;

public class CompilerTests {

    // -----------------------------------------------------------------------
    // 1. BRANCH-AWARE KILL ANALYSIS
    // -----------------------------------------------------------------------

    // [NO FLOW EXPECTED] Both branches sanitize
    public void branchKillBothPaths(String userInput) throws Exception {
        String cmd;
        if (userInput.length() > 100) {
            cmd = "default_command";
        } else {
            cmd = "safe_fallback";
        }
        Runtime.getRuntime().exec(cmd); // safe
    }

    // [FLOW EXPECTED] Only one branch kills taint
    public void branchKillOnePath(String userInput) throws Exception {
        String cmd = userInput;
        if (cmd.length() > 100) {
            cmd = "truncated";
        }
        Runtime.getRuntime().exec(cmd); // tainted: else path preserves
    }

    // -----------------------------------------------------------------------
    // 2. INTERPROCEDURAL KILL (2+ levels deep)
    // -----------------------------------------------------------------------

    private String sanitize(String value) {
        return value.replaceAll("['\";\\-\\-]", "");
    }

    private String wrapSanitize(String value) {
        return sanitize(value);
    }

    // [NO FLOW EXPECTED] Sanitizer applied
    public void interproceduralKillDirect(String userInput) throws Exception {
        String clean = sanitize(userInput);
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        conn.createStatement().execute("SELECT * FROM t WHERE x = '" + clean + "'");
    }

    // [NO FLOW EXPECTED] Sanitizer 2 levels deep
    public void interproceduralKillTwoLevels(String userInput) throws Exception {
        String clean = wrapSanitize(userInput);
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        conn.createStatement().execute("SELECT * FROM t WHERE x = '" + clean + "'");
    }

    // [FLOW EXPECTED] No sanitizer
    public void interproceduralNoKill(String userInput) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        conn.createStatement().execute("SELECT * FROM t WHERE x = '" + userInput + "'");
    }

    // -----------------------------------------------------------------------
    // 3. FIELD-SENSITIVE TRACKING
    // -----------------------------------------------------------------------

    static class Config {
        String command = "";
        String label = "";
    }

    // [FLOW EXPECTED] Tainted field flows to sink
    public void fieldSensitiveTainted(String userInput) throws Exception {
        Config cfg = new Config();
        cfg.command = userInput;
        cfg.label = "safe_label";
        Runtime.getRuntime().exec(cfg.command);
    }

    // [NO FLOW EXPECTED] Only safe field used
    public void fieldSensitiveSafe(String userInput) throws Exception {
        Config cfg = new Config();
        cfg.command = userInput;
        cfg.label = "safe_label";
        Runtime.getRuntime().exec(cfg.label);
    }

    // [NO FLOW EXPECTED] Tainted field overwritten
    public void fieldSensitiveOverwrite(String userInput) throws Exception {
        Config cfg = new Config();
        cfg.command = userInput;
        cfg.command = "hardcoded_safe";
        Runtime.getRuntime().exec(cfg.command);
    }

    // -----------------------------------------------------------------------
    // 4. EXCEPTION CHAIN TAINT
    // -----------------------------------------------------------------------

    // [FLOW EXPECTED] Taint flows through exception message
    public void exceptionTaint(String userInput) throws Exception {
        try {
            throw new RuntimeException("Invalid: " + userInput);
        } catch (RuntimeException e) {
            Runtime.getRuntime().exec(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // 5. CONTAINER ELEMENT PRECISION
    // -----------------------------------------------------------------------

    // [FLOW EXPECTED] Tainted element added to list
    public void containerAppendTainted(String userInput) throws Exception {
        List<String> parts = new ArrayList<>();
        parts.add(userInput);
        String query = String.join(" ", parts);
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        conn.createStatement().execute(query);
    }

    // -----------------------------------------------------------------------
    // 6. TYPE-TRACKED CALL RESOLUTION
    // -----------------------------------------------------------------------

    interface Executor {
        void execute(String cmd) throws Exception;
    }

    static class SafeExecutor implements Executor {
        public void execute(String cmd) {
            System.out.println("Would execute: " + cmd);
        }
    }

    static class UnsafeExecutor implements Executor {
        public void execute(String cmd) throws Exception {
            Runtime.getRuntime().exec(cmd);
        }
    }

    // [FLOW EXPECTED]
    public void typeTrackedUnsafe(String userInput) throws Exception {
        Executor executor = new UnsafeExecutor();
        executor.execute(userInput);
    }

    // [NO FLOW EXPECTED]
    public void typeTrackedSafe(String userInput) throws Exception {
        Executor executor = new SafeExecutor();
        executor.execute(userInput);
    }

    // -----------------------------------------------------------------------
    // 7. PARAMETER SOURCE SYNTHESIS
    // -----------------------------------------------------------------------

    // [FLOW EXPECTED] External entry point
    public void handleWebhook(String payload, String signature) throws Exception {
        Runtime.getRuntime().exec("process " + payload);
    }

    // -----------------------------------------------------------------------
    // 8. CROSS-METHOD CLASS FIELD TAINT
    // -----------------------------------------------------------------------

    static class Pipeline {
        private String data = "";

        void ingest(String raw) {
            this.data = raw;
        }

        void process() throws Exception {
            Runtime.getRuntime().exec(this.data);
        }
    }

    // [FLOW EXPECTED]
    public void crossMethodFieldTaint(String userInput) throws Exception {
        Pipeline p = new Pipeline();
        p.ingest(userInput);
        p.process();
    }

    // -----------------------------------------------------------------------
    // 9. STREAM API TAINT
    // -----------------------------------------------------------------------

    // [FLOW EXPECTED] Taint flows through stream operations
    public void streamTaint(String userInput) throws Exception {
        List<String> inputs = Arrays.asList(userInput, "safe");
        String result = inputs.stream()
            .filter(s -> s.length() > 0)
            .reduce("", (a, b) -> a + " " + b);
        Runtime.getRuntime().exec(result);
    }
}
