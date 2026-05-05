package mega;

public class Executor {
    // SINK — Runtime.exec · java.cmdi.runtime_exec · CWE-78
    static String execute(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception ignored) {}
        return cmd;
    }

    static String cleanTwin() {
        try {
            // NEGATIVE — same sink kind with a constant argument must not report.
            Runtime.getRuntime().exec("echo clean");
        } catch (Exception ignored) {}
        return "clean";
    }
}
