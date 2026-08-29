package gauntlet.runtime;

public final class Executor {
    private Executor() {}

    public static String execute(String cmd) {
        try {
            // SINK -- Runtime.exec / CWE-78.
            Runtime.getRuntime().exec(cmd);
        } catch (Exception ignored) {
        }
        return cmd;
    }

    public static String cleanTwin() {
        try {
            // NEGATIVE -- the constant argument must remain untainted.
            Runtime.getRuntime().exec("echo clean");
        } catch (Exception ignored) {
        }
        return "clean";
    }
}
