import java.io.IOException;

public class Executor {
    public static void execute(String cmd) throws IOException {
        // POSITIVE (terminal cross-file sink)
        Runtime.getRuntime().exec(cmd);
    }
}
