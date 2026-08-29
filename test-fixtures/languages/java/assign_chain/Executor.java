import java.io.IOException;

public class Executor {
    public static void runInOtherFile(String cmd) throws IOException {
        // POSITIVE (cross-file)
        Runtime.getRuntime().exec(cmd);
    }
}
