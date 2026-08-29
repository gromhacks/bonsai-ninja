import java.util.function.Consumer;

public class App {
    public static void executor(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    public static void run(Consumer<String> cb, String value) {
        cb.accept(value);
    }

    public void passToCallback() throws Exception {
        String t = System.getenv("CMD");
        run(App::executor, t);
    }
}
