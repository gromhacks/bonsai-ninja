import org.apache.commons.text.StringEscapeUtils;

public class App {
    public void unsanitized() throws Exception {
        String t = System.getenv("CMD");
        Runtime.getRuntime().exec(t);
    }

    public void sanitized() throws Exception {
        String t = System.getenv("CMD");
        String safe = StringEscapeUtils.escapeJava(t);
        Runtime.getRuntime().exec(safe);
    }
}
