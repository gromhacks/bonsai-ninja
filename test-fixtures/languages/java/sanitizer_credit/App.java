import org.apache.commons.text.StringEscapeUtils;
import javax.servlet.http.HttpServletResponse;

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

    public void encodedXss(HttpServletResponse response) throws Exception {
        String t = System.getenv("HTML");
        String safe = StringEscapeUtils.escapeHtml4(t);
        response.getWriter().write(safe);
    }
}
