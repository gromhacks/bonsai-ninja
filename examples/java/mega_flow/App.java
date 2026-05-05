package mega;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

// mega_flow Java entry — reads a servlet parameter, then dispatches
// the tainted value through a pipeline that exercises every idiomatic
// Java flow construct (Optional, streams, lambdas, records, enhanced
// switch, try-with-resources, var, generics).
public class App {
    public enum Kind { RUN, EVAL }

    // SOURCE — HttpServletRequest.getParameter (jakarta).
    public String handle(HttpServletRequest req) {
        String raw = req.getParameter("cmd");
        String user = Optional.ofNullable(req.getHeader("X-User")).orElse("anon");

        // var + record literal — taint rides the envelope.
        var envelope = new Envelope(Kind.RUN, raw == null ? "" : raw, user, raw == null ? 0 : raw.length());

        return Pipeline.orchestrate(envelope);
    }

    // Record — Java 16+ value type carrying the tainted cmd.
    public record Envelope(Kind kind, String cmd, String user, int length) {}
}
