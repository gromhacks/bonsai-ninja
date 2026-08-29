package gauntlet.entry;

import gauntlet.domain.Envelope;
import gauntlet.pipeline.Pipeline;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

public final class App {
    public String handle(HttpServletRequest request) {
        // SOURCE -- servlet request parameter.
        String raw = request.getParameter("cmd");
        String user = Optional.ofNullable(request.getHeader("X-User")).orElse("anon");
        var envelope = Envelope.fromRequest(raw == null ? "" : raw, user);
        return Pipeline.orchestrate(envelope);
    }
}
