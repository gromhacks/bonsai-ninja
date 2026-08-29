package gauntlet.domain;

import java.util.List;

public record Envelope(Kind kind, String cmd, String user, int length, List<String> extras) {
    public enum Kind { RUN, EVAL }

    public static Envelope fromRequest(String cmd, String user) {
        return new Envelope(Kind.RUN, cmd, user, cmd.length(), List.of(cmd));
    }
}
