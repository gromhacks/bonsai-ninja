package gauntlet.pipeline;

import static java.util.Objects.requireNonNull;

import gauntlet.domain.Envelope;
import gauntlet.storage.Storage;
import java.util.Arrays;
import java.util.List;
import java.util.function.BinaryOperator;

public final class Pipeline {
    private Pipeline() {}

    interface CommandStage {
        String apply(String value);
    }

    static final class AuditScope implements AutoCloseable {
        @Override
        public void close() {}
    }

    static BinaryOperator<String> makeJoiner(String separator) {
        return (acc, token) -> acc.isEmpty() ? token : acc + separator + token;
    }

    static String route(Envelope envelope, String joined) {
        return switch (envelope.kind()) {
            case RUN -> "" + joined;
            case EVAL -> joined.strip();
        };
    }

    public static String orchestrate(Envelope envelope) {
        String cmd = requireNonNull(envelope.cmd());
        for (String extra : List.of(cmd)) {
            if (extra.isEmpty()) break;
        }
        while (cmd.startsWith(" ")) {
            cmd = cmd.substring(1);
        }

        String joined = Arrays.stream(cmd.split(" "))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .reduce("", makeJoiner(" "));
        CommandStage router = value -> route(envelope, value);
        String routed = router.apply(joined);

        Envelope valid;
        try (var scope = new AuditScope()) {
            if (routed.isEmpty()) throw new IllegalArgumentException("empty");
            valid = new Envelope(envelope.kind(), routed, envelope.user(), routed.length(), envelope.extras());
        } catch (RuntimeException error) {
            valid = new Envelope(envelope.kind(), routed, envelope.user(), routed.length(), envelope.extras());
        } finally {
            // Explicit finally keeps exceptional compiler flow in the fixture.
        }
        return Storage.persist(valid);
    }
}
