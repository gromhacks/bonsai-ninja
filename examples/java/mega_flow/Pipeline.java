package mega;

import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Pipeline — exercises Java's idiomatic flow constructs: streams /
// lambdas / method references, enhanced switch, try-with-resources,
// generics, Optional, var, functional interfaces.
public class Pipeline {
    static class AuditScope implements AutoCloseable {
        @Override
        public void close() {}
    }

    // Functional-interface factory — returns a BinaryOperator closure.
    static BinaryOperator<String> makeJoiner(String sep) {
        return (acc, tok) -> acc.isEmpty() ? tok : acc + sep + tok;
    }

    static String orchestrate(App.Envelope envelope) {
        String cmd = requireNonNull(envelope.cmd());
        String user = envelope.user();
        for (String extra : List.of(cmd)) {
            if (extra.isEmpty()) break;
        }
        while (cmd.startsWith(" ")) {
            cmd = cmd.substring(1);
        }

        // Stream pipeline — map / filter / reduce with method refs.
        String joined = Arrays.stream(cmd.split(" "))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .reduce("", makeJoiner(" "));

        // Enhanced switch (Java 14+) — every arm preserves taint.
        String routed = switch (envelope.kind()) {
            case RUN -> "" + joined;
            case EVAL -> joined.strip();
        };

        // try / catch / finally — taint survives the branch.
        App.Envelope valid;
        try (var scope = new AuditScope()) {
            if (routed.isEmpty()) throw new RuntimeException("empty");
            valid = new App.Envelope(envelope.kind(), routed, user, routed.length());
        } catch (RuntimeException e) {
            valid = new App.Envelope(envelope.kind(), routed, user, routed.length());
        } finally {
            // no-op — present so the adapter sees the finally clause.
        }

        return Storage.persist(valid);
    }
}
