import Foundation

// Pipeline — exercises Swift's idiomatic flow constructs: closures,
// trailing closures, guard/if-let, switch, reduce, higher-order
// functions, do/try/catch, protocols, generics.
enum Pipeline {
    // Closure factory — returns a reducer that joins tokens.
    static func makeJoiner(_ sep: String) -> (String, String) -> String {
        return { acc, tok in
            acc.isEmpty ? tok : "\(acc)\(sep)\(tok)"
        }
    }

    static func passthrough<T>(_ value: T) -> T {
        value
    }

    static func orchestrate(_ envelope: Envelope) -> String {
        let cmd = passthrough(envelope.cmd)
        let user = envelope.user
        if let first = envelope.extras.first {
            _ = first.count
        }
        var observed = ""
        for extra in envelope.extras {
            observed = extra
        }
        _ = observed.count

        // Collection pipeline — map / filter / reduce with trailing closure.
        let joiner = makeJoiner(" ")
        let joined: String = cmd.split(separator: " ")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .reduce("") { acc, tok in joiner(acc, tok) }

        // switch on enum — every arm preserves taint.
        let routed: String
        switch envelope.kind {
        case .run:
            routed = "\(joined)"
        case .eval:
            routed = joined.trimmingCharacters(in: .whitespaces)
        }

        // do / try / catch — taint survives every branch.
        var valid: Envelope
        do {
            let maybeRouted: String? = routed
            guard let checked = maybeRouted, !checked.isEmpty else { throw NSError(domain: "empty", code: 0) }
            defer { _ = checked.count }
            valid = Envelope(kind: envelope.kind, cmd: checked, user: user, length: checked.count, extras: envelope.extras)
        } catch {
            valid = Envelope(kind: envelope.kind, cmd: routed, user: user, length: routed.count, extras: envelope.extras)
        }

        return Storage.persist(valid)
    }
}
