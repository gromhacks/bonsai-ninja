import Foundation

// mega_flow Swift entry — reads one tainted stdin line, then dispatches
// through a pipeline that exercises every idiomatic Swift flow construct
// (enums with associated values, optionals, guard/if-let, switch, closures,
// trailing closures, generics, protocols, structs + classes).

enum Kind {
    case run
    case eval
}

struct Envelope {
    var kind: Kind
    var cmd: String
    var user: String
    var length: Int
    var extras: [String]
}

func handle_request() {
    // SOURCE — readLine() reads one tainted stdin line.
    let raw = readLine() ?? ""
    let user = ProcessInfo.processInfo.environment["USER"] ?? "anon"

    let envelope = Envelope(
        kind: .run,
        cmd: "\(raw)",
        user: user,
        length: raw.count,
        extras: [raw])

    _ = Pipeline.orchestrate(envelope)
}

@main
enum MegaFlowApp {
    static func main() {
        handle_request()
    }
}
