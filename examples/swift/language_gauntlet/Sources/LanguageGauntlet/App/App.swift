import Foundation
import Vapor
import Domain
import Pipeline
import Routing

// language_gauntlet Swift entry — decodes a Vapor request query, then dispatches
// through a pipeline that exercises every idiomatic Swift flow construct
// (enums with associated values, optionals, guard/if-let, switch, closures,
// trailing closures, generics, protocols, structs + classes).

private struct RequestQuery: Content {
    let cmd: String
}

func handle_request(_ request: Request) throws {
    // SOURCE — Vapor decodes remote HTTP query data.
    let raw = try request.query.decode(RequestQuery.self).cmd
    let user = "remote"

    let envelope = Envelope(
        kind: .run,
        cmd: "\(raw)",
        user: user,
        length: raw.count,
        extras: [raw])

    _ = FlowPipeline.orchestrate(envelope)
}

@main
enum LanguageGauntletApp {
    static func main() {
        // The server runtime supplies Request to handle_request(_:).
    }
}
