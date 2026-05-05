import Foundation

typealias RepoEnvelope = Envelope

// Protocol + class hierarchy — inheritance, override, computed
// properties, static factory — all preserving taint on the way to
// the sink.
protocol Runnable {
    func run() -> String
}

class Repository: Runnable {
    let data: RepoEnvelope
    init(_ data: RepoEnvelope) { self.data = data }

    // Computed property exposes the tainted cmd field.
    var cmd: String { data.cmd }

    static func wrap(_ data: RepoEnvelope) -> Repository {
        return Repository(data)
    }

    func run() -> String {
        let c = cmd
        return Executor.execute(c)
    }
}

class AuditedRepository: Repository {
    override func run() -> String {
        // super-call preserves taint across the inheritance chain.
        return super.run()
    }
}

enum Storage {
    static func persist(_ envelope: RepoEnvelope) -> String {
        let repo = AuditedRepository(envelope)
        return repo.run()
    }
}
