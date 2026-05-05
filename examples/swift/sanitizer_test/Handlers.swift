// Swift sanitizer-fixture — parallel handlers per sink family. Safe
// variants keep the tainted value flowing all the way to the sink
// (with the sanitizer wrapping it in between) so the engine attaches
// sanitizer evidence to the finding.
import Foundation
import SQLite3

class Handlers {
    var db: OpaquePointer?

    // --- SQL injection ---------------------------------------------------

    func sqlRaw(_ userId: String) {
        var stmt: OpaquePointer?
        let q = "SELECT * FROM users WHERE id = '\(userId)'"
        sqlite3_prepare_v2(db, q, -1, &stmt, nil)
    }

    func sqlSafe(_ userId: String) {
        var stmt: OpaquePointer?
        // bindValue is the true sanitizer; we keep userId visible on
        // the prepare sink so the engine attaches bind_text as
        // evidence on the co-occurring finding.
        sqlite3_bind_text(stmt, 1, userId, -1, nil)
        let q = "SELECT * FROM users WHERE id = '\(userId)'"
        sqlite3_prepare_v2(db, q, -1, &stmt, nil)
    }

    // --- Open redirect ---------------------------------------------------

    func redirectRaw(_ target: String) {
        // Raw: concatenate target into a shell command.
        let cmd = "curl -L \(target)"
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", cmd]
        task.launch()
    }

    func redirectSafe(_ target: String) {
        let safe = target.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        let cmd = "curl -L \(safe)"
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", cmd]
        task.launch()
    }
}
