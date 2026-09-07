// Swift sanitizer-fixture — parallel handlers per sink family. Historical
// "safe" names do not establish safety: URL encoding remains a transform
// on shell-command paths, and an unrelated bind does not protect SQL text.
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
        // This bind is not used by the interpolated query below. Mere
        // co-occurrence must not give that query sanitizer credit.
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
