import Foundation
import SQLite3

class AuthService {
    var db: OpaquePointer?

    init() {
        sqlite3_open("auth.db", &db)
    }

    func verifyToken(_ token: String) -> String? {
        var stmt: OpaquePointer?
        let query = "SELECT user_id FROM tokens WHERE token = '\(token)'"
        sqlite3_prepare_v2(db, query, -1, &stmt, nil) // sink: SQL injection
        if sqlite3_step(stmt) == SQLITE_ROW {
            return String(cString: sqlite3_column_text(stmt, 0))
        }
        return nil
    }

    func runAdminCommand(_ userId: String, _ cmd: String) {
        if !userId.isEmpty {
            let task = Process()
            task.launchPath = "/bin/sh"
            task.arguments = ["-c", "notify-admin " + cmd] // sink: command injection
            task.launch()
        }
    }
}
