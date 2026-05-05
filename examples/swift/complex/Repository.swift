import Foundation

// Health Records API - Data Access Layer
// Terminal sinks: sqlite3_exec, NSPredicate, String(contentsOfFile:),
// FileManager, NSKeyedUnarchiver, XMLParser, fetchAll (GRDB), find (Mongo)

class HealthRepository {
    let dbPath: String
    var db: OpaquePointer?

    init(dbPath: String) {
        self.dbPath = dbPath
    }

    // SINK: SQL injection via findByFilter -> executeRawQuery -> sqlite3_exec
    func findByFilter(sql: String) -> [[String: Any]] {
        return executeRawQuery(sql: sql)
    }

    // Safe version with parameterized query
    func findByFilterSafe(query: String, sortBy: String) -> [[String: Any]] {
        let allowedSorts: Set<String> = ["date", "name", "type", "created_at"]
        let safeSortBy = allowedSorts.contains(sortBy) ? sortBy : "date"
        let sql = "SELECT * FROM health_records WHERE name LIKE ? ORDER BY \(safeSortBy)"
        return executeParameterized(sql: sql, params: ["%\(query)%"])
    }

    func findById(id: String) -> [String: Any]? {
        let results = executeParameterized(sql: "SELECT * FROM health_records WHERE id = ?", params: [id])
        return results.first
    }

    func create(data: Any) -> [String: Any] {
        return ["status": "created", "data": data]
    }

    func getHistory(patientId: String) -> [[String: Any]] {
        return executeParameterized(
            sql: "SELECT * FROM health_records WHERE patient_id = ? ORDER BY created_at DESC",
            params: [patientId]
        )
    }

    func getAllRecords() -> [[String: Any]] {
        return executeRawQuery(sql: "SELECT * FROM health_records")
    }

    // SINK: sqlite3_exec - raw SQL execution (terminal sink for SQL injection chains)
    func executeRawQuery(sql: String) -> [[String: Any]] {
        var results: [[String: Any]] = []
        var errMsg: UnsafeMutablePointer<CChar>?
        sqlite3_exec(db, sql, nil, nil, &errMsg)
        return results
    }

    // Safe: parameterized query
    func executeParameterized(sql: String, params: [String]) -> [[String: Any]] {
        var results: [[String: Any]] = []
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        for (index, param) in params.enumerated() {
            sqlite3_bind_text(stmt, Int32(index + 1), param, -1, nil)
        }
        return results
    }

    // SINK: NSPredicate injection
    func findWithPredicate(format: String) -> [[String: Any]] {
        let predicate = NSPredicate(format: format)
        print("Predicate: \(predicate)")
        return []
    }

    // Safe version
    func findWithPredicateSafe(name: String) -> [[String: Any]] {
        let predicate = NSPredicate(format: "name CONTAINS[cd] %@", argumentArray: [name])
        print("Predicate: \(predicate)")
        return []
    }

    // SINK: Path traversal via String(contentsOfFile:)
    func readFile(path: String) -> String {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return "File not found"
        }
        return content
    }

    // SINK: Path traversal via CSV export
    func exportToCsv(data: String, outputPath: String) -> String {
        let fullPath = "/var/health/exports/\(outputPath)"
        guard let content = try? String(contentsOfFile: fullPath, encoding: .utf8) else {
            return "Export failed"
        }
        return content
    }

    // SINK: Deserialization via NSKeyedUnarchiver
    func deserializeRecord(payload: String) -> String {
        guard let data = payload.data(using: .utf8) else { return "Invalid" }
        let unarchiver = NSKeyedUnarchiver(forReadingFrom: data)
        let obj = unarchiver?.decodeObject(forKey: "record")
        return "\(obj ?? "nil")"
    }

    // SINK: XXE via XMLParser
    func parseXmlDocument(xmlString: String) -> String {
        guard let data = xmlString.data(using: .utf8) else { return "Invalid XML" }
        let parser = XMLParser(data: data)
        parser.parse()
        return "Parsed XML document"
    }

    // SINK: NoSQL injection via MongoKitten find()
    func queryMongo(filter: String) -> [[String: Any]] {
        // MongoKitten-style query with user-controlled filter
        let collection = getMongoCollection()
        let results = collection.find(filter)
        return results
    }

    func getMongoCollection() -> MongoCollection {
        return MongoCollection()
    }

    // SINK: Path traversal via FileManager.contentsOfDirectory
    func listDirectory(path: String) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: path) else {
            return []
        }
        return items
    }

    // SINK: SQL injection via GRDB fetchAll
    func grdbFetchAll(sql: String) -> [[String: Any]] {
        let results = Row.fetchAll(db, sql: sql)
        return results
    }

    // SINK: Path traversal via FileManager.createFile
    func writeExportFile(path: String, content: String) -> Bool {
        let fm = FileManager.default
        return fm.createFile(atPath: path, contents: content.data(using: .utf8), attributes: nil)
    }

    // SINK: Path traversal via FileManager.removeItem
    func deleteExportFile(path: String) -> Bool {
        let fm = FileManager.default
        try? fm.removeItem(atPath: path)
        return true
    }

    // SINK: SQL injection via report query
    func getReportData(reportType: String, dateRange: String) -> [[String: Any]] {
        let sql = "SELECT * FROM health_records WHERE type = '\(reportType)' AND created_at > '\(dateRange)'"
        return executeRawQuery(sql: sql)
    }

    func getStats() -> [String: Any] {
        let results = executeRawQuery(sql: "SELECT COUNT(*) as count FROM health_records")
        return ["totalRecords": results.first?["count"] ?? 0]
    }
}

// Stub types for pattern matching
class MongoCollection {
    func find(_ filter: String) -> [[String: Any]] {
        return []
    }
}

class Row {
    static func fetchAll(_ db: OpaquePointer?, sql: String) -> [[String: Any]] {
        return []
    }
}
