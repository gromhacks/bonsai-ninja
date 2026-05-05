import Foundation

// Health Records API - Service Layer
// Intermediate processing between Routes and Repository
// Functions accept data from Routes and delegate to Repository/NotificationService

class HealthService {
    let repository: HealthRepository
    let notificationService: NotificationService

    init(repository: HealthRepository) {
        self.repository = repository
        self.notificationService = NotificationService()
    }

    // Chain: search() -> buildSearchSQL() -> repository.executeRawQuery() -> sqlite3_exec
    func search(query: String, sortBy: String, limit: String) -> [[String: Any]] {
        let sql = buildSearchSQL(query: query, sortBy: sortBy, limit: limit)
        return repository.findByFilter(sql: sql)
    }

    func buildSearchSQL(query: String, sortBy: String, limit: String) -> String {
        var sql = "SELECT * FROM health_records WHERE name LIKE '%\(query)%'"
        sql += " ORDER BY \(sortBy)"
        sql += " LIMIT \(limit)"
        return sql
    }

    // Safe version with parameterized query
    func searchSafe(query: String, sortBy: String) -> [[String: Any]] {
        return repository.findByFilterSafe(query: query, sortBy: sortBy)
    }

    // Chain: notifyPatient() -> notificationService.sendSMS() -> buildSMSCommand() -> execCommand() -> Process.run()
    func notifyPatient(patientId: String, phone: String, message: String) {
        let record = repository.findById(id: patientId)
        let fullMessage = "Patient \(patientId): \(message)"
        notificationService.sendSMS(phoneNumber: phone, message: fullMessage)
    }

    // Chain: searchPrescriptions() -> buildPrescriptionSQL() -> repository.executeRawQuery() -> sqlite3_exec
    func searchPrescriptions(medication: String) -> [[String: Any]] {
        let sql = buildPrescriptionSQL(medication: medication)
        return repository.executeRawQuery(sql: sql)
    }

    func buildPrescriptionSQL(medication: String) -> String {
        return "SELECT * FROM prescriptions WHERE medication LIKE '%\(medication)%'"
    }

    // Chain: findPatients() -> repository.findWithPredicate() -> NSPredicate()
    func findPatients(name: String) -> [[String: Any]] {
        let predicateFormat = "name CONTAINS[cd] '\(name)'"
        return repository.findWithPredicate(format: predicateFormat)
    }

    // Chain: exportRecord() -> repository.readFile() -> String(contentsOfFile:)
    func exportRecord(filename: String) -> String {
        let basePath = "/var/health/exports"
        let filePath = "\(basePath)/\(filename)"
        return repository.readFile(path: filePath)
    }

    // Chain: queryMetrics() -> buildMetricsSQL() -> repository.executeRawQuery() -> sqlite3_exec
    func queryMetrics(patientId: String, metricType: String, days: String) -> [[String: Any]] {
        let sql = buildMetricsSQL(patientId: patientId, metricType: metricType, days: days)
        return repository.executeRawQuery(sql: sql)
    }

    func buildMetricsSQL(patientId: String, metricType: String, days: String) -> String {
        return "SELECT * FROM metrics WHERE patient_id = '\(patientId)' AND type = '\(metricType)' AND created_at > datetime('now', '-\(days) days')"
    }

    // Chain: bulkExport() -> repository.exportToCsv() -> String(contentsOfFile:)
    func bulkExport(outputPath: String) -> String {
        let records = repository.getAllRecords()
        let csvData = formatAsCsv(records: records)
        return repository.exportToCsv(data: csvData, outputPath: outputPath)
    }

    // Chain: renderPatientReport() -> templateEngine.render() -> executeTemplate() -> loadHTMLString
    func renderPatientReport(template: String, patientId: String) -> String {
        let record = repository.findById(id: patientId)
        let context = "\(record ?? [:])"
        let engine = TemplateEngine(repository: repository)
        return engine.renderTemplate(name: template, context: context)
    }

    // Chain: importPatientData() -> repository.deserializeRecord() -> NSKeyedUnarchiver
    func importPatientData(rawPayload: String) -> String {
        let processed = preprocessImportData(payload: rawPayload)
        return repository.deserializeRecord(payload: processed)
    }

    func preprocessImportData(payload: String) -> String {
        return payload.trimmingCharacters(in: .whitespaces)
    }

    // Chain: parseHL7Message() -> repository.parseXmlDocument() -> XMLParser
    func parseHL7Message(xmlContent: String) -> String {
        let wrapped = wrapHL7Content(content: xmlContent)
        return repository.parseXmlDocument(xmlString: wrapped)
    }

    func wrapHL7Content(content: String) -> String {
        return "<HL7Message>\(content)</HL7Message>"
    }

    // Chain: searchWithNoSQL() -> repository.queryMongo() -> find()
    func searchWithNoSQL(filterExpression: String) -> [[String: Any]] {
        let mongoFilter = buildMongoFilter(expression: filterExpression)
        return repository.queryMongo(filter: mongoFilter)
    }

    func buildMongoFilter(expression: String) -> String {
        return "{\"name\": {\"$regex\": \"\(expression)\"}}"
    }

    // Chain: listExportFiles() -> repository.listDirectory() -> FileManager.contentsOfDirectory
    func listExportFiles(directory: String) -> [String] {
        let fullPath = "/var/health/exports/\(directory)"
        return repository.listDirectory(path: fullPath)
    }

    // Chain: advancedSearch() -> buildAdvancedSQL() -> repository.grdbFetchAll() -> fetchAll
    func advancedSearch(query: String, category: String) -> [[String: Any]] {
        let sql = buildAdvancedSQL(query: query, category: category)
        return repository.grdbFetchAll(sql: sql)
    }

    func buildAdvancedSQL(query: String, category: String) -> String {
        return "SELECT * FROM records WHERE category = '\(category)' AND name LIKE '%\(query)%'"
    }

    func getRecord(id: String) -> [String: Any]? {
        return repository.findById(id: id)
    }

    func createRecord(data: [String: Any]) -> [String: Any] {
        return repository.create(data: data)
    }

    func getPatientSummary(patientId: String) -> [String: Any] {
        guard let patient = repository.findById(id: patientId) else {
            return [:]
        }
        let history = repository.getHistory(patientId: patientId)
        return [
            "patient": patient,
            "historyCount": history.count,
            "recentVisits": Array(history.prefix(5))
        ]
    }

    private func formatAsCsv(records: [[String: Any]]) -> String {
        var csv = "id,name,type,date\n"
        for record in records {
            let id = record["id"] as? String ?? ""
            let name = record["name"] as? String ?? ""
            csv += "\(id),\(name)\n"
        }
        return csv
    }
}

// Notification subsystem
class NotificationService {
    // Chain: sendSMS() -> buildSMSCommand() -> execCommand() -> Process.run()
    func sendSMS(phoneNumber: String, message: String) {
        let cmd = buildSMSCommand(phone: phoneNumber, msg: message)
        execCommand(command: cmd)
    }

    func buildSMSCommand(phone: String, msg: String) -> String {
        return "sms-sender --to \(phone) --message '\(msg)'"
    }

    func execCommand(command: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
    }

    // Safe version
    func sendSMSSafe(phoneNumber: String, message: String) {
        let cleanPhone = phoneNumber.filter { $0.isNumber || $0 == "+" }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/sms-sender")
        process.arguments = ["--to", cleanPhone, "--message", message]
        try? process.run()
    }
}

// Template rendering engine used by HealthService
class TemplateEngine {
    let repository: HealthRepository

    init(repository: HealthRepository) {
        self.repository = repository
    }

    // Chain: renderTemplate() -> executeTemplate() -> loadHTMLString
    func renderTemplate(name: String, context: String) -> String {
        let templateContent = loadTemplate(name: name)
        return executeTemplate(content: templateContent, data: context)
    }

    func loadTemplate(name: String) -> String {
        let path = "/var/health/templates/\(name)"
        return (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
    }

    func executeTemplate(content: String, data: String) -> String {
        // Template injection: user-controlled template name and content
        let html = content.replacingOccurrences(of: "{{data}}", with: data)
        return html
    }
}
