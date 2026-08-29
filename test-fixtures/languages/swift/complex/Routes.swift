import Foundation

// Health Records API - Routes Controller
// Entry point for HTTP request handling with deep dispatch chains
// Sources: readLine(), CommandLine.arguments, ProcessInfo.environment

// --- Top-level helper used across modules ---
func shellExec(_ command: String) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", command]
    let pipe = Pipe()
    process.standardOutput = pipe
    try? process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

class RoutesController {
    let healthService: HealthService
    let repository: HealthRepository
    let integrationService: IntegrationService
    let securityMiddleware: SecurityMiddleware

    init(dbPath: String) {
        self.repository = HealthRepository(dbPath: dbPath)
        self.healthService = HealthService(repository: repository)
        self.integrationService = IntegrationService()
        self.securityMiddleware = SecurityMiddleware()
    }

    // VULN: SQL injection - 4 hop chain
    // readLine -> query -> healthService.search() -> buildSearchSQL() -> repository.executeRawQuery() -> sqlite3_exec
    func searchHealthRecords() {
        let query = readLine() ?? ""
        let sortBy = readLine() ?? "date"
        let limit = readLine() ?? "50"
        let results = healthService.search(query: query, sortBy: sortBy, limit: limit)
        print("Results: \(results)")
    }

    // Safe version with parameterized query
    func searchHealthRecordsSafe() {
        let query = readLine() ?? ""
        let sortBy = readLine() ?? "date"
        let results = healthService.searchSafe(query: query, sortBy: sortBy)
        print("Results: \(results)")
    }

    // VULN: SQL injection - 2 hop chain (direct)
    // readLine -> sql -> repository.executeRawQuery() -> sqlite3_exec
    func adminQuery() {
        let sql = readLine() ?? ""
        let results = repository.executeRawQuery(sql: sql)
        print("Results: \(results)")
    }

    // VULN: Command injection - 5 hop chain
    // readLine -> phone -> healthService.notifyPatient() -> notificationService.sendSMS()
    //   -> buildSMSCommand() -> execCommand() -> Process.run()
    func notifyPatient() {
        let patientId = readLine() ?? ""
        let phone = readLine() ?? ""
        let message = readLine() ?? ""
        healthService.notifyPatient(patientId: patientId, phone: phone, message: message)
        print("Notification sent")
    }

    // VULN: SSRF - 2 hop chain
    // readLine -> url -> integrationService.fetchExternalData() -> URLSession.dataTask()
    func fetchExternalRecord() {
        let url = readLine() ?? ""
        let result = integrationService.fetchExternalData(apiUrl: url)
        print("Fetched: \(result)")
    }

    // VULN: SSRF - 3 hop chain (webhook)
    // readLine -> url -> integrationService.sendWebhook() -> URLRequest() + session.dataTask()
    func sendWebhook() {
        let url = readLine() ?? ""
        let payload = readLine() ?? ""
        let result = integrationService.sendWebhook(url: url, payload: payload)
        print("Webhook result: \(result)")
    }

    // VULN: Command injection - 3 hop chain
    // readLine -> provider/bucket -> integrationService.exportToCloud() -> Process.run()
    func generateReport() {
        let reportType = readLine() ?? "summary"
        let bucket = readLine() ?? "default"
        let filePath = readLine() ?? "report.csv"
        let result = integrationService.exportToCloud(provider: reportType, bucket: bucket, filePath: filePath)
        print("Report: \(result)")
    }

    // VULN: Path traversal - 3 hop chain
    // readLine -> filename -> healthService.exportRecord() -> repository.readFile() -> String(contentsOfFile:)
    func downloadExport() {
        let filename = readLine() ?? ""
        let content = healthService.exportRecord(filename: filename)
        print("Content: \(content)")
    }

    // Safe version
    func downloadExportSafe() {
        let filename = readLine() ?? ""
        let safeName = SecurityMiddleware.sanitizeFilename(filename)
        let content = healthService.exportRecord(filename: safeName)
        print("Content: \(content)")
    }

    // VULN: SQL injection - 4 hop chain
    // readLine -> medication -> healthService.searchPrescriptions() -> buildPrescriptionSQL()
    //   -> repository.executeRawQuery() -> sqlite3_exec
    func searchPrescriptions() {
        let medication = readLine() ?? ""
        let results = healthService.searchPrescriptions(medication: medication)
        print("Prescriptions: \(results)")
    }

    // VULN: NSPredicate injection - 3 hop chain
    // readLine -> name -> healthService.findPatients() -> repository.findWithPredicate() -> NSPredicate()
    func findPatients() {
        let name = readLine() ?? ""
        let results = healthService.findPatients(name: name)
        print("Patients: \(results)")
    }

    // VULN: SSRF - 3 hop chain
    // readLine -> url -> integrationService.syncFromExternal() -> fetchExternalData() -> session.dataTask()
    func syncFromExternal() {
        let externalUrl = readLine() ?? ""
        let patientId = readLine() ?? ""
        let result = integrationService.syncFromExternal(externalUrl: externalUrl, patientId: patientId)
        print("Synced: \(result)")
    }

    // VULN: Command injection - 3 hop chain
    // readLine -> provider/bucket -> integrationService.backupToCloud() -> shellExec() -> Process.run()
    func backupData() {
        let provider = readLine() ?? ""
        let bucket = readLine() ?? ""
        let result = integrationService.backupToCloud(provider: provider, bucket: bucket)
        print("Backup: \(result)")
    }

    // VULN: SQL injection - 4 hop chain
    // readLine -> metricType -> healthService.queryMetrics() -> buildMetricsSQL()
    //   -> repository.executeRawQuery() -> sqlite3_exec
    func queryMetrics() {
        let patientId = readLine() ?? ""
        let metricType = readLine() ?? ""
        let days = readLine() ?? "30"
        let results = healthService.queryMetrics(patientId: patientId, metricType: metricType, days: days)
        print("Metrics: \(results)")
    }

    // VULN: Path traversal - 3 hop chain
    // readLine -> path -> healthService.bulkExport() -> repository.exportToCsv() -> String(contentsOfFile:)
    func bulkExport() {
        let outputPath = readLine() ?? ""
        let results = healthService.bulkExport(outputPath: outputPath)
        print("Exported: \(results)")
    }

    // VULN: Template injection - 4 hop chain
    // readLine -> template -> healthService.renderPatientReport() -> templateEngine.render()
    //   -> executeTemplate() -> loadHTMLString
    func renderPatientReport() {
        let templateName = readLine() ?? ""
        let patientId = readLine() ?? ""
        let html = healthService.renderPatientReport(template: templateName, patientId: patientId)
        print("Rendered: \(html)")
    }

    // VULN: Deserialization - 3 hop chain
    // readLine -> data -> healthService.importPatientData() -> repository.deserializeRecord()
    //   -> NSKeyedUnarchiver
    func importPatientData() {
        let rawData = readLine() ?? ""
        let result = healthService.importPatientData(rawPayload: rawData)
        print("Imported: \(result)")
    }

    // VULN: XXE - 3 hop chain
    // readLine -> xml -> healthService.parseHL7Message() -> repository.parseXmlDocument()
    //   -> XMLParser
    func parseHL7() {
        let xmlPayload = readLine() ?? ""
        let result = healthService.parseHL7Message(xmlContent: xmlPayload)
        print("Parsed: \(result)")
    }

    // VULN: SQL injection via env - 3 hop chain
    // ProcessInfo.environment -> dbQuery -> repository.executeRawQuery() -> sqlite3_exec
    func runScheduledReport() {
        let env = ProcessInfo.processInfo.environment
        let dbQuery = env["REPORT_QUERY"] ?? "SELECT 1"
        let tableFilter = env["TABLE_FILTER"] ?? "health_records"
        let sql = "SELECT * FROM \(tableFilter) WHERE \(dbQuery)"
        let results = repository.executeRawQuery(sql: sql)
        print("Report: \(results)")
    }

    // VULN: Command injection via CLI args - 3 hop chain
    // CommandLine.arguments -> arg -> shellExec() -> Process.run()
    func runMaintenanceTask() {
        let args = CommandLine.arguments
        if args.count > 1 {
            let task = args[1]
            let target = args.count > 2 ? args[2] : "default"
            let cmd = "maintenance-tool --task \(task) --target \(target)"
            let output = shellExec(cmd)
            print("Maintenance: \(output)")
        }
    }

    // VULN: Header injection - 3 hop chain
    // readLine -> headerValue -> integrationService.sendCustomRequest() -> URLRequest.setValue()
    func forwardRequest() {
        let headerValue = readLine() ?? ""
        let targetUrl = readLine() ?? ""
        let result = integrationService.sendCustomRequest(url: targetUrl, customHeader: headerValue)
        print("Forward result: \(result)")
    }

    // VULN: NoSQL injection - 3 hop chain
    // readLine -> filter -> healthService.searchWithNoSQL() -> repository.queryMongo() -> find()
    func searchWithFilter() {
        let filterExpr = readLine() ?? ""
        let results = healthService.searchWithNoSQL(filterExpression: filterExpr)
        print("NoSQL results: \(results)")
    }

    // VULN: Path traversal via FileManager - 3 hop chain
    // readLine -> dirPath -> healthService.listExportFiles() -> repository.listDirectory()
    //   -> FileManager.contentsOfDirectory
    func listExports() {
        let dirPath = readLine() ?? ""
        let files = healthService.listExportFiles(directory: dirPath)
        print("Files: \(files)")
    }

    // VULN: SQL injection via GRDB - 4 hop chain
    // readLine -> query -> healthService.advancedSearch() -> buildAdvancedSQL()
    //   -> repository.grdbFetchAll() -> fetchAll
    func advancedSearch() {
        let query = readLine() ?? ""
        let category = readLine() ?? ""
        let results = healthService.advancedSearch(query: query, category: category)
        print("Advanced results: \(results)")
    }
}
