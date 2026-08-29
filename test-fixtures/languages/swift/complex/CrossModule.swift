import Foundation

// Cross-Module Vulnerability Chains
// Deep chains (4-8 hops) spanning multiple files:
//   Routes.swift       -> RoutesController, shellExec()
//   Repository.swift   -> HealthRepository
//   HealthService.swift -> HealthService, NotificationService, TemplateEngine
//   IntegrationService.swift -> IntegrationService, FHIRClient
//   SecurityMiddleware.swift -> SecurityMiddleware, TokenManager
//   AdvancedPatterns.swift -> ShellRunner, DatabaseClient

// ---------------------------------------------------------------------------
// MARK: - Chain A: Deep SQL injection (6 hops, 3 files)
// readLine -> buildAuditFilter() -> wrapInSubquery()
//   -> HealthService.buildSearchSQL() -> HealthRepository.findByFilter()
//   -> executeRawQuery() -> sqlite3_exec
// ---------------------------------------------------------------------------

class CrossModuleOrchestrator {
    let routes: RoutesController
    let integrationService: IntegrationService
    let fhirClient: FHIRClient

    init() {
        self.routes = RoutesController(dbPath: "/var/health/prod.db")
        self.integrationService = IntegrationService()
        self.fhirClient = FHIRClient(baseUrl: "https://fhir.example.com")
    }

    func deepAuditQuery() {
        let userInput = readLine() ?? ""
        let filter = buildAuditFilter(raw: userInput)
        let subquery = wrapInSubquery(clause: filter)
        let fullSQL = routes.healthService.buildSearchSQL(
            query: subquery, sortBy: "date", limit: "100"
        )
        let results = routes.repository.findByFilter(sql: fullSQL)
        // Direct sqlite3_exec for the flow engine to find
        var db: OpaquePointer?
        sqlite3_exec(db, fullSQL, nil, nil, nil)
        print("Audit: \(results.count)")
    }

    private func buildAuditFilter(raw: String) -> String {
        return "audit_type = '\(raw.trimmingCharacters(in: .whitespaces))'"
    }

    private func wrapInSubquery(clause: String) -> String {
        return "id IN (SELECT record_id FROM audit_log WHERE \(clause))"
    }
}

// ---------------------------------------------------------------------------
// MARK: - Chain B: Shared state command injection (3 files)
// readLine -> SharedState.pendingCommand -> ExecutionWorker.processPending()
//   -> shellExec() -> Process.run()
// ---------------------------------------------------------------------------

class SharedState {
    static var pendingCommand: String = ""
    static var pendingUrl: String = ""

    static func enqueueCommand(cmd: String) {
        SharedState.pendingCommand = cmd
    }

    static func enqueueUrl(url: String) {
        SharedState.pendingUrl = url
    }
}

class ExecutionWorker {
    func processPending() {
        let cmd = SharedState.pendingCommand
        if !cmd.isEmpty {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", cmd]
            try? process.run()
            let output = shellExec(cmd)
            print("Executed: \(output)")
            SharedState.pendingCommand = ""
        }
    }
}

func staticVariableCommandInjection() {
    let input = readLine() ?? ""
    SharedState.enqueueCommand(cmd: input)
    let worker = ExecutionWorker()
    worker.processPending()
}

// ---------------------------------------------------------------------------
// MARK: - Chain C: Closure callback SSRF (3 files)
// readLine -> url -> fetchWithCallback() -> IntegrationService.fetchExternalData()
//   -> URLSession.dataTask()
// ---------------------------------------------------------------------------

typealias FetchCallback = (String) -> Void

func fetchWithCallback(url: String, onComplete: @escaping FetchCallback) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [url]
    try? process.run()
    let service = IntegrationService()
    let result = service.fetchExternalData(apiUrl: url)
    onComplete(result)
}

func closureCallbackSsrf() {
    let url = readLine() ?? ""
    fetchWithCallback(url: url) { result in
        print("Callback received: \(result)")
    }
}

// ---------------------------------------------------------------------------
// MARK: - Chain D: Delegation wrapper command injection (4 files)
// readLine -> NotificationFacade.sendAlert() -> NotificationBridge.relay()
//   -> HealthService.notifyPatient() -> NotificationService.sendSMS()
//   -> buildSMSCommand() -> execCommand() -> Process.run()
// ---------------------------------------------------------------------------

class NotificationBridge {
    let healthService: HealthService

    init() {
        let repo = HealthRepository(dbPath: "/var/health/bridge.db")
        self.healthService = HealthService(repository: repo)
    }

    func relay(phone: String, message: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "display notification \"\(message)\" with title \"\(phone)\""]
        try? process.run()
        healthService.notifyPatient(patientId: "system", phone: phone, message: message)
    }
}

class NotificationFacade {
    let bridge: NotificationBridge

    init() {
        self.bridge = NotificationBridge()
    }

    func sendAlert(phone: String, body: String) {
        let enrichedBody = "[ALERT] \(body)"
        bridge.relay(phone: phone, message: enrichedBody)
    }
}

func reExportedWrapperCommandInjection() {
    let phone = readLine() ?? ""
    let message = readLine() ?? ""
    let facade = NotificationFacade()
    facade.sendAlert(phone: phone, body: message)
}

// ---------------------------------------------------------------------------
// MARK: - Chain E: Recursive template SQL injection (3 files)
// readLine -> RecursiveTemplateEngine.render() -> resolve()
//   -> HealthRepository.executeRawQuery() -> sqlite3_exec
// ---------------------------------------------------------------------------

class RecursiveTemplateEngine {
    let repository: HealthRepository
    let maxDepth: Int

    init(repository: HealthRepository, maxDepth: Int = 5) {
        self.repository = repository
        self.maxDepth = maxDepth
    }

    func render(template: String, depth: Int) -> String {
        if depth >= maxDepth {
            return resolve(finalQuery: template)
        }
        let expanded = template.replacingOccurrences(of: "{{now}}", with: "\(Date())")
        if expanded.contains("{{") {
            return render(template: expanded, depth: depth + 1)
        }
        return resolve(finalQuery: expanded)
    }

    private func resolve(finalQuery: String) -> String {
        var db: OpaquePointer?
        sqlite3_exec(db, finalQuery, nil, nil, nil)
        let results = repository.executeRawQuery(sql: finalQuery)
        return "Rendered \(results.count) rows"
    }
}

func recursiveTemplateInjection() {
    let template = readLine() ?? ""
    let repo = HealthRepository(dbPath: "/var/health/templates.db")
    let engine = RecursiveTemplateEngine(repository: repo)
    let output = engine.render(template: template, depth: 0)
    print(output)
}

// ---------------------------------------------------------------------------
// MARK: - Chain F: Cross-module SSRF via FHIR (4 hops)
// readLine -> buildFhirUrl() -> IntegrationService.fetchExternalData()
//   -> URLRequest() -> URLSession.dataTask()
// ---------------------------------------------------------------------------

func crossModuleFhirSsrf() {
    let patientIdInput = readLine() ?? ""
    let orchestrator = CrossModuleOrchestrator()
    let fhirUrl = buildFhirUrl(baseUrl: orchestrator.fhirClient.baseUrl, patientId: patientIdInput)
    let result = orchestrator.integrationService.fetchExternalData(apiUrl: fhirUrl)
    print("FHIR result: \(result)")
}

func buildFhirUrl(baseUrl: String, patientId: String) -> String {
    return "\(baseUrl)/Patient/\(patientId)"
}

// ---------------------------------------------------------------------------
// MARK: - Chain G: Cross-module path traversal (4 hops, 3 files)
// readLine -> buildExportPath() -> HealthService.exportRecord()
//   -> HealthRepository.readFile() -> String(contentsOfFile:)
// ---------------------------------------------------------------------------

func crossModulePathTraversal() {
    let userDir = readLine() ?? ""
    let fileName = readLine() ?? ""
    let path = buildExportPath(directory: userDir, file: fileName)
    let repo = HealthRepository(dbPath: "/var/health/main.db")
    let service = HealthService(repository: repo)
    let content = service.exportRecord(filename: path)
    print("Export content: \(content)")
}

func buildExportPath(directory: String, file: String) -> String {
    return "\(directory)/\(file)"
}

// ---------------------------------------------------------------------------
// MARK: - Chain H: Cross-module command injection via backup (5 hops, 3 files)
// readLine -> validateProvider() -> IntegrationService.backupToCloud()
//   -> shellExec() -> Process.run()
// ---------------------------------------------------------------------------

func crossModuleBackupInjection() {
    let provider = readLine() ?? ""
    let bucket = readLine() ?? ""
    let validatedProvider = validateProvider(name: provider)
    let enrichedBucket = enrichBucketName(bucket: bucket, prefix: "health")
    let service = IntegrationService()
    let result = service.backupToCloud(provider: validatedProvider, bucket: enrichedBucket)
    print("Backup result: \(result)")
}

func validateProvider(name: String) -> String {
    // No actual validation - taint passes through
    return name.trimmingCharacters(in: .whitespaces)
}

func enrichBucketName(bucket: String, prefix: String) -> String {
    return "\(prefix)-\(bucket)"
}

// ---------------------------------------------------------------------------
// MARK: - Chain I: Cross-module header injection (4 hops, 3 files)
// readLine -> buildAuthHeader() -> IntegrationService.sendCustomRequest()
//   -> URLRequest.setValue()
// ---------------------------------------------------------------------------

func crossModuleHeaderInjection() {
    let token = readLine() ?? ""
    let targetUrl = readLine() ?? ""
    let authHeader = buildAuthHeader(token: token)
    let service = IntegrationService()
    let result = service.sendCustomRequest(url: targetUrl, customHeader: authHeader)
    print("Header result: \(result)")
}

func buildAuthHeader(token: String) -> String {
    return "Bearer \(token)"
}

// ---------------------------------------------------------------------------
// MARK: - Chain J: Cross-module XXE (5 hops, 3 files)
// readLine -> wrapXmlPayload() -> HealthService.parseHL7Message()
//   -> wrapHL7Content() -> HealthRepository.parseXmlDocument() -> XMLParser
// ---------------------------------------------------------------------------

func crossModuleXxe() {
    let xmlInput = readLine() ?? ""
    let wrapped = wrapXmlPayload(content: xmlInput)
    let repo = HealthRepository(dbPath: "/var/health/xml.db")
    let service = HealthService(repository: repo)
    let result = service.parseHL7Message(xmlContent: wrapped)
    print("XXE result: \(result)")
}

func wrapXmlPayload(content: String) -> String {
    return "<Envelope>\(content)</Envelope>"
}

// ---------------------------------------------------------------------------
// MARK: - Chain K: Cross-module deserialization (5 hops, 3 files)
// readLine -> encodePayload() -> HealthService.importPatientData()
//   -> preprocessImportData() -> HealthRepository.deserializeRecord()
//   -> NSKeyedUnarchiver
// ---------------------------------------------------------------------------

func crossModuleDeserialization() {
    let rawInput = readLine() ?? ""
    let encoded = encodePayload(input: rawInput)
    let repo = HealthRepository(dbPath: "/var/health/deser.db")
    let service = HealthService(repository: repo)
    let result = service.importPatientData(rawPayload: encoded)
    print("Deser result: \(result)")
}

func encodePayload(input: String) -> String {
    return Data(input.utf8).base64EncodedString()
}

// ---------------------------------------------------------------------------
// MARK: - Chain L: Cross-module NoSQL injection (5 hops, 3 files)
// readLine -> buildFilterExpression() -> HealthService.searchWithNoSQL()
//   -> buildMongoFilter() -> HealthRepository.queryMongo() -> find()
// ---------------------------------------------------------------------------

func crossModuleNoSqlInjection() {
    let userQuery = readLine() ?? ""
    let filterExpr = buildFilterExpression(query: userQuery)
    let repo = HealthRepository(dbPath: "/var/health/nosql.db")
    let service = HealthService(repository: repo)
    let results = service.searchWithNoSQL(filterExpression: filterExpr)
    print("NoSQL results: \(results)")
}

func buildFilterExpression(query: String) -> String {
    return "name = '\(query)'"
}

// ---------------------------------------------------------------------------
// MARK: - Chain M: Cross-module template injection (5 hops, 3 files)
// readLine -> buildTemplateName() -> HealthService.renderPatientReport()
//   -> TemplateEngine.renderTemplate() -> loadTemplate() -> String(contentsOfFile:)
// ---------------------------------------------------------------------------

func crossModuleTemplateInjection() {
    let templateInput = readLine() ?? ""
    let patientId = readLine() ?? ""
    let templateName = buildTemplateName(input: templateInput)
    let repo = HealthRepository(dbPath: "/var/health/tmpl.db")
    let service = HealthService(repository: repo)
    let html = service.renderPatientReport(template: templateName, patientId: patientId)
    print("Template result: \(html)")
}

func buildTemplateName(input: String) -> String {
    return "\(input).html"
}

// ---------------------------------------------------------------------------
// MARK: - Chain N: Cross-module SSRF via upload (4 hops, 2 files)
// readLine -> buildUploadUrl() -> IntegrationService.uploadToService()
//   -> URLSession.upload()
// ---------------------------------------------------------------------------

func crossModuleUploadSsrf() {
    let targetUrl = readLine() ?? ""
    let data = readLine() ?? ""
    let uploadUrl = buildUploadUrl(base: targetUrl)
    let service = IntegrationService()
    let result = service.uploadToService(url: uploadUrl, data: data)
    print("Upload result: \(result)")
}

func buildUploadUrl(base: String) -> String {
    return "\(base)/upload"
}

// ---------------------------------------------------------------------------
// MARK: - Chain O: Cross-module SSRF via download (4 hops, 2 files)
// readLine -> buildDownloadUrl() -> IntegrationService.downloadExternalFile()
//   -> URLSession.download()
// ---------------------------------------------------------------------------

func crossModuleDownloadSsrf() {
    let remoteUrl = readLine() ?? ""
    let downloadUrl = buildDownloadUrl(base: remoteUrl)
    let service = IntegrationService()
    let result = service.downloadExternalFile(url: downloadUrl, destination: "/tmp/download")
    print("Download result: \(result)")
}

func buildDownloadUrl(base: String) -> String {
    return "\(base)/file"
}

// ---------------------------------------------------------------------------
// MARK: - Chain P: Cross-module command injection via maintenance (4 hops, 2 files)
// readLine -> buildScriptName() -> IntegrationService.runMaintenanceScript()
//   -> Process.run()
// ---------------------------------------------------------------------------

func crossModuleMaintenanceInjection() {
    let scriptInput = readLine() ?? ""
    let argsInput = readLine() ?? ""
    let scriptName = buildScriptName(input: scriptInput)
    let service = IntegrationService()
    let result = service.runMaintenanceScript(scriptName: scriptName, args: argsInput)
    print("Maintenance result: \(result)")
}

func buildScriptName(input: String) -> String {
    return input.trimmingCharacters(in: .whitespaces)
}

// ---------------------------------------------------------------------------
// MARK: - Chain Q: Cross-module FileManager write (4 hops, 3 files)
// readLine -> buildWritePath() -> HealthRepository.writeExportFile()
//   -> FileManager.createFile()
// ---------------------------------------------------------------------------

func crossModuleFileWrite() {
    let dirInput = readLine() ?? ""
    let contentInput = readLine() ?? ""
    let writePath = buildWritePath(dir: dirInput)
    let repo = HealthRepository(dbPath: "/var/health/write.db")
    let success = repo.writeExportFile(path: writePath, content: contentInput)
    print("Write result: \(success)")
}

func buildWritePath(dir: String) -> String {
    return "/var/exports/\(dir)/output.csv"
}

// ---------------------------------------------------------------------------
// MARK: - Chain R: Cross-module FileManager delete (4 hops, 3 files)
// readLine -> buildDeletePath() -> HealthRepository.deleteExportFile()
//   -> FileManager.removeItem()
// ---------------------------------------------------------------------------

func crossModuleFileDelete() {
    let pathInput = readLine() ?? ""
    let deletePath = buildDeletePath(input: pathInput)
    let repo = HealthRepository(dbPath: "/var/health/del.db")
    let success = repo.deleteExportFile(path: deletePath)
    print("Delete result: \(success)")
}

func buildDeletePath(input: String) -> String {
    return "/var/exports/\(input)"
}

// ---------------------------------------------------------------------------
// MARK: - Chain S: Cross-module GRDB SQL injection (5 hops, 3 files)
// readLine -> buildGrdbQuery() -> HealthService.advancedSearch()
//   -> buildAdvancedSQL() -> HealthRepository.grdbFetchAll() -> fetchAll
// ---------------------------------------------------------------------------

func crossModuleGrdbInjection() {
    let searchInput = readLine() ?? ""
    let category = readLine() ?? ""
    let grdbQuery = buildGrdbQuery(term: searchInput)
    let repo = HealthRepository(dbPath: "/var/health/grdb.db")
    let service = HealthService(repository: repo)
    let results = service.advancedSearch(query: grdbQuery, category: category)
    print("GRDB results: \(results)")
}

func buildGrdbQuery(term: String) -> String {
    return "%\(term)%"
}

// ---------------------------------------------------------------------------
// MARK: - Chain T: Multi-source SQL injection (env + readLine, 3 hops)
// ProcessInfo.environment + readLine -> combineInputs() -> executeRawQuery() -> sqlite3_exec
// ---------------------------------------------------------------------------

func multiSourceSqlInjection() {
    let env = ProcessInfo.processInfo.environment
    let envFilter = env["DB_FILTER"] ?? ""
    let userInput = readLine() ?? ""
    let combined = combineInputs(envPart: envFilter, userPart: userInput)
    let repo = HealthRepository(dbPath: "/var/health/multi.db")
    let results = repo.executeRawQuery(sql: combined)
    print("Multi-source results: \(results)")
}

func combineInputs(envPart: String, userPart: String) -> String {
    return "SELECT * FROM records WHERE env_filter = '\(envPart)' AND user_filter = '\(userPart)'"
}

// ---------------------------------------------------------------------------
// MARK: - Entry Point
// ---------------------------------------------------------------------------

func runCrossModuleChains() {
    let orchestrator = CrossModuleOrchestrator()
    orchestrator.deepAuditQuery()
    staticVariableCommandInjection()
    closureCallbackSsrf()
    reExportedWrapperCommandInjection()
    recursiveTemplateInjection()
    crossModuleFhirSsrf()
    crossModulePathTraversal()
    crossModuleBackupInjection()
    crossModuleHeaderInjection()
    crossModuleXxe()
    crossModuleDeserialization()
    crossModuleNoSqlInjection()
    crossModuleTemplateInjection()
    crossModuleUploadSsrf()
    crossModuleDownloadSsrf()
    crossModuleMaintenanceInjection()
    crossModuleFileWrite()
    crossModuleFileDelete()
    crossModuleGrdbInjection()
    multiSourceSqlInjection()
}
