import Foundation

// Advanced Swift Patterns - Self-contained vulnerability chains
// Exercises: protocols, guard let, if let, nil coalescing, switch/enum,
// trailing closures, Result type, map/filter, computed properties,
// extensions, Codable, do-catch, async/await, KeyPaths, unsafe pointers

// ---------------------------------------------------------------------------
// MARK: - Protocol Dispatch
// ---------------------------------------------------------------------------

protocol CommandRunner {
    func execute(command: String) -> String
}

class ShellRunner: CommandRunner {
    func execute(command: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

class LoggingRunner: CommandRunner {
    let inner: CommandRunner

    init(inner: CommandRunner) {
        self.inner = inner
    }

    func execute(command: String) -> String {
        print("Running: \(command)")
        return inner.execute(command: command)
    }
}

// VULN 1: Protocol dispatch command injection
func runViaProtocol() {
    let input = readLine() ?? ""
    let runner: CommandRunner = LoggingRunner(inner: ShellRunner())
    let result = runner.execute(command: input)
    print(result)
}

// ---------------------------------------------------------------------------
// MARK: - Guard Let + If Let
// ---------------------------------------------------------------------------

class DatabaseClient {
    var connectionString: String

    init(connectionString: String) {
        self.connectionString = connectionString
    }

    func query(sql: String) -> [[String: Any]] {
        var errMsg: UnsafeMutablePointer<CChar>?
        sqlite3_exec(nil, sql, nil, nil, &errMsg)
        return []
    }
}

// VULN 2: Guard let SQL injection
func guardLetSQLInjection() {
    let raw = readLine()
    guard let userInput = raw else { return }
    let sql = buildSQL(filter: userInput)
    let db = DatabaseClient(connectionString: "sqlite:///data.db")
    let results = db.query(sql: sql)
    print("Found \(results.count) rows")
}

func buildSQL(filter: String) -> String {
    return "SELECT * FROM users WHERE name = '\(filter)'"
}

// VULN 3: If let command injection via environment
func ifLetCommandInjection() {
    let env = ProcessInfo.processInfo.environment
    if let cmd = env["EXTERNAL_CMD"] {
        let runner = ShellRunner()
        let output = runner.execute(command: cmd)
        print(output)
    }
}

// ---------------------------------------------------------------------------
// MARK: - Nil Coalescing
// ---------------------------------------------------------------------------

// VULN 4: Nil coalescing SSRF
func nilCoalescingSsrf() {
    let args = CommandLine.arguments
    let target = args.count > 1 ? args[1] : nil
    let urlString = target ?? "https://default.example.com"
    guard let url = URL(string: urlString) else { return }
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
}

// ---------------------------------------------------------------------------
// MARK: - Switch + Associated Values
// ---------------------------------------------------------------------------

enum UserAction {
    case search(query: String)
    case execute(command: String)
    case fetch(url: String)
    case safe(message: String)
}

// VULN 5: Switch associated values SQL injection
func switchAssociatedValueVuln() {
    let input = readLine() ?? ""
    let action: UserAction = .search(query: input)
    let db = DatabaseClient(connectionString: "sqlite:///app.db")
    switch action {
    case .search(let query):
        let sql = "SELECT * FROM items WHERE title LIKE '%\(query)%'"
        let results = db.query(sql: sql)
        print("Results: \(results.count)")
    case .execute(let command):
        let runner = ShellRunner()
        let output = runner.execute(command: command)
        print(output)
    case .fetch(let url):
        guard let reqUrl = URL(string: url) else { return }
        let request = URLRequest(url: reqUrl)
        let task = URLSession.shared.dataTask(with: request)
        task.resume()
    case .safe(let message):
        print("Safe: \(message)")
    }
}

// ---------------------------------------------------------------------------
// MARK: - Trailing Closure
// ---------------------------------------------------------------------------

func withDatabaseConnection(_ connectionString: String, handler: (DatabaseClient) -> Void) {
    let db = DatabaseClient(connectionString: connectionString)
    handler(db)
}

// VULN 6: Trailing closure SQL injection
func trailingClosureSQLInjection() {
    let userQuery = readLine() ?? ""
    withDatabaseConnection("sqlite:///store.db") { db in
        let sql = "SELECT * FROM products WHERE name = '\(userQuery)'"
        let results = db.query(sql: sql)
        print("Products: \(results.count)")
    }
}

// ---------------------------------------------------------------------------
// MARK: - Result Type
// ---------------------------------------------------------------------------

enum AppError: Error {
    case networkError(String)
    case parseError(String)
}

func fetchUserData(endpoint: String) -> Result<String, AppError> {
    guard let url = URL(string: endpoint) else {
        return .failure(.networkError("Invalid URL"))
    }
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
    return .success("Fetched from \(endpoint)")
}

// VULN 7: Result type SSRF
func resultTypeSsrf() {
    let endpoint = readLine() ?? ""
    let result = fetchUserData(endpoint: endpoint)
    switch result {
    case .success(let data): print("Data: \(data)")
    case .failure(let error): print("Error: \(error)")
    }
}

// ---------------------------------------------------------------------------
// MARK: - Collection Chain
// ---------------------------------------------------------------------------

// VULN 8: Collection chain command injection
func collectionChainCommandInjection() {
    let raw = readLine() ?? ""
    let parts = raw.split(separator: ",").map { String($0) }
    let filtered = parts.filter { !$0.isEmpty }
    let transformed = filtered.map { "echo \($0)" }
    let combined = transformed.reduce("") { r, n in r.isEmpty ? n : "\(r) && \(n)" }
    let runner = ShellRunner()
    let output = runner.execute(command: combined)
    print(output)
}

// ---------------------------------------------------------------------------
// MARK: - Computed Property
// ---------------------------------------------------------------------------

class RequestContext {
    let rawPath: String
    init(path: String) { self.rawPath = path }
    var fullPath: String { return "/var/data/uploads/" + rawPath }
}

// VULN 9: Computed property path traversal
func computedPropertyPathTraversal() {
    let path = readLine() ?? ""
    let ctx = RequestContext(path: path)
    guard let content = try? String(contentsOfFile: ctx.fullPath, encoding: .utf8) else { return }
    print(content)
}

// ---------------------------------------------------------------------------
// MARK: - Extension Method
// ---------------------------------------------------------------------------

extension String {
    func asShellCommand() -> String {
        return "/bin/sh -c '\(self)'"
    }
}

// VULN 10: Extension method command injection
func extensionMethodCommandInjection() {
    let input = readLine() ?? ""
    let cmd = input.asShellCommand()
    let runner = ShellRunner()
    let output = runner.execute(command: cmd)
    print(output)
}

// ---------------------------------------------------------------------------
// MARK: - Codable / JSONDecoder
// ---------------------------------------------------------------------------

struct ApiRequest: Codable {
    let action: String
    let target: String
    let payload: String
}

// VULN 11: Codable decode command injection
func codableDecodeCommandInjection() {
    let jsonString = readLine() ?? "{}"
    guard let jsonData = jsonString.data(using: .utf8) else { return }
    do {
        let request = try JSONDecoder().decode(ApiRequest.self, from: jsonData)
        let runner = ShellRunner()
        let output = runner.execute(command: request.action)
        print("Action result: \(output)")
    } catch { print("Decode error: \(error)") }
}

// ---------------------------------------------------------------------------
// MARK: - Do-Catch
// ---------------------------------------------------------------------------

enum FileError: Error { case readFailed(String) }

func readConfig(path: String) throws -> String {
    guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
        throw FileError.readFailed(path)
    }
    return content
}

// VULN 12: Do-catch path traversal
func doCatchPathTraversal() {
    let filePath = readLine() ?? ""
    do {
        let content = try readConfig(path: filePath)
        print("Config: \(content)")
    } catch { print("Failed: \(error)") }
}

// ---------------------------------------------------------------------------
// MARK: - Async/Await
// ---------------------------------------------------------------------------

// VULN 13: Async/await SSRF
func fetchAsync(urlString: String) async throws -> String {
    guard let url = URL(string: urlString) else { return "Invalid" }
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
    return "Fetched: \(urlString)"
}

func asyncAwaitSsrf() {
    let urlString = readLine() ?? ""
    Task {
        let result = try? await fetchAsync(urlString: urlString)
        print(result ?? "Failed")
    }
}

// ---------------------------------------------------------------------------
// MARK: - KeyPath Access
// ---------------------------------------------------------------------------

struct ServerConfig {
    var hostname: String
    var port: Int
    var adminCommand: String
}

func readField<T>(_ config: ServerConfig, keyPath: KeyPath<ServerConfig, T>) -> T {
    return config[keyPath: keyPath]
}

// VULN 14: KeyPath command injection
func keyPathCommandInjection() {
    let adminCmd = readLine() ?? "status"
    let config = ServerConfig(hostname: "localhost", port: 8080, adminCommand: adminCmd)
    let cmd: String = readField(config, keyPath: \.adminCommand)
    let runner = ShellRunner()
    let output = runner.execute(command: cmd)
    print("Admin output: \(output)")
}

// ---------------------------------------------------------------------------
// MARK: - Unsafe Pointer Patterns
// ---------------------------------------------------------------------------

// VULN 15: UnsafeMutablePointer from user input
func unsafePointerFromInput() {
    let sizeStr = readLine() ?? "1024"
    let size = Int(sizeStr) ?? 1024
    let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
    ptr.initialize(repeating: 0, count: size)
    let buffer = UnsafeMutableBufferPointer(start: ptr, count: size)
    print("Allocated \(buffer.count) bytes")
    ptr.deallocate()
}

// VULN 16: UnsafeRawPointer bindMemory
func unsafeBindMemory() {
    let input = readLine() ?? ""
    let data = input.data(using: .utf8) ?? Data()
    data.withUnsafeBytes { rawBuffer in
        let ptr = rawBuffer.bindMemory(to: UInt32.self)
        print("Bound \(ptr.count) elements")
    }
}

// ---------------------------------------------------------------------------
// MARK: - FileManager Path Traversal
// ---------------------------------------------------------------------------

// VULN 17: FileManager.copyItem
func copyFileFromInput() {
    let sourcePath = readLine() ?? ""
    let destPath = readLine() ?? "/tmp/output"
    let fm = FileManager.default
    try? fm.copyItem(atPath: sourcePath, toPath: destPath)
}

// VULN 18: FileManager.moveItem
func moveFileFromInput() {
    let sourcePath = readLine() ?? ""
    let destPath = readLine() ?? "/tmp/moved"
    let fm = FileManager.default
    try? fm.moveItem(atPath: sourcePath, toPath: destPath)
}

// VULN 19: FileManager.removeItem
func removeFileFromInput() {
    let targetPath = readLine() ?? ""
    let fm = FileManager.default
    try? fm.removeItem(atPath: targetPath)
}

// VULN 20: FileManager.createFile
func createFileFromInput() {
    let filePath = readLine() ?? ""
    let content = readLine() ?? ""
    let fm = FileManager.default
    fm.createFile(atPath: filePath, contents: content.data(using: .utf8), attributes: nil)
}

// VULN 21: FileManager.contentsOfDirectory
func listDirectoryFromInput() {
    let dirPath = readLine() ?? ""
    let fm = FileManager.default
    let items = try? fm.contentsOfDirectory(atPath: dirPath)
    print("Items: \(items ?? [])")
}

// ---------------------------------------------------------------------------
// MARK: - Deserialization + XXE
// ---------------------------------------------------------------------------

// VULN 22: NSKeyedUnarchiver from file
func deserializeFromFile() {
    let filePath = readLine() ?? ""
    let obj = NSKeyedUnarchiver.unarchiveObject(withFile: filePath)
    print("Deserialized: \(obj ?? "nil")")
}

// VULN 23: XMLDocument XXE
func parseXmlDocument() {
    let xmlInput = readLine() ?? ""
    guard let data = xmlInput.data(using: .utf8) else { return }
    let doc = try? XMLDocument(data: data, options: [])
    print("Parsed: \(doc?.rootElement()?.name ?? "none")")
}

// VULN 24: XMLParser XXE
func parseXmlWithParser() {
    let xmlInput = readLine() ?? ""
    guard let data = xmlInput.data(using: .utf8) else { return }
    let parser = XMLParser(data: data)
    parser.parse()
}

// ---------------------------------------------------------------------------
// MARK: - Protocol-based SQL Injection Chain
// ---------------------------------------------------------------------------

protocol DataQueryable {
    func runQuery(sql: String) -> [[String: Any]]
}

class SQLiteQueryEngine: DataQueryable {
    func runQuery(sql: String) -> [[String: Any]] {
        var errMsg: UnsafeMutablePointer<CChar>?
        sqlite3_exec(nil, sql, nil, nil, &errMsg)
        return []
    }
}

// VULN 25: Protocol-based SQL injection
func protocolBasedSqlInjection() {
    let searchTerm = readLine() ?? ""
    let engine: DataQueryable = SQLiteQueryEngine()
    let sql = buildSearchQuery(term: searchTerm)
    let results = engine.runQuery(sql: sql)
    print("Found: \(results.count)")
}

func buildSearchQuery(term: String) -> String {
    return "SELECT * FROM patients WHERE name LIKE '%\(term)%'"
}

// ---------------------------------------------------------------------------
// MARK: - Closure SSRF
// ---------------------------------------------------------------------------

func performRequest(urlStr: String, completion: (String) -> Void) {
    guard let url = URL(string: urlStr) else { return }
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
    completion("Requested: \(urlStr)")
}

// VULN 26: Closure callback SSRF
func closureBasedSsrf() {
    let target = readLine() ?? ""
    performRequest(urlStr: target) { result in
        print("Result: \(result)")
    }
}

// ---------------------------------------------------------------------------
// MARK: - Process.launchPath
// ---------------------------------------------------------------------------

// VULN 27: launchPath injection
func launchPathInjection() {
    let execPath = readLine() ?? ""
    let process = Process()
    process.launchPath = execPath
    process.arguments = ["--run"]
    try? process.run()
}

// ---------------------------------------------------------------------------
// MARK: - Data.contentsOf
// ---------------------------------------------------------------------------

// VULN 28: Data(contentsOf:) path traversal
func dataContentsOfTraversal() {
    let filePath = readLine() ?? ""
    let url = URL(fileURLWithPath: filePath)
    let data = try? Data(contentsOf: url)
    print("Read \(data?.count ?? 0) bytes")
}

// ---------------------------------------------------------------------------
// MARK: - WKWebView template injection
// ---------------------------------------------------------------------------

class WKWebView {
    func loadHTMLString(_ string: String, baseURL: URL?) {}
}

// VULN 29: loadHTMLString template injection
func webViewTemplateInjection() {
    let userContent = readLine() ?? ""
    let html = "<html><body>\(userContent)</body></html>"
    let webView = WKWebView()
    webView.loadHTMLString(html, baseURL: nil)
}

// ---------------------------------------------------------------------------
// MARK: - Direct same-scope sink chains
// ---------------------------------------------------------------------------

// VULN 30: Direct readLine -> sqlite3_exec
func directSqlInjection() {
    let userSql = readLine() ?? ""
    var db: OpaquePointer?
    sqlite3_exec(db, userSql, nil, nil, nil)
}

// VULN 31: Direct readLine -> URLRequest SSRF
func directSsrf() {
    let url = readLine() ?? ""
    guard let requestUrl = URL(string: url) else { return }
    let request = URLRequest(url: requestUrl)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
}

// VULN 32: Direct readLine -> String(contentsOfFile:) path traversal
func directPathTraversal() {
    let path = readLine() ?? ""
    let content = try? String(contentsOfFile: path, encoding: .utf8)
    print(content ?? "")
}

// VULN 33: Direct readLine -> Process command injection
func directCommandInjection() {
    let cmd = readLine() ?? ""
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", cmd]
    try? process.run()
}

// VULN 34: Direct readLine -> NSPredicate injection
func directPredicateInjection() {
    let filter = readLine() ?? ""
    let predicate = NSPredicate(format: filter)
    print("Predicate: \(predicate)")
}

// VULN 35: Direct readLine -> FileManager.contents path traversal
func directFileManagerRead() {
    let path = readLine() ?? ""
    let fm = FileManager.default
    let data = fm.contents(atPath: path)
    print("Read \(data?.count ?? 0) bytes")
}

// VULN 36: CLI args -> SSRF
func cliArgsSsrf() {
    let args = CommandLine.arguments
    if args.count > 2 {
        let url = args[2]
        guard let requestUrl = URL(string: url) else { return }
        let request = URLRequest(url: requestUrl)
        let task = URLSession.shared.dataTask(with: request)
        task.resume()
    }
}

// VULN 37: Env -> command injection
func envCommandInjection() {
    let env = ProcessInfo.processInfo.environment
    let script = env["STARTUP_SCRIPT"] ?? ""
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", script]
    try? process.run()
}

// VULN 38: readLine -> FileHandle path traversal
func fileHandlePathTraversal() {
    let path = readLine() ?? ""
    let fh = FileHandle(forReadingAtPath: path)
    let data = fh?.readDataToEndOfFile()
    print("Read \(data?.count ?? 0) bytes")
}

// VULN 39: readLine -> NSPredicate with format arg
func predicateFormatInjection() {
    let nameInput = readLine() ?? ""
    let predicate = NSPredicate(format: "name == '\(nameInput)'")
    print("Predicate: \(predicate)")
}

// VULN 40: readLine -> 2-hop SQL injection chain
func twoHopSqlInjection() {
    let table = readLine() ?? ""
    let condition = readLine() ?? ""
    let sql = constructQuery(table: table, condition: condition)
    var errMsg: UnsafeMutablePointer<CChar>?
    sqlite3_exec(nil, sql, nil, nil, &errMsg)
}

func constructQuery(table: String, condition: String) -> String {
    return "SELECT * FROM \(table) WHERE \(condition)"
}

// VULN 41: readLine -> 2-hop SSRF chain
func twoHopSsrf() {
    let baseUrl = readLine() ?? ""
    let endpoint = readLine() ?? ""
    let fullUrl = constructUrl(base: baseUrl, path: endpoint)
    guard let url = URL(string: fullUrl) else { return }
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request)
    task.resume()
}

func constructUrl(base: String, path: String) -> String {
    return "\(base)/\(path)"
}

// VULN 42: readLine -> 2-hop command injection chain
func twoHopCommandInjection() {
    let toolName = readLine() ?? ""
    let toolArgs = readLine() ?? ""
    let command = constructCommand(tool: toolName, args: toolArgs)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", command]
    try? process.run()
}

func constructCommand(tool: String, args: String) -> String {
    return "\(tool) \(args)"
}

// VULN 43: readLine -> 2-hop path traversal chain
func twoHopPathTraversal() {
    let dir = readLine() ?? ""
    let file = readLine() ?? ""
    let fullPath = constructPath(directory: dir, filename: file)
    let content = try? String(contentsOfFile: fullPath, encoding: .utf8)
    print(content ?? "")
}

func constructPath(directory: String, filename: String) -> String {
    return "\(directory)/\(filename)"
}

// ============================================================
// ADDITIONAL PATTERNS - Property wrappers, actors, string interpolation
// ============================================================

// String interpolation flow
func stringInterpolationFlow(_ input: String) {
    let cmd = "ls \(input)"  // taint via string interpolation
    let process = Process()
    process.arguments = ["-c", cmd]
    try? process.run()
}

// Property wrapper (simulated)
struct UserInput {
    var raw: String
    var sanitized: String { raw.replacingOccurrences(of: "'", with: "''") }
}

func propertyFlow(_ input: UserInput) {
    let process = Process()
    process.arguments = ["-c", input.raw]  // taint from struct field
    try? process.run()
}

// Enum with associated values (pattern matching)
enum Action {
    case execute(command: String)
    case query(sql: String)
    case safe
}

func enumDispatch(_ action: Action) {
    switch action {
    case .execute(let command):
        let p = Process()
        p.arguments = ["-c", command]  // taint from enum associated value
        try? p.run()
    case .query(let sql):
        print(sql)  // taint through query
    case .safe:
        break
    }
}

// Trailing closure capture
func withInput(_ input: String, handler: (String) -> Void) {
    handler(input)  // taint through closure parameter
}

func trailingClosureFlow(_ input: String) {
    withInput(input) { cmd in
        let p = Process()
        p.arguments = ["-c", cmd]
        try? p.run()
    }
}

// Actor isolation (Swift 5.5+)
actor CommandRunner {
    func run(_ cmd: String) {
        let p = Process()
        p.arguments = ["-c", cmd]
        try? p.run()
    }
}

// Map/filter chain on optionals
func optionalChainFlow(_ input: String?) {
    let result = input
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .flatMap { $0.isEmpty ? nil : $0 }
    if let cmd = result {
        let p = Process()
        p.arguments = ["-c", cmd]
        try? p.run()
    }
}

// Property observer
class MonitoredValue {
    var command: String = "" {
        didSet {
            print("Command changed to: \(command)")
        }
        willSet {
            print("Command will change to: \(newValue)")
        }
    }
}

// Defer block
func deferFlow(_ input: String) {
    let p = Process()
    defer { p.terminate() }
    p.arguments = ["-c", input]
    try? p.run()
}
