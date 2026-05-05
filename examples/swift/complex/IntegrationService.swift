import Foundation

// Health Records API - External Integration Layer
// SSRF sinks (URLSession.dataTask, URLRequest), command injection (Process.run),
// Header injection (URLRequest.setValue)

class IntegrationService {
    let session: URLSession

    init() {
        self.session = URLSession.shared
    }

    // SINK: SSRF via webhook URL -> URLRequest + session.dataTask
    func sendWebhook(url: String, payload: String) -> String {
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        request.httpBody = payload.data(using: .utf8)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let task = session.dataTask(with: request)
        task.resume()
        return "Webhook sent to: \(url)"
    }

    // Safe version
    func sendWebhookSafe(url: String, payload: String) -> String {
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"]
        if let host = requestUrl.host, blocked.contains(host) {
            return "Blocked host: \(host)"
        }
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        request.httpBody = payload.data(using: .utf8)
        return "Webhook sent safely to: \(url)"
    }

    // SINK: SSRF via external API fetch -> URLRequest + session.dataTask
    func fetchExternalData(apiUrl: String) -> String {
        guard let url = URL(string: apiUrl) else { return "Invalid URL" }
        let request = URLRequest(url: url)
        let task = session.dataTask(with: request)
        task.resume()
        return "Fetching from: \(apiUrl)"
    }

    // SINK: Command injection via cloud export -> Process.run()
    func exportToCloud(provider: String, bucket: String, filePath: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/cloud-upload")
        process.arguments = ["--provider", provider, "--bucket", bucket, "--file", filePath]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    // Safe version
    func exportToCloudSafe(provider: String, bucket: String, filePath: String) -> String {
        let allowedProviders: Set<String> = ["aws", "gcp", "azure"]
        guard allowedProviders.contains(provider) else { return "Invalid provider" }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/cloud-upload")
        process.arguments = ["--provider", provider, "--bucket", bucket, "--file", filePath]
        try? process.run()
        return "Upload started"
    }

    // SINK: SSRF deeper chain -> fetchExternalData -> session.dataTask
    func syncFromExternal(externalUrl: String, patientId: String) -> String {
        let result = fetchExternalData(apiUrl: externalUrl)
        return "Synced patient \(patientId): \(result)"
    }

    // SINK: Command injection via backup -> shellExec -> Process.run()
    func backupToCloud(provider: String, bucket: String) -> String {
        let cmd = "cloud-backup --provider \(provider) --bucket \(bucket) --compress"
        return shellExec(cmd)
    }

    // Safe version
    func backupToCloudSafe(provider: String, bucket: String) -> String {
        let allowedProviders: Set<String> = ["aws", "gcp", "azure"]
        guard allowedProviders.contains(provider) else { return "Invalid provider" }
        let safeBucket = bucket.filter { $0.isLetter || $0.isNumber || $0 == "-" }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/cloud-backup")
        process.arguments = ["--provider", provider, "--bucket", safeBucket, "--compress"]
        try? process.run()
        return "Backup started"
    }

    // SINK: Header injection via URLRequest.setValue
    func sendCustomRequest(url: String, customHeader: String) -> String {
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        var request = URLRequest(url: requestUrl)
        request.setValue(customHeader, forHTTPHeaderField: "X-Custom-Auth")
        let task = session.dataTask(with: request)
        task.resume()
        return "Custom request sent"
    }

    // SSRF: Download external file via URLSession.download
    func downloadExternalFile(url: String, destination: String) -> String {
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        let task = session.download(from: requestUrl)
        return "Downloading to \(destination)"
    }

    // SSRF: Upload data to external service
    func uploadToService(url: String, data: String) -> String {
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        let bodyData = data.data(using: .utf8) ?? Data()
        let task = session.upload(from: bodyData, to: requestUrl)
        return "Uploaded to \(url)"
    }

    // Command injection: execute maintenance script
    func runMaintenanceScript(scriptName: String, args: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/\(scriptName)")
        process.arguments = [args]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

class FHIRClient {
    let baseUrl: String
    let session: URLSession

    init(baseUrl: String) {
        self.baseUrl = baseUrl
        self.session = URLSession.shared
    }

    // SINK: SSRF via FHIR endpoint
    func getPatient(patientId: String) -> String {
        let url = "\(baseUrl)/Patient/\(patientId)"
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        let request = URLRequest(url: requestUrl)
        let task = session.dataTask(with: request)
        task.resume()
        return "Fetching patient: \(patientId)"
    }

    func searchPatients(query: String) -> String {
        let url = "\(baseUrl)/Patient?name=\(query)"
        guard let requestUrl = URL(string: url) else { return "Invalid URL" }
        let request = URLRequest(url: requestUrl)
        let task = session.dataTask(with: request)
        task.resume()
        return "Searching patients: \(query)"
    }
}

class SyncService {
    let repository: HealthRepository
    let integrationService: IntegrationService

    init(repository: HealthRepository, integrationService: IntegrationService) {
        self.repository = repository
        self.integrationService = integrationService
    }

    func syncToCloud(patientId: String) -> String {
        guard let record = repository.findById(id: patientId) else {
            return "Patient not found"
        }
        let payload = "\(record)"
        return integrationService.sendWebhook(url: "https://api.health-cloud.com/sync", payload: payload)
    }
}
