import Foundation

// Health Records API - Security Middleware
// Sanitizers, validators, auth helpers
// These functions break taint chains when used properly

class SecurityMiddleware {
    static func escapeHtml(_ input: String) -> String {
        return input
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#x27;")
    }

    static func sanitizeSql(_ input: String) -> String {
        return input
            .replacingOccurrences(of: "'", with: "''")
            .replacingOccurrences(of: "\\", with: "\\\\")
    }

    static func isValidEmail(_ email: String) -> Bool {
        let pattern = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$"
        return email.range(of: pattern, options: .regularExpression) != nil
    }

    static func isValidIdentifier(_ id: String) -> Bool {
        let pattern = "^[A-Za-z0-9_-]+$"
        return id.range(of: pattern, options: .regularExpression) != nil
    }

    static func sanitizeFilename(_ filename: String) -> String {
        return (filename as NSString).lastPathComponent
            .replacingOccurrences(of: "[^a-zA-Z0-9._-]", with: "", options: .regularExpression)
    }

    static func isValidUrl(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString) else { return false }
        let blocked = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"]
        guard let host = url.host else { return false }
        if blocked.contains(host) { return false }
        guard let scheme = url.scheme, ["http", "https"].contains(scheme) else { return false }
        return true
    }

    static func hashPassword(_ password: String) -> String {
        let salt = UUID().uuidString
        guard let data = (salt + password).data(using: .utf8) else { return "" }
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { bytes in
            _ = bytes
        }
        return "\(salt):\(Data(hash).base64EncodedString())"
    }

    static func generateToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
    }

    static func verifyToken(_ token: String, expected: String) -> Bool {
        guard token.count == expected.count else { return false }
        var result: UInt8 = 0
        for (a, b) in zip(token.utf8, expected.utf8) {
            result |= a ^ b
        }
        return result == 0
    }

    static func sanitizeShellArg(_ input: String) -> String {
        return input.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    }

    static func sanitizeXmlInput(_ input: String) -> String {
        return input
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}

class RateLimiter {
    private var requests: [String: [TimeInterval]] = [:]
    let maxRequests: Int
    let windowSeconds: TimeInterval

    init(maxRequests: Int = 100, windowSeconds: TimeInterval = 60) {
        self.maxRequests = maxRequests
        self.windowSeconds = windowSeconds
    }

    func allow(key: String) -> Bool {
        let now = Date().timeIntervalSince1970
        let windowStart = now - windowSeconds
        var timestamps = requests[key] ?? []
        timestamps = timestamps.filter { $0 > windowStart }
        if timestamps.count >= maxRequests {
            return false
        }
        timestamps.append(now)
        requests[key] = timestamps
        return true
    }
}

class TokenManager {
    let secret: String

    init(secret: String) {
        self.secret = secret
    }

    func generateJWT(payload: [String: Any]) -> String {
        let header = Data("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".utf8).base64EncodedString()
        let payloadStr = "\(payload)"
        let body = Data(payloadStr.utf8).base64EncodedString()
        let signature = hmacSign(data: "\(header).\(body)")
        return "\(header).\(body).\(signature)"
    }

    func verifyJWT(token: String) -> [String: Any]? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        let headerBody = "\(parts[0]).\(parts[1])"
        let signature = String(parts[2])
        let expected = hmacSign(data: headerBody)
        guard SecurityMiddleware.verifyToken(signature, expected: expected) else { return nil }
        guard let data = Data(base64Encoded: String(parts[1])) else { return nil }
        return ["payload": String(data: data, encoding: .utf8) ?? ""]
    }

    private func hmacSign(data: String) -> String {
        return Data((data + secret).utf8).base64EncodedString()
    }
}
