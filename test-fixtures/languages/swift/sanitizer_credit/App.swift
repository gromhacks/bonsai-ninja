import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func unsanitized() {
    let t = readLine() ?? ""
    system(t)
}

func sanitized() {
    let t = readLine() ?? ""
    let safe = t.replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "", options: .regularExpression)
    system(safe)
}
