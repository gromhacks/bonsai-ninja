import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func taintedThroughTry() {
    var t = ""
    do {
        t = readLine() ?? ""
    } catch {
        t = ""
    }
    system(t)
}
