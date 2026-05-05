import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func execute(cmd: String) {
    // POSITIVE (terminal cross-file sink)
    system(cmd)
}
