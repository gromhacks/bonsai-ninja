import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func runInOtherFile(cmd: String) {
    // POSITIVE (cross-file)
    system(cmd)
}
