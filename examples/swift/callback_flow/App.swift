import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func executor(_ cmd: String) {
    system(cmd)
}

func runCb(_ cb: (String) -> Void, _ value: String) {
    cb(value)
}

func passToCallback() {
    let t = readLine() ?? ""
    runCb(executor, t)
}
