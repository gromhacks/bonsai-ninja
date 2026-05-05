import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let CONST_OK = "ls /tmp"

func decoy() {
    let _unused = readLine()
    system(CONST_OK)
}

func unrelatedChain() -> String {
    let a = "hello"
    return a.uppercased()
}
