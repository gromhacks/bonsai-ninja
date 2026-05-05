import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func taintOneLeg(cond: Bool) {
    let x: String
    if cond { x = readLine() ?? "" }
    else { x = "safe-static" }
    system(x)
}

func taintOverwritten(cond: Bool) {
    var x = readLine() ?? ""
    x = cond ? "clean-then" : "clean-else"
    system(x)
}
