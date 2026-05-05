// Receiver-type audit fixture (Swift).
// system() is a free function (no receiver) — simplest case.
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func handle() {
    // POSITIVE
    let tainted = readLine() ?? ""
    system(tainted)
}
