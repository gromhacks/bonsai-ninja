// Assignment-chain audit fixture (Swift).
// Uses readLine() as source (swift.cli.readline) + system() as
// cmdi sink (swift.cmdi.system_libc). ProcessInfo subscript-read
// + Process field-write chain is a separate adapter audit.
import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let CONST_OK = "ls /tmp"

func passthrough(_ x: String) -> String { return x }
func wrap(_ x: String) -> String { return "wrapped:" + x }
func combine(_ acc: String, _ item: String) -> String { return acc + ":" + item }

class Bag {
    var payload: String = ""
}

func chainSimple() {
    // POSITIVE
    if let tmp = readLine() {
        system(tmp)
    }
}

func chainMultiHop() {
    // POSITIVE
    guard let t1 = readLine() else { return }
    let t2 = passthrough(t1)
    let t3 = wrap(t2)
    let t4 = passthrough(t3)
    system(t4)
}

func chainBranchJoin(cond: Bool) {
    // POSITIVE
    let t: String
    if cond {
        t = readLine() ?? ""
    } else {
        t = "safe-static"
    }
    system(t)
}

func chainLoopCarried(items: [String]) {
    // POSITIVE
    var acc = readLine() ?? ""
    for item in items {
        acc = combine(acc, item)
    }
    system(acc)
}

func chainFieldWrite() {
    // POSITIVE
    let bag = Bag()
    bag.payload = readLine() ?? ""
    system(bag.payload)
}

func chainSubscriptWrite() {
    // POSITIVE
    var cmds: [String: String] = [:]
    cmds["x"] = readLine() ?? ""
    system(cmds["x"]!)
}

func chainCleanConstant() {
    // NEGATIVE
    let _ = readLine()
    system(CONST_OK)
}

func chainCrossFile() {
    // POSITIVE
    let t = readLine() ?? ""
    runInOtherFile(cmd: t)
}
