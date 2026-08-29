/// Compiler architecture test cases for the tree-sitter-sast flow engine.
///
/// Each section tests a specific capability with both positive (flow expected)
/// and negative (no flow expected) scenarios.

import Foundation

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

/// [NO FLOW EXPECTED] Both branches sanitize
func branchKillBothPaths(userInput: String) {
    let cmd: String
    if userInput.count > 100 {
        cmd = "default_command"
    } else {
        cmd = "safe_fallback"
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cmd)
    try? process.run() // safe
}

/// [FLOW EXPECTED] Only one branch kills taint
func branchKillOnePath(userInput: String) {
    var cmd = userInput
    if cmd.count > 100 {
        cmd = "truncated"
    }
    // else: cmd still holds userInput
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cmd)
    try? process.run() // tainted
}

/// [FLOW EXPECTED] Switch without exhaustive kill
func branchKillSwitch(userInput: String) {
    var query = userInput
    switch query.first {
    case "a":
        query = "SELECT * FROM a"
    case "b":
        query = "SELECT * FROM b"
    default:
        break // query keeps userInput
    }
    let process = Process()
    process.arguments = ["-c", query]
    try? process.run()
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

func sanitize(_ value: String) -> String {
    return value.replacingOccurrences(of: "'", with: "")
        .replacingOccurrences(of: ";", with: "")
        .replacingOccurrences(of: "--", with: "")
}

func wrapSanitize(_ value: String) -> String {
    return sanitize(value)
}

/// [NO FLOW EXPECTED] Sanitizer applied
func interproceduralKillDirect(userInput: String) {
    let clean = sanitize(userInput)
    let query = "SELECT * FROM t WHERE x = '\(clean)'"
    let process = Process()
    process.arguments = ["-c", query]
    try? process.run()
}

/// [NO FLOW EXPECTED] Sanitizer 2 levels deep
func interproceduralKillTwoLevels(userInput: String) {
    let clean = wrapSanitize(userInput)
    let query = "SELECT * FROM t WHERE x = '\(clean)'"
    let process = Process()
    process.arguments = ["-c", query]
    try? process.run()
}

/// [FLOW EXPECTED] No sanitizer
func interproceduralNoKill(userInput: String) {
    let query = "SELECT * FROM t WHERE x = '\(userInput)'"
    let process = Process()
    process.arguments = ["-c", query]
    try? process.run()
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

struct Config {
    var command: String
    var label: String
}

/// [FLOW EXPECTED] Tainted field
func fieldSensitiveTainted(userInput: String) {
    let cfg = Config(command: userInput, label: "safe")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cfg.command)
    try? process.run()
}

/// [NO FLOW EXPECTED] Safe field only
func fieldSensitiveSafe(userInput: String) {
    let cfg = Config(command: userInput, label: "safe")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cfg.label)
    try? process.run()
}

/// [NO FLOW EXPECTED] Tainted field overwritten
func fieldSensitiveOverwrite(userInput: String) {
    var cfg = Config(command: userInput, label: "")
    cfg.command = "hardcoded_safe"
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cfg.command)
    try? process.run()
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT (do-catch)
// ---------------------------------------------------------------------------

enum AppError: Error {
    case invalidInput(String)
}

/// [FLOW EXPECTED] Taint through error
func exceptionTaint(userInput: String) {
    do {
        throw AppError.invalidInput(userInput)
    } catch AppError.invalidInput(let msg) {
        let process = Process()
        process.arguments = ["-c", msg]
        try? process.run() // tainted
    } catch {
        // ignore
    }
}


// ---------------------------------------------------------------------------
// 5. GUARD-LET TAINT (Swift-specific)
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Taint flows through guard let
func guardLetTaint(userInput: String?) {
    guard let cmd = userInput else { return }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cmd)
    try? process.run()
}


// ---------------------------------------------------------------------------
// 6. IMPLICIT RETURN (Swift-specific)
// ---------------------------------------------------------------------------

func processInput(_ userInput: String) -> String {
    "cmd: \(userInput)" // implicit return
}

/// [FLOW EXPECTED] Implicit return carries taint
func implicitReturnSink(userInput: String) {
    let cmd = processInput(userInput)
    let process = Process()
    process.arguments = ["-c", cmd]
    try? process.run()
}


// ---------------------------------------------------------------------------
// 7. PROTOCOL DISPATCH (Swift polymorphism)
// ---------------------------------------------------------------------------

protocol Executor {
    func execute(_ cmd: String)
}

class SafeExecutor: Executor {
    func execute(_ cmd: String) {
        print("Would execute: \(cmd)") // safe
    }
}

class UnsafeExecutor: Executor {
    func execute(_ cmd: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cmd)
        try? process.run() // dangerous
    }
}

/// [FLOW EXPECTED]
func typeTrackedUnsafe(userInput: String) {
    let executor: Executor = UnsafeExecutor()
    executor.execute(userInput)
}

/// [NO FLOW EXPECTED]
func typeTrackedSafe(userInput: String) {
    let executor: Executor = SafeExecutor()
    executor.execute(userInput)
}


// ---------------------------------------------------------------------------
// 8. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] External entry point
func handleWebhook(payload: String, signature: String) {
    let process = Process()
    process.arguments = ["-c", "process \(payload)"]
    try? process.run()
}


// ---------------------------------------------------------------------------
// 9. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    private var data: String = ""

    func ingest(raw: String) {
        data = raw
    }

    func process() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: data)
        try? proc.run()
    }
}

/// [FLOW EXPECTED]
func crossMethodFieldTaint(userInput: String) {
    let p = Pipeline()
    p.ingest(raw: userInput)
    p.process()
}


// ---------------------------------------------------------------------------
// 10. CLOSURE TAINT
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Closure captures tainted value
func closureTaint(userInput: String) {
    let execute = { (cmd: String) in
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cmd)
        try? process.run()
    }
    execute(userInput)
}


// ---------------------------------------------------------------------------
// 11. OPTIONAL CHAINING
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Taint flows through optional chain
func optionalChainTaint(userInput: String?) {
    let cmd = userInput ?? "default"
    let process = Process()
    process.arguments = ["-c", cmd]
    try? process.run()
}


// ---------------------------------------------------------------------------
// 12. STRING INTERPOLATION CHAIN
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Taint in string interpolation
func interpolationChain(userInput: String) {
    let query = "SELECT * FROM users WHERE name = '\(userInput)'"
    let process = Process()
    process.arguments = ["-c", query]
    try? process.run()
}
