// DeepFlowSink.swift -- Final stage: formatting + execution.
// Steps 21-32 of the taint flow. All types prefixed with Dfc.

import Foundation

struct DfcExecutionRequest {
    var program: String
    var programArgs: [String]
    var logEntry: String
}

class DfcProcessFormatter {
    let baseProgram: String
    var formattedArgs: [String]

    init(executable: String) {
        self.baseProgram = executable
        self.formattedArgs = []
    }

    func addArguments(args: [String]) {
        for arg in args { formattedArgs.append(arg) }
    }

    func getProgram() -> String { return baseProgram }
    func getArgs() -> [String] { return formattedArgs }
}

func dfcCreateLogEntry(program: String, args: [String], original: String) -> String {
    let argsStr = args.joined(separator: ", ")
    let log = "Executing: \(program) with args [\(argsStr)] from input: \(original)"
    return log
}

func dfcBuildExecutionRequest(program: String, args: [String], log: String) -> DfcExecutionRequest {
    let request = DfcExecutionRequest(program: program, programArgs: args, logEntry: log)
    return request
}

func dfcExtractProgram(request: DfcExecutionRequest) -> String {
    let prog = request.program
    return prog
}

func dfcExtractArgs(request: DfcExecutionRequest) -> [String] {
    let args = request.programArgs
    return args
}

func dfcSpawnCommand(program: String, args: [String]) -> Int32 {
    // SINK: command injection via Process with launchPath
    let process = Process()
    process.executableURL = URL(fileURLWithPath: program)
    process.arguments = args

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        print("Failed to launch process")
    }
    return process.terminationStatus
}

func dfcExecutePipeline(validated: DfcValidatedCommand) {
    let exec = validated.executable
    let args = validated.arguments
    let original = validated.metadata.originalInput

    let formatter = DfcProcessFormatter(executable: exec)
    formatter.addArguments(args: args)

    let program = formatter.getProgram()
    let finalArgs = formatter.getArgs()

    let log = dfcCreateLogEntry(program: program, args: finalArgs, original: original)
    let request = dfcBuildExecutionRequest(program: program, args: finalArgs, log: log)

    let prog = dfcExtractProgram(request: request)
    let cmdArgs = dfcExtractArgs(request: request)
    let code = dfcSpawnCommand(program: prog, args: cmdArgs)
    print("Exited with code \(code)")
}
