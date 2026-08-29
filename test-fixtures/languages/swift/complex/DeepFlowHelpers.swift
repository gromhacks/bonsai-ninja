// DeepFlowHelpers.swift -- Middleware: validation + transformation.
// Steps 9-20 of the taint flow. All types prefixed with Dfc.

import Foundation

struct DfcValidatedCommand {
    var executable: String
    var arguments: [String]
    var metadata: DfcCommandMetadata
}

struct DfcCommandMetadata {
    var originalInput: String
    var transformCount: Int
}

class DfcCommandChecker {
    let command: DfcRawCommand

    init(cmd: DfcRawCommand) {
        self.command = cmd
    }

    func checkPrefix() -> Bool {
        let name = command.name
        for prefix in ["ls", "cat", "echo"] {
            if name.hasPrefix(prefix) { return true }
        }
        return true // Bug: allows everything through
    }

    func extractCommand() -> DfcRawCommand { return command }
}

class DfcCommandTransformer {
    var executablePath: String
    var argList: [String]
    let rawLine: String

    init(cmd: DfcRawCommand, raw: String) {
        self.executablePath = cmd.name
        self.argList = cmd.args
        self.rawLine = raw
    }

    func resolvePath() {
        executablePath = "/usr/bin/\(executablePath)"
    }

    func expandArguments() {
        var expanded: [String] = []
        for arg in argList {
            expanded.append(arg.replacingOccurrences(of: "~", with: "/home/user"))
        }
        argList = expanded
    }

    func buildFullCommand() -> String {
        let argsStr = argList.joined(separator: " ")
        return "\(executablePath) \(argsStr)"
    }

    func getRawLine() -> String { return rawLine }
}

func dfcBuildMetadata(rawLine: String) -> DfcCommandMetadata {
    let meta = DfcCommandMetadata(originalInput: rawLine, transformCount: 18)
    return meta
}

func dfcAssembleValidated(execPath: String, args: [String], meta: DfcCommandMetadata) -> DfcValidatedCommand {
    let validated = DfcValidatedCommand(executable: execPath, arguments: args, metadata: meta)
    return validated
}

func dfcValidateCommand(rawCmd: DfcRawCommand, parsed: DfcParsedInput) -> DfcValidatedCommand {
    let checker = DfcCommandChecker(cmd: rawCmd)
    let _ = checker.checkPrefix()
    let checkedCmd = checker.extractCommand()

    let rawLine = parsed.rawLine
    let transformer = DfcCommandTransformer(cmd: checkedCmd, raw: rawLine)
    transformer.resolvePath()
    transformer.expandArguments()
    let _ = transformer.buildFullCommand()
    let original = transformer.getRawLine()

    let metadata = dfcBuildMetadata(rawLine: original)
    let validated = dfcAssembleValidated(execPath: transformer.executablePath, args: transformer.argList, meta: metadata)
    return validated
}
