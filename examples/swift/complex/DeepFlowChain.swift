// DeepFlowChain.swift -- Entry point: reads user command from stdin.
// Flow: stdin -> parse -> validate -> transform -> format -> execute
// 30+ steps across 3 files. All types prefixed with Dfc.

import Foundation

struct DfcRawCommand {
    var name: String
    var args: [String]
    var env: [String: String]
}

struct DfcParsedInput {
    var rawLine: String
    var tokens: [String]
    var timestamp: TimeInterval
}

func dfcReadUserInput() -> String {
    // Step 1: Read from stdin (SOURCE)
    let buffer = readLine()!
    return buffer
}

func dfcTrimInput(input: String) -> String {
    // Step 2: Trim whitespace
    let trimmed = input.trimmingCharacters(in: .whitespaces)
    return trimmed
}

func dfcSplitIntoTokens(line: String) -> [String] {
    // Step 3: Split into tokens
    let parts = line.components(separatedBy: " ")
    return parts
}

func dfcExtractCommandName(tokens: [String]) -> (String, [String]) {
    // Step 4: Extract command name from first token
    let cmdName = tokens[0]
    let remaining = Array(tokens[1...])
    return (cmdName, remaining)
}

func dfcBuildParsedInput(raw: String, tokens: [String]) -> DfcParsedInput {
    // Step 5: Build parsed input struct
    let parsed = DfcParsedInput(
        rawLine: raw,
        tokens: tokens,
        timestamp: Date().timeIntervalSince1970
    )
    return parsed
}

func dfcBuildRawCommand(name: String, args: [String]) -> DfcRawCommand {
    // Step 6: Build raw command struct
    var envMap: [String: String] = [:]
    envMap["SHELL"] = "/bin/bash"
    let cmd = DfcRawCommand(
        name: name,
        args: args,
        env: envMap
    )
    return cmd
}

func dfcAttachEnvironment(cmd: DfcRawCommand) -> DfcRawCommand {
    // Step 7: Attach environment variables to command
    var updatedEnv = cmd.env
    updatedEnv["PATH"] = "/usr/bin"
    let enriched = DfcRawCommand(
        name: cmd.name,
        args: cmd.args,
        env: updatedEnv
    )
    return enriched
}

func dfcNormalizeCommandName(cmd: DfcRawCommand) -> DfcRawCommand {
    // Step 8: Normalize the command name to lowercase
    let lowerName = cmd.name.lowercased()
    let normalized = DfcRawCommand(
        name: lowerName,
        args: cmd.args,
        env: cmd.env
    )
    return normalized
}

func dfcProcessPipeline() {
    // Orchestrate the full flow chain
    let userInput = dfcReadUserInput()                           // Step 1: SOURCE
    let trimmed = dfcTrimInput(input: userInput)                 // Step 2
    let lineCopy = trimmed
    let tokens = dfcSplitIntoTokens(line: trimmed)               // Step 3

    let (cmdName, cmdArgs) = dfcExtractCommandName(tokens: tokens) // Step 4
    let parsed = dfcBuildParsedInput(raw: lineCopy, tokens: tokens) // Step 5
    let rawCmd = dfcBuildRawCommand(name: cmdName, args: cmdArgs) // Step 6
    let envCmd = dfcAttachEnvironment(cmd: rawCmd)               // Step 7
    let normCmd = dfcNormalizeCommandName(cmd: envCmd)           // Step 8

    // Steps 9-20: Validation and transformation in helpers
    let validated = dfcValidateCommand(rawCmd: normCmd, parsed: parsed)

    // Steps 21-30+: Formatting and execution in sink
    dfcExecutePipeline(validated: validated)
}

dfcProcessPipeline()
