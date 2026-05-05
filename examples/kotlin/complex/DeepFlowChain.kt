package com.pipeline.entry

// DeepFlowChain.kt -- Entry point for deep cross-file flow chain.
// All type/function names prefixed with Dfc.

annotation class DfcAudited

object DfcCommandParser {
    fun tokenize(input: String): List<String> {
        val tokens = input.trim().split("\\s+".toRegex())
        return tokens
    }

    fun extractAction(tokens: List<String>): String {
        if (tokens.isEmpty()) return ""
        var action = tokens[0]
        for (i in 1 until tokens.size) {
            action = action + " " + tokens[i]
        }
        return action
    }
}

object DfcInputValidator {
    fun validateLength(input: String): String {
        var validated = input
        if (validated.length > 4096)
            validated = validated.substring(0, 4096)
        return validated
    }

    fun normalizeWhitespace(input: String): String {
        val normalized = input.trim().replace("\\s+".toRegex(), " ")
        return normalized
    }
}

data class DfcRequestContext(
    val action: String,
    val origin: String,
    val metadata: MutableMap<String, String> = mutableMapOf()
)

@DfcAudited
fun main() {
    // SOURCE: user-controlled stdin input
    val rawInput = readLine() ?: return

    val tokens = DfcCommandParser.tokenize(rawInput)
    val action = DfcCommandParser.extractAction(tokens)
    val validated = DfcInputValidator.validateLength(action)
    val normalized = DfcInputValidator.normalizeWhitespace(validated)

    val ctx = DfcRequestContext(normalized, "cli")

    // Cross to helpers
    val registry = DfcPipelineRegistry()
    registry.register("default", ctx)
    val registeredCtx = registry.lookup("default")

    val prefixed = DfcTransformStage.applyPrefix(registeredCtx!!)
    val wrapped = DfcTransformStage.wrapInQuotes(prefixed)

    val assembler = DfcCommandAssembler()
    assembler.setPayload(wrapped)
    assembler.setTarget("/bin/sh")
    val assembled = assembler.assemble()

    val formatted = DfcOutputFormatter.formatForShell(assembled)

    // Cross to sink
    val executor = DfcCommandExecutor()
    val prepared = executor.prepare(formatted)
    val finalCommand = executor.constructCommand(prepared)

    val execCtx = DfcExecutionContext()
    execCtx.setCommand(finalCommand)
    val cmdToRun = execCtx.getCommand()

    DfcAuditLogger.logPreExecution(cmdToRun)

    val launcher = DfcProcessLauncher()
    launcher.createProcess(cmdToRun)
    launcher.configureEnvironment()
    launcher.launch()  // SINK: Runtime.exec
}
