package com.pipeline.entry

annotation class DfcWrappedAudited

class DecoratedDeepFlowEntry {
    @DfcWrappedAudited
    fun runDecorated(rawInput: String) {
        val tokens = DfcCommandParser.tokenize(rawInput)
        val action = DfcCommandParser.extractAction(tokens)
        val validated = DfcInputValidator.validateLength(action)
        val normalized = DfcInputValidator.normalizeWhitespace(validated)

        val ctx = DfcRequestContext(normalized, "cli")
        val registry = DfcPipelineRegistry()
        registry.register("default", ctx)
        val registeredCtx = registry.lookup("default") ?: return

        val prefixed = DfcTransformStage.applyPrefix(registeredCtx)
        val wrapped = DfcTransformStage.wrapInQuotes(prefixed)

        val assembler = DfcCommandAssembler()
        assembler.setPayload(wrapped)
        assembler.setTarget("/bin/sh")
        val assembled = assembler.assemble()

        val formatted = DfcOutputFormatter.formatForShell(assembled)

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
        launcher.launch()
    }
}
