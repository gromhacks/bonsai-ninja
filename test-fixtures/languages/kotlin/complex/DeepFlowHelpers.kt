package com.pipeline.helpers

// DeepFlowHelpers.kt -- Middleware pipeline stages. All types prefixed with Dfc.

class DfcPipelineRegistry {
    private val store = mutableMapOf<String, DfcRequestContext>()

    fun register(name: String, ctx: DfcRequestContext) {
        val updated = ctx.copy()
        updated.metadata["registered"] = "true"
        store[name] = updated
    }

    fun lookup(name: String): DfcRequestContext? {
        val found = store[name]
        return found
    }
}

object DfcTransformStage {
    fun applyPrefix(ctx: DfcRequestContext): String {
        val action = ctx.action
        val prefixed = "CMD:$action"
        return prefixed
    }

    fun wrapInQuotes(input: String): String {
        val wrapped = "\"$input\""
        return wrapped
    }
}

class DfcCommandAssembler {
    private var payload: String = ""
    private var target: String = ""

    fun setPayload(payload: String) {
        this.payload = payload
    }

    fun setTarget(target: String) {
        this.target = target
    }

    fun assemble(): String {
        val sb = StringBuilder()
        sb.append(target)
        sb.append(" -c ")
        sb.append(payload)
        val assembled = sb.toString()
        return assembled
    }
}

object DfcOutputFormatter {
    fun formatForShell(input: String): String {
        val shellFmt = input.replace("\\", "\\\\")
        return shellFmt
    }
}
