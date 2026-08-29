package com.pipeline.sink

// DeepFlowSink.kt -- Final execution stage. All types prefixed with Dfc.

class DfcCommandExecutor {
    fun prepare(input: String): String {
        var prepared = input.trim()
        if (prepared.startsWith("#!")) {
            val newline = prepared.indexOf('\n')
            if (newline > 0) prepared = prepared.substring(newline + 1)
        }
        return prepared
    }

    fun constructCommand(prepared: String): String {
        val parts = prepared.split("\\s+".toRegex(), limit = 2)
        val command = if (parts.size > 1) parts[0] + " " + parts[1] else parts[0]
        return command
    }
}

class DfcExecutionContext {
    private var command: String = ""

    fun setCommand(command: String) {
        this.command = command
    }

    fun getCommand(): String {
        val cmd = this.command
        return cmd
    }
}

object DfcAuditLogger {
    private val auditLog = mutableListOf<String>()

    fun logPreExecution(command: String): String {
        val entry = "AUDIT[${System.currentTimeMillis()}]: $command"
        auditLog.add(entry)
        println(entry)
        val audited = command
        return audited
    }
}

class DfcProcessLauncher {
    private var commandToExecute: String = ""
    private var processBuilder: ProcessBuilder? = null

    fun createProcess(command: String) {
        this.commandToExecute = command
        val parts = command.split("\\s+".toRegex())
        processBuilder = ProcessBuilder(parts)
    }

    fun configureEnvironment() {
        val env = processBuilder?.environment()
        env?.put("LANG", "en_US.UTF-8")
        processBuilder?.redirectErrorStream(true)
    }

    fun launch() {
        try {
            // SINK: tainted data from readLine() reaches exec
            val cmd = this.commandToExecute
            Runtime.getRuntime().exec(cmd)
        } catch (e: Exception) {
            System.err.println("Execution failed: ${e.message}")
        }
    }
}
