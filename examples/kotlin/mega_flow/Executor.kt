package mega

object Executor {
    // SINK — Runtime.exec · kotlin.cmdi.runtime_exec · CWE-78
    fun execute(cmd: String): String {
        Runtime.getRuntime().exec(cmd)
        return cmd
    }

    fun cleanTwin(): String {
        // NEGATIVE — same sink kind with a constant argument must not report.
        Runtime.getRuntime().exec("echo clean")
        return "clean"
    }
}
