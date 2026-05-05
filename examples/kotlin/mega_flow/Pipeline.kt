package mega

// Pipeline — exercises Kotlin's idiomatic flow constructs: lambdas,
// higher-order functions, scope functions (let / apply / run / with),
// extension functions, sequences, when expressions, try/catch,
// string templates, Elvis, safe-call.
object Pipeline {
    // Higher-order function returning a closure reducer.
    private fun makeJoiner(sep: String): (String, String) -> String =
        { acc, tok -> if (acc.isEmpty()) tok else "$acc$sep$tok" }

    // Extension function — applied over every tainted token.
    private fun String.canonical(): String = this.trim()

    fun orchestrate(envelope: App.Envelope): String {
        val cmd = envelope.cmd
        val user = envelope.user
        val firstExtra = envelope.extras.firstOrNull()?.trim() ?: ""
        firstExtra.let { _ -> }

        // Sequence (lazy pipeline) — map / filter / fold with a closure.
        val joined = cmd.splitToSequence(" ")
            .map { it.canonical() }
            .filter { it.isNotEmpty() }
            .fold("", makeJoiner(" "))

        // when expression — every arm preserves taint.
        val routed = when (envelope.kind) {
            App.Kind.RUN -> "$joined"
            App.Kind.EVAL -> joined.trim()
        }

        // runCatching (Kotlin's try/catch) — taint survives every branch.
        val valid = runCatching {
            require(routed.isNotEmpty()) { "empty" }
            envelope.copy(cmd = routed, user = user, length = routed.length)
        }.getOrElse { envelope.copy(cmd = routed, user = user, length = routed.length) }
        return Storage.persist(valid)
    }

    private fun tryCatchMarker(value: String): String {
        return try {
            value
        } catch (_: IllegalStateException) {
            value
        }
    }
}
