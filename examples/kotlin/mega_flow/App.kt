package mega

import jakarta.servlet.http.HttpServletRequest

// mega_flow Kotlin entry — reads a servlet parameter, then dispatches
// the tainted value through a pipeline that exercises every idiomatic
// Kotlin flow construct (data classes, sealed hierarchies, when,
// scope functions, lambdas, extension functions, null-safety, elvis).
class App {
    enum class Kind { RUN, EVAL }

    data class Envelope(
        val kind: Kind,
        val cmd: String,
        val user: String,
        val length: Int,
        val extras: List<String>,
    )

    // SOURCE — HttpServletRequest.getParameter.
    fun handle(req: HttpServletRequest): String {
        val raw = req.getParameter("cmd") ?: ""
        val user = req.getHeader("X-User") ?: "anon"

        val envelope = Envelope(
            kind = Kind.RUN,
            cmd = "$raw",
            user = user,
            length = raw.length,
            extras = listOf(raw),
        )

        return Pipeline.orchestrate(envelope)
    }
}
