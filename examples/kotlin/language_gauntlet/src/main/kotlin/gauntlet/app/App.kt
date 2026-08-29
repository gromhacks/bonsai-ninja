package gauntlet.app

import gauntlet.domain.Envelope
import gauntlet.domain.Kind
import gauntlet.routing.startPipeline
import jakarta.servlet.http.HttpServletRequest

// language_gauntlet Kotlin entry — reads a servlet parameter, then dispatches
// the tainted value through a pipeline that exercises every idiomatic
// Kotlin flow construct (data classes, sealed hierarchies, when,
// scope functions, lambdas, extension functions, null-safety, elvis).
class App {
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

        return startPipeline(envelope)
    }
}
