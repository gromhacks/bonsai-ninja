package gauntlet.routing

import gauntlet.domain.Envelope
import gauntlet.pipeline.Pipeline
import java.util.concurrent.CompletableFuture

typealias RouteCallback = (Envelope) -> String

fun startPipeline(initial: Envelope): String = Pipeline.orchestrate(initial)

fun routeEnvelope(initial: Envelope): Envelope = CommandRouter(initial).route()

/**
 * Nested-package bridge on the source-to-sink path. The mutable receiver field,
 * copy return, loop, branch, and callback invocation are all intentional
 * compiler-flow probes.
 */
class CommandRouter(initial: Envelope) {
    private var current: Envelope = initial

    private fun snapshot(): Envelope = current.copy(cmd = current.cmd)

    fun route(): Envelope {
        var routed = snapshot()
        for (attempt in 0 until 2) {
            routed = if (attempt == 0) {
                routed.copy(cmd = routed.cmd)
            } else {
                current = routed
                current
            }
        }
        return routed
    }

    fun dispatch(next: RouteCallback): String = next(route())

    // Async syntax belongs in the language gauntlet even though the main
    // deterministic path uses dispatch directly.
    fun dispatchAsync(next: RouteCallback): CompletableFuture<String> =
        CompletableFuture.supplyAsync { dispatch(next) }
}
