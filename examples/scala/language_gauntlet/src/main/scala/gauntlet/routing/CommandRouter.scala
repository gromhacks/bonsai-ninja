package gauntlet.routing

import gauntlet.app.App
import gauntlet.app.App.Envelope
import gauntlet.pipeline.Pipeline
import scala.concurrent.{ExecutionContext, Future}

type RouteCallback = Envelope => String

def startPipeline(initial: App.Envelope): String = Pipeline.orchestrate(initial)

/** Nested-package bridge deliberately kept on the critical dataflow path. */
final class CommandRouter(initial: Envelope) {
  private var current: Envelope = initial

  private def snapshot(): Envelope = current.copy(cmd = current.cmd)

  def route(): Envelope = {
    var routed = snapshot()
    for attempt <- 0 until 2 do
      routed =
        if attempt == 0 then routed.copy(cmd = routed.cmd)
        else
          current = routed
          current
    routed
  }

  def dispatch(next: RouteCallback): String = next(route())

  // Future-based syntax exercises the idiomatic async callable shape without
  // making the deterministic command-line gauntlet depend on a scheduler.
  def dispatchAsync(next: RouteCallback)(using ExecutionContext): Future[String] =
    Future(dispatch(next))
}
