package mega

import scala.util.{Try, Success, Failure}
import mega.Storage as Store

// Pipeline — exercises Scala's idiomatic flow constructs: higher-order
// functions, currying, for-comprehensions, pattern matching, Try,
// traits, lazy val, foldLeft.
object Pipeline {
  // Curried closure factory — returns a reducer that joins tokens.
  private def makeJoiner(sep: String)(acc: String, tok: String): String =
    if (acc.isEmpty) tok else s"$acc$sep$tok"

  def orchestrate(envelope: App.Envelope): String = {
    val cmd = envelope.cmd
    val user = envelope.user

    // Collection pipeline: iterator + map + filter + foldLeft.
    lazy val joined: String = cmd.split(" ").iterator
      .map(_.trim)
      .filter(_.nonEmpty)
      .foldLeft("")(makeJoiner(" "))

    val routedInput = (for value <- Option(joined) yield value).getOrElse(joined)

    // Pattern match — every arm preserves taint.
    val routed: String = envelope.kind match {
      case App.Kind.Run  => s"$routedInput"
      case App.Kind.Eval => routedInput.trim
    }

    // Try monad (Scala's try/catch) — taint survives every branch.
    val valid: App.Envelope = Try {
      require(routed.nonEmpty, "empty")
      envelope.copy(cmd = routed, user = user, length = routed.length)
    } match {
      case Success(v) => v
      case Failure(_) => envelope.copy(cmd = routed, user = user, length = routed.length)
    }

    Store.persist(valid)
  }
}
