package mega

import jakarta.servlet.http.HttpServletRequest

// mega_flow Scala entry — reads a servlet parameter, then dispatches
// the tainted value through a pipeline that exercises every idiomatic
// Scala flow construct (case classes, Option, for-comprehensions,
// pattern matching, traits, currying, partial functions).
object App {
  enum Kind:
    case Run, Eval

  case class Envelope(kind: Kind, cmd: String, user: String, length: Int, extras: List[String])
}

class App {
  // SOURCE — HttpServletRequest.getParameter.
  def handle(req: HttpServletRequest): String = {
    val raw = Option(req.getParameter("cmd")).getOrElse("")
    val user = Option(req.getHeader("X-User")).getOrElse("anon")

    val envelope = App.Envelope(
      kind = App.Kind.Run,
      cmd = s"$raw",
      user = user,
      length = raw.length,
      extras = List(raw),
    )

    Pipeline.orchestrate(envelope)
  }
}
