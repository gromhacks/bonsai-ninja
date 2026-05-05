package mega

import scala.sys.process._

object Executor {
  // SINK — scala.sys.process run · scala.cmdi.process_run · CWE-78
  def execute(cmd: String): String = {
    cmd.!
    cmd
  }

  def cleanTwin(): String = {
    // NEGATIVE — same sink kind with a constant argument must not report.
    "echo clean".!
    "clean"
  }
}
