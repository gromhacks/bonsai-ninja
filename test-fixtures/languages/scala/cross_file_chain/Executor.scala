import scala.sys.process._

object Executor {
  def execute(cmd: String): Unit = {
    // POSITIVE (terminal cross-file sink)
    Seq("sh", "-c", cmd).!
  }
}
