import scala.sys.process._

object Executor {
  def runInOtherFile(cmd: String): Unit = {
    // POSITIVE (cross-file)
    Seq("sh", "-c", cmd).!
  }
}
