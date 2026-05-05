// Receiver-type audit fixture (Scala).
// Seq("sh", "-c", tainted).! — uses sys.process implicit on Seq.
// Instance-receiver shapes (main: IMain) are a deeper gap (Task #283).
import scala.io.StdIn
import scala.sys.process._

object App {
  def handle(): Unit = {
    // POSITIVE
    val tainted = StdIn.readLine()
    Seq("sh", "-c", tainted).!
  }
}
