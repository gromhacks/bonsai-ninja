import scala.io.StdIn
import scala.sys.process._

object App {
    def taintedThroughTry(): Unit = {
        val t = try {
            StdIn.readLine()
        } catch {
            case _: Throwable => ""
        }
        Seq("sh", "-c", t).!
    }
}
