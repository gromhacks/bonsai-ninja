import scala.io.StdIn
import scala.sys.process._

object App {
    def unsanitized(): Unit = {
        val t = StdIn.readLine()
        Seq("sh", "-c", t).!
    }
    def sanitized(): Unit = {
        val t = StdIn.readLine()
        val safe = t.replaceAll("[^A-Za-z0-9_-]", "")
        Seq("sh", "-c", safe).!
    }
}
