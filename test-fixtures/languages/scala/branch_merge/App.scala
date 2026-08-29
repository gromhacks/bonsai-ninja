import scala.io.StdIn
import scala.sys.process._

object App {
    def taintOneLeg(cond: Boolean): Unit = {
        val x = if (cond) StdIn.readLine() else "safe-static"
        Seq("sh", "-c", x).!
    }
    def taintOverwritten(cond: Boolean): Unit = {
        var x = StdIn.readLine()
        x = if (cond) "clean-then" else "clean-else"
        Seq("sh", "-c", x).!
    }
}
