import scala.io.StdIn
import scala.sys.process._

object App {
    def executor(cmd: String): Unit = { Seq("sh", "-c", cmd).! }
    def runCb(cb: String => Unit, value: String): Unit = { cb(value) }
    def passToCallback(): Unit = {
        val t = StdIn.readLine()
        runCb(executor, t)
    }
}
