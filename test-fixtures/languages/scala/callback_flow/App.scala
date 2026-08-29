import scala.io.StdIn
object App {
    def executor(cmd: String): Unit = { Runtime.getRuntime.exec(cmd) }
    def runCb(cb: String => Unit, value: String): Unit = { cb(value) }
    def passToCallback(): Unit = {
        val t = StdIn.readLine()
        runCb(executor, t)
    }
}
