import scala.io.StdIn
import scala.sys.process._

object App {
    val CONST_OK = "ls /tmp"
    def decoy(): Unit = {
        val _unused = StdIn.readLine()
        Seq("sh", "-c", CONST_OK).!
    }
    def unrelatedChain(): String = "hello".toUpperCase
}
