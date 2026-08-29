// Cross-file argument flow audit fixture (Scala).
import scala.io.StdIn

object App {
  def handler(): Unit = {
    // POSITIVE
    val user = StdIn.readLine()
    Pipeline.runPipeline(user)
  }

  def handlerSplit(): Unit = {
    // POSITIVE
    val user = StdIn.readLine()
    val flag = StdIn.readLine()
    Pipeline.runPipeline(s"$user:$flag")
  }
}
