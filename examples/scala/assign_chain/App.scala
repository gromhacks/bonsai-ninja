// Assignment-chain audit fixture (Scala).
// Uses StdIn.readLine() as source (scala.cli.stdin_readline) +
// scala.sys.process Seq.! as cmdi sink. Map subscript-read shape
// is a separate adapter audit (Task #265).
import scala.io.StdIn
import scala.sys.process._

object App {
  val CONST_OK = "ls /tmp"

  def passthrough(x: String): String = x
  def wrap(x: String): String = "wrapped:" + x
  def combine(acc: String, item: String): String = acc + ":" + item

  class Bag {
    var payload: String = ""
  }

  def chainSimple(): Unit = {
    // POSITIVE
    val tmp = StdIn.readLine()
    Seq("sh", "-c", tmp).!
  }

  def chainMultiHop(): Unit = {
    // POSITIVE
    val t1 = StdIn.readLine()
    val t2 = passthrough(t1)
    val t3 = wrap(t2)
    val t4 = passthrough(t3)
    Seq("sh", "-c", t4).!
  }

  def chainBranchJoin(cond: Boolean): Unit = {
    // POSITIVE
    val t = if (cond) StdIn.readLine() else "safe-static"
    Seq("sh", "-c", t).!
  }

  def chainLoopCarried(items: Seq[String]): Unit = {
    // POSITIVE
    var acc = StdIn.readLine()
    for (item <- items) {
      acc = combine(acc, item)
    }
    Seq("sh", "-c", acc).!
  }

  def chainFieldWrite(): Unit = {
    // POSITIVE
    val bag = new Bag()
    bag.payload = StdIn.readLine()
    Seq("sh", "-c", bag.payload).!
  }

  def chainSubscriptWrite(): Unit = {
    // POSITIVE
    val cmds = scala.collection.mutable.Map[String, String]()
    cmds("x") = StdIn.readLine()
    Seq("sh", "-c", cmds("x")).!
  }

  def chainCleanConstant(): Unit = {
    // NEGATIVE
    val _unused = StdIn.readLine()
    Seq("sh", "-c", CONST_OK).!
  }

  def chainCrossFile(): Unit = {
    // POSITIVE
    val t = StdIn.readLine()
    Executor.runInOtherFile(t)
  }
}
