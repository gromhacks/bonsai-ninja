/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
import java.sql.DriverManager

object CompilerTests {

  // -------------------------------------------------------------------------
  // 1. BRANCH-AWARE KILL ANALYSIS
  // -------------------------------------------------------------------------

  // [NO FLOW EXPECTED] Both branches sanitize
  def branchKillBothPaths(userInput: String): Unit = {
    val cmd = if (userInput.length > 100) "default_command" else "safe_fallback"
    Runtime.getRuntime.exec(cmd) // safe
  }

  // [FLOW EXPECTED] Only one branch kills taint
  def branchKillOnePath(userInput: String): Unit = {
    var cmd = userInput
    if (cmd.length > 100) {
      cmd = "truncated"
    }
    Runtime.getRuntime.exec(cmd) // tainted
  }

  // [FLOW EXPECTED] Match without exhaustive coverage
  def branchKillMatch(userInput: String): Unit = {
    var query = userInput
    userInput.charAt(0) match {
      case 'a' => query = "SELECT * FROM a"
      case 'b' => query = "SELECT * FROM b"
      case _ => // query keeps userInput
    }
    Runtime.getRuntime.exec(query)
  }


  // -------------------------------------------------------------------------
  // 2. INTERPROCEDURAL KILL (2+ levels deep)
  // -------------------------------------------------------------------------

  private def sanitize(value: String): String =
    value.replaceAll("['\";\\-\\-]", "")

  private def wrapSanitize(value: String): String = sanitize(value)

  // [NO FLOW EXPECTED]
  def interproceduralKillDirect(userInput: String): Unit = {
    val clean = sanitize(userInput)
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().execute(s"SELECT * FROM t WHERE x = '$clean'")
  }

  // [NO FLOW EXPECTED]
  def interproceduralKillTwoLevels(userInput: String): Unit = {
    val clean = wrapSanitize(userInput)
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().execute(s"SELECT * FROM t WHERE x = '$clean'")
  }


  // -------------------------------------------------------------------------
  // 3. FIELD-SENSITIVE TRACKING
  // -------------------------------------------------------------------------

  case class Config(var command: String = "", var label: String = "")

  // [FLOW EXPECTED] Tainted field
  def fieldSensitiveTainted(userInput: String): Unit = {
    val cfg = Config(command = userInput, label = "safe")
    Runtime.getRuntime.exec(cfg.command)
  }

  // [NO FLOW EXPECTED] Safe field only
  def fieldSensitiveSafe(userInput: String): Unit = {
    val cfg = Config(command = userInput, label = "safe")
    Runtime.getRuntime.exec(cfg.label)
  }


  // -------------------------------------------------------------------------
  // 4. EXCEPTION CHAIN TAINT
  // -------------------------------------------------------------------------

  // [FLOW EXPECTED] Taint through exception
  def exceptionTaint(userInput: String): Unit = {
    try {
      throw new RuntimeException(s"Invalid: $userInput")
    } catch {
      case e: RuntimeException => Runtime.getRuntime.exec(e.getMessage)
    }
  }


  // -------------------------------------------------------------------------
  // 5. PATTERN MATCHING TAINT
  // -------------------------------------------------------------------------

  sealed trait Command
  case class Execute(cmd: String) extends Command
  case class Query(sql: String) extends Command

  // [FLOW EXPECTED] Taint through pattern match extraction
  def patternMatchTaint(userInput: String): Unit = {
    val cmd: Command = Execute(userInput)
    cmd match {
      case Execute(c) => Runtime.getRuntime.exec(c)
      case Query(_) => ()
    }
  }


  // -------------------------------------------------------------------------
  // 6. FOR-COMPREHENSION TAINT
  // -------------------------------------------------------------------------

  // [FLOW EXPECTED] Taint flows through for-comprehension
  def forComprehensionTaint(userInput: String): Unit = {
    val inputs = List(userInput, "safe")
    val result = for {
      item <- inputs
      if item.nonEmpty
    } yield item
    Runtime.getRuntime.exec(result.mkString(" "))
  }


  // -------------------------------------------------------------------------
  // 7. IMPLICIT RETURN (Scala-specific)
  // -------------------------------------------------------------------------

  // [FLOW EXPECTED] Last expression is implicit return
  def implicitReturn(userInput: String): String = {
    val processed = s"cmd: $userInput"
    processed // implicit return
  }

  def implicitReturnSink(userInput: String): Unit = {
    val cmd = implicitReturn(userInput)
    Runtime.getRuntime.exec(cmd)
  }


  // -------------------------------------------------------------------------
  // 8. PARAMETER SOURCE SYNTHESIS
  // -------------------------------------------------------------------------

  // [FLOW EXPECTED] External entry point
  def handleWebhook(payload: String, signature: String): Unit = {
    Runtime.getRuntime.exec(s"process $payload")
  }


  // -------------------------------------------------------------------------
  // 9. CROSS-METHOD CLASS FIELD TAINT
  // -------------------------------------------------------------------------

  class Pipeline {
    private var data: String = ""

    def ingest(raw: String): Unit = {
      data = raw
    }

    def process(): Unit = {
      Runtime.getRuntime.exec(data)
    }
  }

  // [FLOW EXPECTED]
  def crossMethodFieldTaint(userInput: String): Unit = {
    val p = new Pipeline()
    p.ingest(userInput)
    p.process()
  }


  // -------------------------------------------------------------------------
  // 10. OPTION MONAD TAINT
  // -------------------------------------------------------------------------

  // [FLOW EXPECTED] Taint flows through Option.map
  def optionTaint(userInput: String): Unit = {
    val maybeCmd: Option[String] = Some(userInput)
    maybeCmd.map(cmd => Runtime.getRuntime.exec(cmd))
  }
}
