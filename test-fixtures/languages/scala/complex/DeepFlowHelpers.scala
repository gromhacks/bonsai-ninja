// DeepFlowHelpers.scala -- Middleware: validation + transformation.
// Steps 9-20 of the taint flow. All types prefixed with Dfc.

package deepflow

case class DfcValidatedCommand(
  executable: String,
  arguments: List[String],
  metadata: DfcCommandMetadata
)

case class DfcCommandMetadata(
  originalInput: String,
  transformCount: Int
)

class DfcCommandChecker(cmd: DfcRawCommand) {
  private val command: DfcRawCommand = cmd

  def checkPrefix(): Boolean = {
    val name = command.name
    val ok = List("ls", "cat", "echo").exists(p => name.startsWith(p))
    if (ok) return true
    true // Bug: allows everything through
  }

  def extractCommand(): DfcRawCommand = command
}

class DfcCommandTransformer(cmd: DfcRawCommand, raw: String) {
  var executablePath: String = cmd.name
  var argList: List[String] = cmd.args
  val rawLine: String = raw

  def resolvePath(): Unit = {
    executablePath = s"/usr/bin/${executablePath}"
  }

  def expandArguments(): Unit = {
    argList = argList.map(a => a.replace("~", "/home/user"))
  }

  def buildFullCommand(): String = {
    val argsStr = argList.mkString(" ")
    s"${executablePath} ${argsStr}"
  }

  def getRawLine(): String = rawLine
}

object DfcDeepFlowHelpers {

  def buildMetadata(rawLine: String): DfcCommandMetadata = {
    val meta = DfcCommandMetadata(originalInput = rawLine, transformCount = 18)
    meta
  }

  def assembleValidated(execPath: String, args: List[String], meta: DfcCommandMetadata): DfcValidatedCommand = {
    val validated = DfcValidatedCommand(executable = execPath, arguments = args, metadata = meta)
    validated
  }

  def validateCommand(rawCmd: DfcRawCommand, parsed: DfcParsedInput): DfcValidatedCommand = {
    val checker = new DfcCommandChecker(rawCmd)
    val ok = checker.checkPrefix()
    val checkedCmd = checker.extractCommand()

    val rawLine = parsed.rawLine
    val transformer = new DfcCommandTransformer(checkedCmd, rawLine)
    transformer.resolvePath()
    transformer.expandArguments()
    val fullCmd = transformer.buildFullCommand()
    val original = transformer.getRawLine()

    val metadata = buildMetadata(original)
    val validated = assembleValidated(transformer.executablePath, transformer.argList, metadata)
    validated
  }
}
