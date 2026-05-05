// DeepFlowSink.scala -- Final stage: formatting + execution.
// Steps 21-32 of the taint flow. All types prefixed with Dfc.

package deepflow

case class DfcExecutionRequest(
  program: String,
  programArgs: List[String],
  logEntry: String
)

case class DfcExecutionResult(
  exitCode: Int,
  commandRun: String
)

class DfcCommandFormatter(executable: String) {
  // Step 21: Create formatter with executable
  val baseProgram: String = executable
  var formattedArgs: List[String] = List.empty

  def addArguments(args: List[String]): Unit = {
    // Step 22: Add arguments to formatter
    formattedArgs = formattedArgs ++ args
  }

  def prependVerboseFlag(): Unit = {
    // Step 23: Add verbose flag
    formattedArgs = "-v" :: formattedArgs
  }

  def getProgram(): String = {
    // Step 24: Get the program path
    baseProgram
  }

  def getArgs(): List[String] = {
    // Step 25: Get formatted arguments
    formattedArgs
  }
}

object DfcDeepFlowSink {

  def createLogEntry(program: String, args: List[String], original: String): String = {
    // Step 26: Create log entry with original input embedded
    val argsStr = args.mkString(", ")
    val log = s"Executing: ${program} with args [${argsStr}] from input: ${original}"
    log
  }

  def buildExecutionRequest(program: String, args: List[String], log: String): DfcExecutionRequest = {
    // Step 27: Build the execution request
    val request = DfcExecutionRequest(
      program = program,
      programArgs = args,
      logEntry = log
    )
    request
  }

  def extractProgram(request: DfcExecutionRequest): String = {
    // Step 28: Extract program from request
    val prog = request.program
    prog
  }

  def extractArgs(request: DfcExecutionRequest): List[String] = {
    // Step 29: Extract args from request
    val args = request.programArgs
    args
  }

  def spawnCommand(program: String, args: List[String]): DfcExecutionResult = {
    // Step 30: Spawn the command (SINK - command injection)
    val cmdArray = (program :: args).toArray
    val process = Runtime.getRuntime.exec(cmdArray)
    val code = process.waitFor()

    // Step 31: Build result
    val cmdStr = s"${program} ${args.mkString(" ")}"
    val result = DfcExecutionResult(
      exitCode = code,
      commandRun = cmdStr
    )
    result
  }

  def reportResult(result: DfcExecutionResult): Unit = {
    // Step 32: Report execution result
    val msg = s"Command '${result.commandRun}' exited with code ${result.exitCode}"
    println(msg)
  }

  def executePipeline(validated: DfcValidatedCommand): Unit = {
    // Orchestrate steps 21-32
    val exec = validated.executable
    val args = validated.arguments
    val original = validated.metadata.originalInput

    val formatter = new DfcCommandFormatter(exec)        // Step 21
    formatter.addArguments(args)                          // Step 22
    formatter.prependVerboseFlag()                        // Step 23

    val program = formatter.getProgram()                  // Step 24
    val finalArgs = formatter.getArgs()                   // Step 25

    val log = createLogEntry(program, finalArgs, original) // Step 26

    val request = buildExecutionRequest(program, finalArgs, log) // Step 27

    val prog = extractProgram(request)                    // Step 28
    val cmdArgs = extractArgs(request)                    // Step 29
    val result = spawnCommand(prog, cmdArgs)              // Step 30-31
    reportResult(result)                                  // Step 32
  }
}
