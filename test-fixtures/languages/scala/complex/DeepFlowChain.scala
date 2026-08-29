// DeepFlowChain.scala -- Entry point: reads user command from env/stdin.
// Flow: env/stdin -> parse -> validate -> transform -> format -> exec
// 30+ steps across 3 files. All types prefixed with Dfc.

package deepflow

import scala.collection.mutable
import scala.annotation.StaticAnnotation

class DfcAudited extends StaticAnnotation

case class DfcRawCommand(
  name: String,
  args: List[String],
  env: Map[String, String]
)

case class DfcParsedInput(
  rawLine: String,
  tokens: List[String],
  timestamp: Long
)

object DfcDeepFlowChain {

  def readUserInput(): String = {
    // Step 1: Read from environment (SOURCE)
    val input = System.getenv("USER_COMMAND")
    input
  }

  def trimInput(input: String): String = {
    // Step 2: Trim whitespace
    val trimmed = input.trim()
    trimmed
  }

  def splitIntoTokens(line: String): List[String] = {
    // Step 3: Split into tokens
    val parts = line.split("\\s+").toList
    parts
  }

  def extractCommandName(tokens: List[String]): (String, List[String]) = {
    // Step 4: Extract command name from first token
    val cmdName = tokens.head
    val remaining = tokens.tail
    (cmdName, remaining)
  }

  def buildParsedInput(raw: String, tokens: List[String]): DfcParsedInput = {
    // Step 5: Build parsed input
    val parsed = DfcParsedInput(
      rawLine = raw,
      tokens = tokens,
      timestamp = System.currentTimeMillis()
    )
    parsed
  }

  def buildRawCommand(name: String, args: List[String]): DfcRawCommand = {
    // Step 6: Build raw command
    val envMap = Map("SHELL" -> "/bin/bash")
    val cmd = DfcRawCommand(
      name = name,
      args = args,
      env = envMap
    )
    cmd
  }

  def attachEnvironment(cmd: DfcRawCommand): DfcRawCommand = {
    // Step 7: Attach environment variables
    val updatedEnv = cmd.env + ("PATH" -> "/usr/bin")
    val enriched = DfcRawCommand(
      name = cmd.name,
      args = cmd.args,
      env = updatedEnv
    )
    enriched
  }

  def normalizeCommandName(cmd: DfcRawCommand): DfcRawCommand = {
    // Step 8: Normalize command name to lowercase
    val lowerName = cmd.name.toLowerCase()
    val normalized = DfcRawCommand(
      name = lowerName,
      args = cmd.args,
      env = cmd.env
    )
    normalized
  }

  @DfcAudited
  def processPipeline(): Unit = {
    // Orchestrate the full flow chain
    val userInput = readUserInput()                          // Step 1: SOURCE
    val trimmed = trimInput(userInput)                       // Step 2
    val lineCopy = trimmed
    val tokens = splitIntoTokens(trimmed)                    // Step 3

    val (cmdName, cmdArgs) = extractCommandName(tokens)      // Step 4
    val parsed = buildParsedInput(lineCopy, tokens)          // Step 5
    val rawCmd = buildRawCommand(cmdName, cmdArgs)           // Step 6
    val envCmd = attachEnvironment(rawCmd)                   // Step 7
    val normCmd = normalizeCommandName(envCmd)               // Step 8

    // Steps 9-20: Validation and transformation in helpers
    val validated = DfcDeepFlowHelpers.validateCommand(normCmd, parsed)

    // Steps 21-30+: Formatting and execution in sink
    DfcDeepFlowSink.executePipeline(validated)
  }

  def main(args: Array[String]): Unit = {
    processPipeline()
  }
}
