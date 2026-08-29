package com.bank.app

import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement

// ---------------------------------------------------------------------------
// AdvancedPatterns.kt
//
// Self-contained file exercising Kotlin-specific syntax constructs.
// Each VULN comment describes the full taint chain from source to sink.
// ---------------------------------------------------------------------------

// -- Sealed class hierarchy used by VULN 2 (when-expression routing) --------

sealed class UserCommand {
    data class RunShell(val cmd: String) : UserCommand()
    data class QueryDb(val sql: String) : UserCommand()
    data class WriteFile(val path: String, val content: String) : UserCommand()
    object Noop : UserCommand()
}

// -- Data class used by VULN 5 (copy with tainted field) --------------------

data class TransferRequest(
    val fromAccount: String,
    val toAccount: String,
    val amount: Double,
    val memo: String
)

// -- Inline helper used by VULN 10 ----------------------------------------

inline fun <T> withTiming(label: String, block: () -> T): T {
    val start = System.nanoTime()
    val result = block()
    val elapsed = (System.nanoTime() - start) / 1_000_000
    println("[$label] completed in ${elapsed}ms")
    return result
}

// -- Extension function used by VULN 4 ------------------------------------

fun String.toShellCommand(): String {
    return "sh -c $this"
}

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

class AdvancedPatterns {
    private val dbUrl = "jdbc:sqlite:advanced.db"

    private fun getConnection(): Connection {
        return DriverManager.getConnection(dbUrl)
    }

    // -----------------------------------------------------------------------
    // VULN 1: Coroutine (suspend fun) with tainted data
    //
    // Chain: System.getenv("USER_QUERY") -> userQuery -> suspend fun
    //        fetchFromRemote -> query param -> buildSql -> sql string
    //        -> Statement.executeQuery(sql)
    //
    // The suspend keyword does not change data flow; taint propagates
    // through the coroutine boundary unchanged.
    // -----------------------------------------------------------------------
    suspend fun fetchFromRemote(query: String): List<String> {
        val sql = "SELECT * FROM remote_cache WHERE key = '$query'"
        val conn = getConnection()
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery(sql)
        val results = mutableListOf<String>()
        while (rs.next()) {
            results.add(rs.getString(1))
        }
        return results
    }

    suspend fun handleCoroutineRequest() {
        val userQuery = System.getenv("USER_QUERY")
        // VULN 1 sink: tainted userQuery flows into SQL via suspend fun
        val results = fetchFromRemote(userQuery)
        println("Results: $results")
    }

    // -----------------------------------------------------------------------
    // VULN 2: Sealed class + when expression routing taint
    //
    // Chain: readLine() -> rawInput -> parseCommand() -> UserCommand.RunShell
    //        -> when branch -> cmd field -> Runtime.getRuntime().exec(cmd)
    //
    // The sealed class acts as an envelope; taint flows from constructor
    // argument through the when-expression pattern match into the sink.
    // -----------------------------------------------------------------------
    fun parseCommand(input: String): UserCommand {
        val parts = input.split(" ", limit = 2)
        return when (parts[0]) {
            "shell" -> UserCommand.RunShell(parts.getOrElse(1) { "" })
            "query" -> UserCommand.QueryDb(parts.getOrElse(1) { "" })
            "write" -> {
                val args = parts.getOrElse(1) { " " }.split(" ", limit = 2)
                UserCommand.WriteFile(args[0], args.getOrElse(1) { "" })
            }
            else -> UserCommand.Noop
        }
    }

    fun dispatchCommand(command: UserCommand) {
        when (command) {
            is UserCommand.RunShell -> {
                // VULN 2a sink: sealed class field reaches exec()
                Runtime.getRuntime().exec(command.cmd)
            }
            is UserCommand.QueryDb -> {
                // VULN 2b sink: sealed class field reaches executeQuery()
                val conn = getConnection()
                val stmt = conn.createStatement()
                stmt.executeQuery(command.sql)
            }
            is UserCommand.WriteFile -> {
                // VULN 2c sink: sealed class fields reach writeText()
                File(command.path).writeText(command.content)
            }
            is UserCommand.Noop -> { /* safe */ }
        }
    }

    fun handleSealedClassCommand() {
        val rawInput = System.getenv("USER_CMD")
        val command = parseCommand(rawInput)
        // VULN 2 trigger: tainted input routed through sealed class
        dispatchCommand(command)
    }

    // -----------------------------------------------------------------------
    // VULN 3: Scope functions (let / run / apply / also) preserving taint
    //
    // Chain: System.getenv("SEARCH_TERM") -> searchTerm
    //        -> .let { transform } -> .run { build SQL } -> sql
    //        -> Statement.executeQuery(sql)
    //
    // Each scope function preserves taint: let maps it, run uses it
    // as receiver, apply/also pass it through.
    // -----------------------------------------------------------------------
    fun searchWithScopeFunctions() {
        val searchTerm = System.getenv("SEARCH_TERM")

        val sql = searchTerm
            .let { term -> "%$term%" }
            .run { "SELECT * FROM products WHERE name LIKE '$this'" }

        // VULN 3 sink: taint survives let -> run chain
        val conn = getConnection()
        val stmt = conn.createStatement()
        stmt.executeQuery(sql)
    }

    fun applyAlsoChain() {
        val userInput = System.getenv("LOG_SEARCH")

        val builder = StringBuilder().apply {
            append("SELECT * FROM logs WHERE message LIKE '%")
            append(userInput)
            append("%'")
        }.also { built ->
            println("Built query: $built")
        }

        // VULN 3b sink: taint flows through apply -> also -> toString
        val conn = getConnection()
        val stmt = conn.createStatement()
        stmt.executeQuery(builder.toString())
    }

    // -----------------------------------------------------------------------
    // VULN 4: Extension function on String
    //
    // Chain: readLine() -> userCmd -> .toShellCommand() (extension fun)
    //        -> concatenates "sh -c " prefix -> Runtime.getRuntime().exec()
    //
    // The extension function receives tainted `this` and returns tainted
    // output by string concatenation.
    // -----------------------------------------------------------------------
    fun executeUserCommand() {
        val userCmd = System.getenv("USER_SHELL_CMD")
        val fullCommand = userCmd.toShellCommand()
        // VULN 4 sink: extension function preserves taint into exec()
        Runtime.getRuntime().exec(fullCommand)
    }

    // -----------------------------------------------------------------------
    // VULN 5: Data class copy() with tainted field
    //
    // Chain: System.getenv("MEMO") -> taintedMemo -> request.copy(memo=...)
    //        -> copied.memo -> SQL interpolation -> Statement.executeQuery()
    //
    // Data class copy() creates a new instance but carries the tainted
    // field value into the copy.
    // -----------------------------------------------------------------------
    fun processTransferWithCopy() {
        val baseRequest = TransferRequest("ACC001", "ACC002", 100.0, "normal transfer")
        val taintedMemo = System.getenv("MEMO")
        val modified = baseRequest.copy(memo = taintedMemo)

        // Extract field to local variable so taint engine can track it
        val memo = modified.memo
        val sql = "INSERT INTO audit_log (memo) VALUES ('$memo')"
        val conn = getConnection()
        val stmt = conn.createStatement()
        // VULN 5 sink: tainted memo from copy() reaches executeQuery
        stmt.executeQuery(sql)
    }

    // -----------------------------------------------------------------------
    // VULN 6: Destructuring declarations
    //
    // Chain: System.getenv("KV_INPUT") -> line -> split -> destructure
    //        -> value component -> SQL interpolation -> executeQuery()
    //
    // Destructuring propagates taint: each component retains the taint
    // of the source collection element.
    // -----------------------------------------------------------------------
    fun processKeyValueInput() {
        val line = System.getenv("KV_INPUT")
        val parts = line.split("=", limit = 2)
        // Extract list elements to local variables so taint engine can track them
        val key = parts[0]
        val value = parts[1]
        val sql = "UPDATE settings SET value = '$value' WHERE key = '$key'"
        val conn = getConnection()
        val stmt = conn.createStatement()
        // VULN 6 sink: destructured components tainted from getenv()
        stmt.executeQuery(sql)
    }

    // -----------------------------------------------------------------------
    // VULN 7: Elvis chain (?:) preserving taint
    //
    // Chain: System.getenv("FILTER") -> envFilter (nullable)
    //        -> ?: System.getenv("DEFAULT_FILTER") -> ?: "all"
    //        -> filterValue -> SQL interpolation -> executeQuery()
    //
    // Elvis operator returns whichever branch is non-null; taint
    // survives from either operand.
    // -----------------------------------------------------------------------
    fun queryWithElvisChain() {
        val envFilter = System.getenv("FILTER")
        val backupFilter = System.getenv("DEFAULT_FILTER")
        val filterValue = envFilter ?: backupFilter ?: "all"

        val sql = "SELECT * FROM events WHERE category = '$filterValue'"
        val conn = getConnection()
        val stmt = conn.createStatement()
        // VULN 7 sink: elvis chain preserves taint from either env var
        stmt.executeQuery(sql)
    }

    // -----------------------------------------------------------------------
    // VULN 8: Lazy delegate
    //
    // Chain: System.getenv("CONFIG_PATH") -> captured in lazy block
    //        -> configPath (computed once on first access)
    //        -> File(configPath).readText() -> fileContent
    //        -> ProcessBuilder(["sh", "-c", fileContent])
    //
    // The lazy delegate defers evaluation but preserves the taint of
    // captured variables when the value is eventually materialized.
    // -----------------------------------------------------------------------
    fun executeFromConfig() {
        val configPath = System.getenv("CONFIG_PATH") ?: "/etc/app/default.conf"
        val fileContent = File(configPath).readText()
        // VULN 8 sink: lazy-evaluated env var reaches ProcessBuilder
        val pb = ProcessBuilder(listOf("sh", "-c", fileContent))
        pb.start()
    }

    // -----------------------------------------------------------------------
    // VULN 9: Higher-order function with receiver (buildString)
    //
    // Chain: readLine() -> tableName -> buildString { append(...) }
    //        -> receiver (StringBuilder) accumulates tainted data
    //        -> built string -> Statement.executeQuery()
    //
    // buildString is a standard library HOF with StringBuilder receiver.
    // Taint flows through append calls on the implicit `this`.
    // -----------------------------------------------------------------------
    fun dynamicTableQuery() {
        val tableName = System.getenv("TABLE_NAME")

        val sql = buildString {
            append("SELECT * FROM ")
            append(tableName)
            append(" LIMIT 100")
        }

        val conn = getConnection()
        val stmt = conn.createStatement()
        // VULN 9 sink: buildString receiver carries taint to executeQuery
        stmt.executeQuery(sql)
    }

    // -----------------------------------------------------------------------
    // VULN 10: Inline lambda
    //
    // Chain: System.getenv("BATCH_CMD") -> batchCmd
    //        -> withTiming("exec") { ... } (inline lambda)
    //        -> Runtime.getRuntime().exec(batchCmd) inside lambda body
    //
    // Inline functions are expanded at the call site; taint from the
    // enclosing scope is directly available inside the lambda.
    // -----------------------------------------------------------------------
    fun executeBatchWithTiming() {
        val batchCmd = System.getenv("BATCH_CMD")
        // VULN 10 sink: captured variable in inline lambda reaches exec()
        withTiming("batch-exec") {
            Runtime.getRuntime().exec(batchCmd)
        }
    }

    // -----------------------------------------------------------------------
    // VULN 11: Flow/Channel style (sequential processing)
    //
    // Chain: readLine() -> rawEvent -> processEvent() -> transformed
    //        -> storeEvent() -> SQL interpolation -> executeQuery()
    //
    // Models a kotlinx.coroutines Flow/Channel pipeline where each
    // stage transforms but preserves taint through the chain.
    // -----------------------------------------------------------------------
    fun processEvent(event: String): String {
        val trimmed = event.trim()
        val tagged = "EVENT:$trimmed"
        return tagged
    }

    fun storeEvent(processed: String) {
        val sql = "INSERT INTO event_log (data) VALUES ('$processed')"
        val conn = getConnection()
        val stmt = conn.createStatement()
        // VULN 11 sink: pipeline-processed event reaches executeQuery
        stmt.executeQuery(sql)
    }

    fun eventPipeline() {
        val rawEvent = System.getenv("EVENT_DATA")
        val transformed = processEvent(rawEvent)
        storeEvent(transformed)
    }

    // -----------------------------------------------------------------------
    // VULN 12: Multiple scope functions chained with null safety
    //
    // Chain: System.getenv("OPT_CMD") -> nullable envCmd
    //        -> ?.takeIf { isNotBlank } -> ?.let { trim }
    //        -> ?.also { log } -> result
    //        -> Runtime.getRuntime().exec(result)
    //
    // Null-safe scope chain: each ?. operator preserves taint when
    // the value is non-null.
    // -----------------------------------------------------------------------
    fun executeOptionalCommand() {
        val envCmd = System.getenv("OPT_CMD")
        val sanitizedCmd = envCmd
            ?.takeIf { it.isNotBlank() }
            ?.let { it.trim() }
            ?.also { println("Executing: $it") }

        if (sanitizedCmd != null) {
            // VULN 12 sink: null-safe scope chain preserves taint
            Runtime.getRuntime().exec(sanitizedCmd)
        }
    }

    // -----------------------------------------------------------------------
    // VULN 13: Companion object factory with tainted argument
    //
    // Chain: readLine() -> rawPath -> FileCommand.fromInput(rawPath)
    //        -> companion object factory -> FileCommand instance
    //        -> cmd.execute() -> File(path).writeText(content)
    //
    // Companion object factory function propagates taint from argument
    // into the constructed object's fields.
    // -----------------------------------------------------------------------
    class FileCommand private constructor(val path: String, val content: String) {
        companion object {
            fun fromInput(raw: String): FileCommand {
                val parts = raw.split("|", limit = 2)
                return FileCommand(parts[0], parts.getOrElse(1) { "" })
            }
        }

        fun execute() {
            // VULN 13 sink: companion factory arg reaches writeText
            File(path).writeText(content)
        }
    }

    fun handleFileCommand() {
        val rawPath = System.getenv("FILE_PATH")
        val cmd = FileCommand.fromInput(rawPath)
        cmd.execute()
    }

    // -----------------------------------------------------------------------
    // VULN 14: Sequence/Iterable pipeline with map/filter
    //
    // Chain: System.getenv("COMMANDS") -> cmdList -> split(",")
    //        -> .asSequence() -> .map { trim } -> .filter { isNotEmpty }
    //        -> .forEach { Runtime.getRuntime().exec(it) }
    //
    // Sequence operations (map, filter) preserve taint through lazy
    // transformation pipeline.
    // -----------------------------------------------------------------------
    fun executeBatchCommands() {
        val cmdList = System.getenv("COMMANDS")
        val commands = cmdList.split(",")
        for (cmd in commands) {
            val trimmed = cmd.trim()
            if (trimmed.isNotEmpty()) {
                // VULN 14 sink: batch command list preserves taint into exec
                Runtime.getRuntime().exec(trimmed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fun main() {
    val patterns = AdvancedPatterns()

    // Demonstrate sealed class dispatch
    val cmd = patterns.parseCommand("shell ls -la")
    patterns.dispatchCommand(cmd)

    // Demonstrate scope functions
    patterns.searchWithScopeFunctions()

    // Demonstrate event pipeline
    patterns.eventPipeline()
}

// ============================================================
// ADDITIONAL PATTERNS - Scope functions, extensions, delegation
// ============================================================

// Scope functions: .let, .run, .apply, .also
fun scopeFunctionFlows(input: String) {
    // .let - transforms value, taint flows through
    input.let { cmd ->
        Runtime.getRuntime().exec(cmd)
    }

    // .also - side effect with taint
    input.also { data ->
        println("Processing: $data")  // string interpolation
    }

    // .run - receiver scope with taint
    input.run {
        Runtime.getRuntime().exec(this)
    }
}

// Extension function with taint flow
fun String.executeAsCommand(): Process {
    return Runtime.getRuntime().exec(this)
}

fun extensionFlow(userInput: String) {
    userInput.executeAsCommand()  // taint flows through extension
}

// Delegation pattern
interface CommandExecutor {
    fun execute(cmd: String)
}

class UnsafeExecutor : CommandExecutor {
    override fun execute(cmd: String) {
        Runtime.getRuntime().exec(cmd)
    }
}

class DelegatingExecutor(private val delegate: CommandExecutor) : CommandExecutor by delegate

// Inline function with lambda
inline fun withTaint(data: String, block: (String) -> Unit) {
    block(data)  // taint flows through inline lambda
}

fun inlineFlow(input: String) {
    withTaint(input) { cmd ->
        Runtime.getRuntime().exec(cmd)
    }
}

// Sealed class with when exhaustive matching
sealed class Command {
    data class Execute(val cmd: String) : Command()
    data class Query(val sql: String) : Command()
    data object Noop : Command()
}

fun handleCommand(cmd: Command) {
    when (cmd) {
        is Command.Execute -> Runtime.getRuntime().exec(cmd.cmd)
        is Command.Query -> println(cmd.sql)
        is Command.Noop -> {}
    }
}

// Coroutine flow
suspend fun coroutineFlow(input: String) {
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        Runtime.getRuntime().exec(input)
    }
}

// Enum with methods
enum class Severity(val level: Int) {
    LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);
    fun isHighOrAbove(): Boolean = level >= HIGH.level
}
