/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
import java.sql.DriverManager

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

// [NO FLOW EXPECTED] Both branches sanitize
fun branchKillBothPaths(userInput: String) {
    val cmd = if (userInput.length > 100) "default_command" else "safe_fallback"
    Runtime.getRuntime().exec(cmd) // safe
}

// [FLOW EXPECTED] Only one branch kills taint
fun branchKillOnePath(userInput: String) {
    var cmd = userInput
    if (cmd.length > 100) {
        cmd = "truncated"
    }
    Runtime.getRuntime().exec(cmd) // tainted: else path preserves
}

// [FLOW EXPECTED] When expression without exhaustive coverage
fun branchKillWhen(userInput: String) {
    var query = userInput
    when (query.first()) {
        'a' -> query = "SELECT * FROM a"
        'b' -> query = "SELECT * FROM b"
        // no else: query keeps userInput for other chars
    }
    Runtime.getRuntime().exec(query)
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

fun sanitize(value: String): String =
    value.replace("'", "").replace(";", "").replace("--", "")

fun wrapSanitize(value: String): String = sanitize(value)

// [NO FLOW EXPECTED]
fun interproceduralKillDirect(userInput: String) {
    val clean = sanitize(userInput)
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().execute("SELECT * FROM t WHERE x = '$clean'")
}

// [NO FLOW EXPECTED]
fun interproceduralKillTwoLevels(userInput: String) {
    val clean = wrapSanitize(userInput)
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().execute("SELECT * FROM t WHERE x = '$clean'")
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

data class Config(var command: String = "", var label: String = "")

// [FLOW EXPECTED] Tainted field
fun fieldSensitiveTainted(userInput: String) {
    val cfg = Config(command = userInput, label = "safe")
    Runtime.getRuntime().exec(cfg.command)
}

// [NO FLOW EXPECTED] Safe field only
fun fieldSensitiveSafe(userInput: String) {
    val cfg = Config(command = userInput, label = "safe")
    Runtime.getRuntime().exec(cfg.label)
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint through exception
fun exceptionTaint(userInput: String) {
    try {
        throw RuntimeException("Invalid: $userInput")
    } catch (e: RuntimeException) {
        Runtime.getRuntime().exec(e.message)
    }
}


// ---------------------------------------------------------------------------
// 5. SCOPE FUNCTION TAINT (Kotlin-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through .let
fun scopeFunctionLet(userInput: String) {
    userInput.let { input ->
        Runtime.getRuntime().exec(input)
    }
}

// [FLOW EXPECTED] Taint flows through .run
fun scopeFunctionRun(userInput: String) {
    val result = userInput.run { uppercase() }
    Runtime.getRuntime().exec(result)
}


// ---------------------------------------------------------------------------
// 6. SEALED CLASS DISPATCH
// ---------------------------------------------------------------------------

sealed class Command {
    data class Execute(val cmd: String) : Command()
    data class Query(val sql: String) : Command()
    data object Noop : Command()
}

// [FLOW EXPECTED] Taint through sealed class variant
fun sealedClassDispatch(userInput: String) {
    val cmd: Command = Command.Execute(userInput)
    when (cmd) {
        is Command.Execute -> Runtime.getRuntime().exec(cmd.cmd)
        is Command.Query -> {}
        is Command.Noop -> {}
    }
}


// ---------------------------------------------------------------------------
// 7. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] External entry point
fun handleWebhook(payload: String, signature: String) {
    Runtime.getRuntime().exec("process $payload")
}


// ---------------------------------------------------------------------------
// 8. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    private var data: String = ""

    fun ingest(raw: String) {
        data = raw
    }

    fun process() {
        Runtime.getRuntime().exec(data)
    }
}

// [FLOW EXPECTED]
fun crossMethodFieldTaint(userInput: String) {
    val p = Pipeline()
    p.ingest(userInput)
    p.process()
}


// ---------------------------------------------------------------------------
// 9. ELVIS OPERATOR CHAIN
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint survives elvis chain
fun elvisChain(userInput: String?) {
    val cmd = userInput ?: return
    Runtime.getRuntime().exec(cmd)
}


// ---------------------------------------------------------------------------
// 10. COROUTINE-LIKE SUSPEND (simulated)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint through string interpolation
fun interpolationChain(userInput: String) {
    val query = "SELECT * FROM users WHERE name = '$userInput'"
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().execute(query)
}
