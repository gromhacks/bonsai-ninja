package com.bank.app

import java.io.File
import java.net.URL
import java.sql.DriverManager
import java.sql.Statement

// ---------------------------------------------------------------------------
// CrossModuleHandler.kt
//
// Cross-file vulnerability chains using all 5 existing Kotlin classes:
//   - MainActivity (MainActivity.kt)
//   - DatabaseHelper (DatabaseHelper.kt)
//   - TransactionService (TransactionService.kt)
//   - SecurityUtils (SecurityUtils.kt)
//   - NetworkClient (NetworkClient.kt)
//
// Each chain is documented with its full hop sequence and file traversal.
// ---------------------------------------------------------------------------

// -- Top-level variable used by Chain B ------------------------------------

var globalAdminCommand: String = "default"

// -- Companion object cache used by Chain B --------------------------------

class CommandRegistry {
    companion object {
        private val registry = mutableMapOf<String, String>()

        fun register(name: String, command: String) {
            registry[name] = command
        }

        fun lookup(name: String): String? {
            return registry[name]
        }
    }
}

// ---------------------------------------------------------------------------
// Chain A: 10+ hops across 4 files (deepest chain)
//
// Full chain (12 hops):
//   1.  System.getenv("ADMIN_QUERY")          [CrossModuleHandler.kt] source
//   2.  -> adminQuery param                   [CrossModuleHandler.kt]
//   3.  -> enrichQuery(adminQuery)            [CrossModuleHandler.kt]
//   4.  -> enriched return value              [CrossModuleHandler.kt]
//   5.  -> networkClient.post(enriched)       [CrossModuleHandler.kt -> NetworkClient.kt]
//   6.  -> remoteResponse                     [CrossModuleHandler.kt]
//   7.  -> mergeResults(enriched, response)   [CrossModuleHandler.kt]
//   8.  -> merged string                      [CrossModuleHandler.kt]
//   9.  -> transactionService.customSearch()  [CrossModuleHandler.kt -> TransactionService.kt]
//  10.  -> whereClause param                  [TransactionService.kt]
//  11.  -> dbHelper.executeQuery(sql)         [TransactionService.kt -> DatabaseHelper.kt]
//  12.  -> stmt.executeQuery(sql)             [DatabaseHelper.kt] SINK
//
// Files touched: CrossModuleHandler.kt -> NetworkClient.kt ->
//                CrossModuleHandler.kt -> TransactionService.kt ->
//                DatabaseHelper.kt
// ---------------------------------------------------------------------------

class CrossModuleHandler {
    private val mainActivity = MainActivity()
    private val dbHelper = DatabaseHelper("jdbc:sqlite:cross_module.db")
    private val transactionService = TransactionService()
    private val networkClient = NetworkClient()
    private val securityUtils = SecurityUtils()

    // -- Chain A helpers --

    private fun enrichQuery(raw: String): String {
        val timestamp = System.currentTimeMillis()
        val result = raw + " AND timestamp > " + timestamp
        return result
    }

    private fun mergeResults(localQuery: String, remoteData: String): String {
        val result = localQuery + " OR remote_id IN (" + remoteData + ")"
        return result
    }

    fun deepChainAdmin() {
        // Hop 1: source - env var
        val adminQuery = System.getenv("ADMIN_QUERY")
        // Hop 3: enrich
        val enriched = enrichQuery(adminQuery)
        // Hop 5: send to network, get response
        val remoteResponse = networkClient.post("/api/search", enriched)
        // Hop 7: merge local + remote
        val merged = mergeResults(enriched, remoteResponse)
        // Hop 9-12: flows through TransactionService -> DatabaseHelper -> executeQuery
        // VULN Chain A sink: 12-hop chain across 4 files reaches SQL execution
        val results = transactionService.customSearch(merged, dbHelper)
        println("Admin search results: $results")
    }

    // -----------------------------------------------------------------------
    // Chain B: Companion object + top-level variable
    //
    // Full chain (8 hops):
    //   1.  readLine()                           [CrossModuleHandler.kt] source
    //   2.  -> userCmd                           [CrossModuleHandler.kt]
    //   3.  -> CommandRegistry.register(userCmd) [CrossModuleHandler.kt]
    //   4.  -> companion object registry map     [CrossModuleHandler.kt]
    //   5.  -> globalAdminCommand = ...          [CrossModuleHandler.kt] top-level var
    //   6.  -> CommandRegistry.lookup()          [CrossModuleHandler.kt]
    //   7.  -> retrieved command string          [CrossModuleHandler.kt]
    //   8.  -> Runtime.getRuntime().exec()       [CrossModuleHandler.kt] SINK
    //
    // Demonstrates taint propagation through companion object state
    // and a top-level (module-level) mutable variable.
    // -----------------------------------------------------------------------

    fun registerAdminCommand() {
        // Hop 1: source - env var
        val userCmd = System.getenv("ADMIN_CMD")
        // Hop 3: store into companion object
        CommandRegistry.register("admin", userCmd)
        // Hop 5: also store in top-level variable
        globalAdminCommand = userCmd
    }

    fun executeRegisteredCommand() {
        // Hop 6: retrieve from companion object
        val storedCmd = CommandRegistry.lookup("admin")
        if (storedCmd != null) {
            // VULN Chain B sink: companion object state reaches exec()
            Runtime.getRuntime().exec(storedCmd)
        }
    }

    fun executeGlobalCommand() {
        // Alternative path via top-level variable
        val cmd = globalAdminCommand
        // VULN Chain B-alt sink: top-level variable reaches exec()
        Runtime.getRuntime().exec(cmd)
    }

    // -----------------------------------------------------------------------
    // Chain C: Lambda / higher-order callback
    //
    // Full chain (9 hops):
    //   1.  System.getenv("WEBHOOK_URL")         [CrossModuleHandler.kt] source
    //   2.  -> webhookUrl                        [CrossModuleHandler.kt]
    //   3.  -> processWithCallback(webhookUrl, lambda)  [CrossModuleHandler.kt]
    //   4.  -> callback parameter (lambda)       [CrossModuleHandler.kt]
    //   5.  -> lambda body: transform(data)      [CrossModuleHandler.kt]
    //   6.  -> transformed string                [CrossModuleHandler.kt]
    //   7.  -> networkClient.fetchExternal()     [CrossModuleHandler.kt -> NetworkClient.kt]
    //   8.  -> URL(targetUrl)                    [NetworkClient.kt]
    //   9.  -> conn.openConnection()             [NetworkClient.kt] SINK (SSRF)
    //
    // Demonstrates taint flowing through a lambda callback parameter
    // and then crossing into NetworkClient for the SSRF sink.
    // -----------------------------------------------------------------------

    fun processWithCallback(data: String, callback: (String) -> String): String {
        val processed = callback(data)
        return processed
    }

    fun lambdaChainSsrf() {
        // Hop 1: source - env var
        val webhookUrl = System.getenv("WEBHOOK_URL")

        // Hop 3-6: pass through higher-order function with lambda
        val finalUrl = processWithCallback(webhookUrl) { input ->
            val trimmed = input.trim()
            trimmed + "/callback"
        }

        // Hop 7-9: flows into NetworkClient.fetchExternal -> URL open
        // VULN Chain C sink: lambda callback preserves taint into SSRF
        val response = networkClient.fetchExternal(finalUrl)
        println("Webhook response: $response")
    }

    // -----------------------------------------------------------------------
    // Chain D: Re-exported wrapper (facade pattern)
    //
    // Full chain (8 hops):
    //   1.  readLine()                           [CrossModuleHandler.kt] source
    //   2.  -> accountFilter                     [CrossModuleHandler.kt]
    //   3.  -> quickSearch(accountFilter)        [CrossModuleHandler.kt]
    //   4.  -> wrapForSearch(raw)                [CrossModuleHandler.kt]
    //   5.  -> wrapped string                    [CrossModuleHandler.kt]
    //   6.  -> dbHelper.getAccount(wrapped)      [CrossModuleHandler.kt -> DatabaseHelper.kt]
    //   7.  -> SQL interpolation                 [DatabaseHelper.kt]
    //   8.  -> stmt.executeQuery(sql)            [DatabaseHelper.kt] SINK
    //
    // Wrapper/facade functions re-export tainted data without sanitization.
    // The chain crosses through a wrapper layer before reaching the DB.
    // -----------------------------------------------------------------------

    private fun wrapForSearch(raw: String): String {
        return raw.replace("'", "").trim()
    }

    fun quickSearch(filter: String): Map<String, Any>? {
        val wrapped = wrapForSearch(filter)
        // VULN Chain D sink: wrapper does insufficient sanitization;
        // taint flows through to DatabaseHelper.getAccount -> SQL injection
        return dbHelper.getAccount(wrapped)
    }

    fun handleQuickSearch() {
        // Hop 1: source - env var
        val accountFilter = System.getenv("ACCOUNT_FILTER")
        // Hop 3-8: through wrapper -> dbHelper -> SQL
        val result = quickSearch(accountFilter)
        println("Quick search result: $result")
    }

    // -----------------------------------------------------------------------
    // Chain E: Recursive chain
    //
    // Full chain (variable depth, minimum 7 hops):
    //   1.  System.getenv("TEMPLATE")            [CrossModuleHandler.kt] source
    //   2.  -> template string                   [CrossModuleHandler.kt]
    //   3.  -> expandTemplate(template, depth=0) [CrossModuleHandler.kt]
    //   4.  -> recursive call: expandTemplate(expanded, depth+1) [recursive]
    //   5.  -> ... (up to 3 recursive expansions) ...
    //   6.  -> fully expanded string             [CrossModuleHandler.kt]
    //   7.  -> File(path).writeText(expanded)    [CrossModuleHandler.kt] SINK
    //
    // Recursive functions propagate taint through each recursive call.
    // The tainted template is expanded recursively and then written to disk.
    // -----------------------------------------------------------------------

    private fun expandTemplate(template: String, depth: Int): String {
        if (depth > 3) return template

        val envPattern = Regex("\\$\\{([^}]+)\\}")
        val expanded = envPattern.replace(template) { match ->
            val varName = match.groupValues[1]
            System.getenv(varName) ?: match.value
        }

        // Recurse if there are still unexpanded variables
        return if (expanded.contains("\${")) {
            expandTemplate(expanded, depth + 1)
        } else {
            expanded
        }
    }

    fun renderTemplate() {
        // Hop 1: source - env var
        val template = System.getenv("TEMPLATE")
        // Hop 3-5: recursive expansion (each level may pull in more env vars)
        val expanded = expandTemplate(template, 0)
        val outputPath = System.getenv("OUTPUT_PATH") ?: "/tmp/rendered.txt"
        // VULN Chain E sink: recursively expanded tainted template written to file
        File(outputPath).writeText(expanded)
    }

    // -----------------------------------------------------------------------
    // Combined workflow: ties multiple chains together
    // -----------------------------------------------------------------------

    fun fullWorkflow() {
        // Chain A: deep admin search
        deepChainAdmin()

        // Chain B: register then execute
        registerAdminCommand()
        executeRegisteredCommand()

        // Chain C: lambda callback into SSRF
        lambdaChainSsrf()

        // Chain D: quick search through wrapper
        handleQuickSearch()

        // Chain E: recursive template expansion
        renderTemplate()
    }
}

// ---------------------------------------------------------------------------
// Additional cross-module helper that ties SecurityUtils into chains
// ---------------------------------------------------------------------------

class AuditLogger(private val dbHelper: DatabaseHelper) {

    // -----------------------------------------------------------------------
    // Supplemental chain: SecurityUtils bypass
    //
    // Chain (7 hops):
    //   1.  readLine()                           [CrossModuleHandler.kt] source
    //   2.  -> rawEntry                          [CrossModuleHandler.kt]
    //   3.  -> SecurityUtils.sanitizeLogEntry()  [SecurityUtils.kt] (partial sanitize)
    //   4.  -> sanitized (newlines removed only) [CrossModuleHandler.kt]
    //   5.  -> SQL string interpolation          [CrossModuleHandler.kt]
    //   6.  -> dbHelper.executeQuery(sql)        [CrossModuleHandler.kt -> DatabaseHelper.kt]
    //   7.  -> stmt.executeQuery(sql)            [DatabaseHelper.kt] SINK
    //
    // SecurityUtils.sanitizeLogEntry only strips newlines, not SQL
    // metacharacters. The "sanitization" is insufficient for SQL context.
    // -----------------------------------------------------------------------
    fun logAuditEvent(entry: String) {
        val sanitized = SecurityUtils.sanitizeLogEntry(entry)
        val sql = "INSERT INTO audit_log (message) VALUES ('$sanitized')"
        // VULN supplemental sink: insufficient sanitization for SQL context
        dbHelper.executeQuery(sql)
    }

    fun handleAuditLog() {
        val rawEntry = System.getenv("AUDIT_ENTRY")
        logAuditEvent(rawEntry)
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fun main() {
    val handler = CrossModuleHandler()
    handler.fullWorkflow()

    val dbHelper = DatabaseHelper("jdbc:sqlite:cross_module.db")
    val logger = AuditLogger(dbHelper)
    logger.handleAuditLog()
}
