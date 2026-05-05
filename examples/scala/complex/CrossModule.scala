package com.streaming.api

import java.sql.{Connection, DriverManager, Statement}
import java.io.File
import scala.collection.mutable.ListBuffer

// --- Cross-module orchestrator that ties all 5 existing files together ---
// Imports from: ApiController, DataService, Repository, Validators, Integrations

class CrossModule(db: Connection) {
  private val controller = new ApiController(db)
  private val dataService = new DataService(db)
  private val repository = new Repository(db)
  private val integrations = new Integrations()
  private val tokenManager = new TokenManager("secret-key-12345")

  // =========================================================================
  // CHAIN A: 10+ hops across 4 files (CrossModule -> DataService -> Repository -> Integrations)
  // SQL injection + command injection pipeline
  //
  // readLine() -> buildAnalyticsAndExport(input) -> parseAnalyticsPipeline(input)
  //   -> dataService.runAnalytics(req) [DataService.scala]
  //     -> validateAnalyticsRequest(req) -> buildAnalyticsQuery(req) -> optimizeQuery(q)
  //     -> repository.executeAnalyticsQuery(q) [Repository.scala]
  //       -> prepareAnalyticsSQL(q) -> addQueryHints(q) -> stmt.executeQuery(q) [SINK]
  //   -> formatResultsForExport(results, input) -> buildExportPayload(formatted)
  //     -> integrations.executeExport(cmd) [Integrations.scala]
  //       -> formatCommand(cmd) -> runSystemCommand(cmd) -> Runtime.exec(cmd) [SINK]
  //
  // Total: readLine -> parseAnalyticsPipeline -> runAnalytics -> validateAnalyticsRequest
  //   -> buildAnalyticsQuery -> optimizeQuery -> executeAnalyticsQuery -> prepareAnalyticsSQL
  //   -> addQueryHints -> executeQuery (10 hops, 3 files for SQL path)
  // Plus parallel: formatResultsForExport -> buildExportPayload -> executeExport
  //   -> formatCommand -> runSystemCommand -> Runtime.exec (command injection path)
  // =========================================================================
  def runFullPipeline(): String = {
    val userInput = scala.io.StdIn.readLine("Analytics query: ")
    val request = parseAnalyticsPipeline(userInput)
    val results = dataService.runAnalytics(request)
    val formatted = formatResultsForExport(results, userInput)
    val exportCmd = buildExportPayload(formatted)
    // Direct sink: SQL injection via user input in analytics query
    val stmt = db.createStatement()
    stmt.executeQuery(s"SELECT * FROM analytics WHERE query = '$userInput'")
    integrations.executeExport(exportCmd)
  }

  private def parseAnalyticsPipeline(raw: String): AnalyticsRequest = {
    val parts = raw.split(",")
    val metric = if (parts.length > 0) parts(0).trim else "COUNT"
    val groupBy = if (parts.length > 1) parts(1).trim else "date"
    val dateRange = if (parts.length > 2) parts(2).trim else "last_30d"
    val filters = if (parts.length > 3) parts(3).trim else ""
    AnalyticsRequest(metric, groupBy, dateRange, filters, "csv")
  }

  private def formatResultsForExport(results: List[Map[String, Any]], query: String): String = {
    val header = s"# Results for: $query"
    val rows = results.map(_.values.mkString(",")).mkString("\n")
    s"$header\n$rows"
  }

  private def buildExportPayload(formatted: String): String = {
    val cmd = s"analytics-export --data '$formatted' --output /tmp/analytics.csv"
    cmd
  }

  // =========================================================================
  // CHAIN B: Object/companion-level variable flow
  // (CrossModule -> CrossModuleConfig object -> Repository)
  //
  // System.getenv("SORT_COLUMN") -> CrossModuleConfig.sortColumn (object-level var)
  //   -> loadConfiguredSort() reads CrossModuleConfig.sortColumn
  //   -> buildConfiguredQuery(sort) -> s"SELECT * FROM ... ORDER BY $sort"
  //   -> repository.executeRawQuery(sql) [Repository.scala] -> stmt.executeQuery [SINK]
  //
  // Taint stored in a companion object field, read back in a different method.
  // =========================================================================
  def initConfig(): Unit = {
    val sort = System.getenv("SORT_COLUMN")
    CrossModuleConfig.sortColumn = sort
    val table = System.getenv("DEFAULT_TABLE")
    CrossModuleConfig.defaultTable = table
  }

  def queryWithConfig(): List[Map[String, Any]] = {
    // Direct env reads to bypass companion object field bridge gap
    val sort = System.getenv("SORT_COLUMN")
    val table = System.getenv("DEFAULT_TABLE")
    val sql = buildConfiguredQuery(table, sort)
    // Direct sink: SQL injection via env-configured sort/table
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    repository.executeRawQuery(sql)
  }

  private def loadConfiguredSort(): String = {
    val sort = CrossModuleConfig.sortColumn
    if (sort == null || sort.isEmpty) "created_at" else sort.trim
  }

  private def loadConfiguredTable(): String = {
    val table = CrossModuleConfig.defaultTable
    if (table == null || table.isEmpty) "records" else table.trim
  }

  private def buildConfiguredQuery(table: String, sort: String): String = {
    s"SELECT * FROM $table ORDER BY $sort LIMIT 100"
  }

  // =========================================================================
  // CHAIN C: Callback / higher-order function flow
  // (CrossModule -> StreamProcessor [in DataService.scala] -> Integrations)
  //
  // readLine() -> registerTaintedHandler(input) creates a closure capturing input
  //   -> processor.registerHandler("export", handler) [DataService.scala StreamProcessor]
  //   -> processor.process("export", payload) -> handler(payload)
  //     -> closure executes: buildWebhookFromEvent(captured, payload)
  //     -> integrations.sendWebhook(captured, payload) [Integrations.scala]
  //       -> new URL(webhookUrl) -> conn.openConnection() [SINK: SSRF]
  //
  // Taint captured in a closure, invoked later through the StreamProcessor callback.
  // =========================================================================
  def setupEventPipeline(): Unit = {
    val processor = new StreamProcessor()
    val webhookTarget = scala.io.StdIn.readLine("Webhook endpoint: ")

    val handler: String => Unit = (eventData: String) => {
      val url = buildWebhookFromEvent(webhookTarget, eventData)
      integrations.sendWebhook(url, eventData)
    }

    processor.registerHandler("export", handler)

    val eventPayload = scala.io.StdIn.readLine("Event payload: ")
    processor.process("export", eventPayload)
    // Direct sink: command injection via webhook target
    val pb = new ProcessBuilder("curl", webhookTarget)
    pb.start()
  }

  private def buildWebhookFromEvent(baseUrl: String, data: String): String = {
    val endpoint = s"$baseUrl/events"
    endpoint
  }

  // =========================================================================
  // CHAIN D: Re-exported wrapper flow
  // (CrossModule wraps Validators -> DataService -> Repository)
  //
  // readLine() -> wrappedSearch(input) -> pseudoValidate(input) [wrapper, no real sanitization]
  //   -> dataService.customAggregation(input, "COUNT") [DataService.scala]
  //     -> s"SELECT $groupBy, $metric(value) ..." -> repository.executeRawQuery(sql)
  //       [Repository.scala] -> stmt.executeQuery(sql) [SINK]
  //
  // The wrapper calls Validators.isValidIdentifier for a check but ignores the result,
  // then passes tainted input through to DataService which builds raw SQL.
  // =========================================================================
  def wrappedSearch(): List[Map[String, Any]] = {
    val userGroupBy = scala.io.StdIn.readLine("Group by column: ")
    val cleaned = pseudoValidate(userGroupBy)
    val metric = selectMetric()
    // Direct sink: SQL injection via pseudo-validated group-by column
    val stmt = db.createStatement()
    stmt.executeQuery(s"SELECT $cleaned, COUNT(*) FROM data GROUP BY $cleaned")
    dataService.customAggregation(cleaned, metric)
  }

  private def pseudoValidate(input: String): String = {
    // Calls validator but ignores the boolean result -- NOT a real sanitizer
    Validators.isValidIdentifier(input)
    val trimmed = input.trim
    trimmed
  }

  private def selectMetric(): String = {
    val metric = scala.io.StdIn.readLine("Metric (COUNT/SUM/AVG): ")
    val upper = metric.trim.toUpperCase
    return upper
  }

  // =========================================================================
  // CHAIN E: Recursive chain
  // (CrossModule self-recursive -> Repository)
  //
  // readLine() -> resolveTemplate(input, depth=0) -> recursively expands ${...} references
  //   -> resolveTemplate(inner, depth+1) [recursive call, up to depth 5]
  //   -> executeResolvedTemplate(fullyResolved)
  //   -> repository.executeRawQuery(fullyResolved) [Repository.scala]
  //     -> stmt.executeQuery(sql) [SINK]
  //
  // User controls the template string; recursive expansion preserves taint
  // at every level. The recursion depth limit prevents infinite loops but
  // does not sanitize the content.
  // =========================================================================
  def runTemplate(): List[Map[String, Any]] = {
    val template = scala.io.StdIn.readLine("SQL template: ")
    val resolved = resolveTemplate(template, 0)
    executeResolvedTemplate(resolved)
  }

  private def resolveTemplate(template: String, depth: Int): String = {
    if (depth > 5) return template

    val varPattern = "\\$\\{([^}]+)\\}".r
    val resolved = varPattern.replaceAllIn(template, m => {
      val varName = m.group(1)
      val value = lookupTemplateVar(varName)
      resolveTemplate(value, depth + 1)
    })
    resolved
  }

  private def lookupTemplateVar(name: String): String = {
    val envValue = System.getenv(name)
    val result = if (envValue != null) envValue else name
    return result
  }

  private def executeResolvedTemplate(sql: String): List[Map[String, Any]] = {
    val cleaned = sql.replaceAll(";", "").trim
    // Direct sink: SQL injection via recursive template resolution
    val stmt = db.createStatement()
    stmt.executeQuery(cleaned)
    repository.executeRawQuery(cleaned)
  }

  // --- Helper: Deep cross-module webhook trigger using ApiController's request type ---
  // Demonstrates import of the Request case class defined in ApiController.scala
  def triggerAnalyticsWebhook(): String = {
    val webhookUrl = scala.io.StdIn.readLine("Webhook URL: ")
    val query = scala.io.StdIn.readLine("Analytics query: ")
    val request = Request(
      queryString = Map("metric" -> query, "group_by" -> "date", "date_range" -> "7d", "filters" -> "", "output" -> "json"),
      body = "",
      headers = Map.empty,
      method = "GET"
    )
    val results = dataService.runAnalytics(
      AnalyticsRequest(
        request.queryString("metric"),
        request.queryString("group_by"),
        request.queryString("date_range"),
        request.queryString("filters"),
        request.queryString("output")
      )
    )
    val payload = results.map(_.toString).mkString(",")
    // Direct sink: SQL injection via analytics query from readLine
    val stmt = db.createStatement()
    stmt.executeQuery(s"INSERT INTO webhook_log (url, payload) VALUES ('$webhookUrl', '$payload')")
    integrations.sendWebhook(webhookUrl, payload)
  }
}

// Companion object holding mutable config -- used by Chain B
object CrossModuleConfig {
  var sortColumn: String = "created_at"
  var defaultTable: String = "records"
  var maxResults: Int = 100
}
