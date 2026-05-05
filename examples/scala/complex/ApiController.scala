package com.streaming.api

import java.sql.{Connection, DriverManager, Statement, PreparedStatement, ResultSet}
import java.io._
import java.net.URL
import scala.collection.mutable.ListBuffer

case class Request(
  queryString: Map[String, String],
  body: String,
  headers: Map[String, String],
  method: String
)

class ApiController(db: Connection) {
  private val dataService = new DataService(db)
  private val repository = new Repository(db)
  private val integrations = new Integrations()
  private val validators = new Validators()

  // VULN: SQL injection via deep search chain (10+ hops)
  // request.queryString -> extractSearchQuery -> parseSearchParams -> validateParams
  //   -> dataService.processSearch -> extractQuery -> validateSearchParams -> applySearchDefaults
  //   -> search -> validateCriteria -> normalizeCriteria -> enrichCriteria -> buildFilter
  //   -> repository.findByFilter -> criteria.toSQL -> stmt.executeQuery
  def searchData(request: Request): List[Map[String, Any]] = {
    val rawQuery = request.queryString.getOrElse("q", "")
    val rawSort = request.queryString.getOrElse("sort", "created_at")
    val rawLimit = request.queryString.getOrElse("limit", "50")
    val params = parseSearchParams(rawQuery, rawSort, rawLimit)
    val validated = validateRequestParams(params)
    dataService.processSearch(validated)
  }

  private def parseSearchParams(query: String, sort: String, limit: String): SearchParams = {
    val page = 1
    SearchParams(query, sort, limit, page)
  }

  private def validateRequestParams(params: SearchParams): SearchParams = {
    if (params.query.isEmpty) {
      throw new IllegalArgumentException("Query parameter required")
    }
    params
  }

  // Safe version
  def searchDataSafe(request: Request): List[Map[String, Any]] = {
    val query = request.queryString.getOrElse("q", "")
    val sortBy = request.queryString.getOrElse("sort", "created_at")
    dataService.searchSafe(query, sortBy)
  }

  def getData(request: Request): Option[Map[String, Any]] = {
    val id = request.queryString.getOrElse("id", "")
    repository.findById(id)
  }

  def createData(request: Request): Map[String, Any] = {
    val body = request.body
    repository.create(body)
  }

  // VULN: XSS via unsanitized output
  def renderDashboard(request: Request): String = {
    val search = request.queryString.getOrElse("search", "")
    val html = s"<html><body><h1>Dashboard</h1><p>Search: $search</p></body></html>"
    html
  }

  // Safe version
  def renderDashboardSafe(request: Request): String = {
    val search = Validators.escapeHtml(request.queryString.getOrElse("search", ""))
    s"<html><body><h1>Dashboard</h1><p>Search: $search</p></body></html>"
  }

  // VULN: Command injection via deep export chain (10+ hops)
  // request.queryString -> extractExportParams -> validateExportParams -> buildExportConfig
  //   -> dataService.prepareExport -> buildExportQuery -> buildExportCommand
  //   -> integrations.executeExport -> formatCommand -> Runtime.exec
  def exportAnalytics(request: Request): String = {
    val format = request.queryString.getOrElse("format", "csv")
    val query = request.queryString.getOrElse("query", "")
    val dest = request.queryString.getOrElse("dest", "/tmp/export")
    val params = extractExportParams(format, query, dest)
    val validated = validateExportParams(params)
    val config = buildExportConfig(validated)
    val cmd = dataService.prepareExport(config._1, config._2, config._3)
    integrations.executeExport(cmd)
  }

  private def extractExportParams(format: String, query: String, dest: String): (String, String, String) = {
    val cleanFormat = format.trim.toLowerCase
    val cleanQuery = query.trim
    val cleanDest = dest.trim
    (cleanFormat, cleanQuery, cleanDest)
  }

  private def validateExportParams(params: (String, String, String)): (String, String, String) = {
    if (params._1.isEmpty) throw new IllegalArgumentException("Format required")
    params
  }

  private def buildExportConfig(params: (String, String, String)): (String, String, String) = {
    val format = params._1
    val query = if (params._2.isEmpty) "SELECT * FROM data_records" else params._2
    val dest = params._3
    (format, query, dest)
  }

  // VULN: Deep analytics chain - SQL injection (10+ hops)
  // request.queryString -> extractAnalyticsParams -> parseAnalyticsRequest -> validateRequest
  //   -> dataService.runAnalytics -> validateAnalyticsRequest -> buildAnalyticsQuery
  //   -> optimizeQuery -> repository.executeAnalyticsQuery -> prepareAnalyticsSQL -> stmt.executeQuery
  def runAnalytics(request: Request): List[Map[String, Any]] = {
    val metric = request.queryString.getOrElse("metric", "")
    val groupBy = request.queryString.getOrElse("group_by", "")
    val dateRange = request.queryString.getOrElse("date_range", "")
    val filters = request.queryString.getOrElse("filters", "")
    val outputFormat = request.queryString.getOrElse("output", "json")
    val params = extractAnalyticsParams(metric, groupBy, dateRange, filters, outputFormat)
    val analyticsReq = parseAnalyticsRequest(params)
    dataService.runAnalytics(analyticsReq)
  }

  private def extractAnalyticsParams(
    metric: String, groupBy: String, dateRange: String, filters: String, outputFormat: String
  ): (String, String, String, String, String) = {
    (metric.trim, groupBy.trim, dateRange.trim, filters.trim, outputFormat.trim)
  }

  private def parseAnalyticsRequest(params: (String, String, String, String, String)): AnalyticsRequest = {
    AnalyticsRequest(params._1, params._2, params._3, params._4, params._5)
  }

  // VULN: Deep SSRF chain (10+ hops)
  // request.queryString -> extractWebhookParams -> validateWebhookUrl -> buildWebhookRequest
  //   -> dataService (no-op passthrough not needed, go via integrations directly)
  //   -> integrations.dispatchWebhook -> resolveEndpoint -> buildConnection -> sendRequest -> URL
  def triggerWebhook(request: Request): String = {
    val rawUrl = request.queryString.getOrElse("url", "")
    val rawPayload = request.body
    val params = extractWebhookParams(rawUrl, rawPayload)
    val prepared = prepareWebhookPayload(params)
    integrations.dispatchWebhook(prepared._1, prepared._2)
  }

  private def extractWebhookParams(url: String, payload: String): (String, String) = {
    val trimmedUrl = url.trim
    val trimmedPayload = payload.trim
    (trimmedUrl, trimmedPayload)
  }

  private def prepareWebhookPayload(params: (String, String)): (String, String) = {
    val url = params._1
    val payload = if (params._2.isEmpty) "{}" else params._2
    (url, payload)
  }

  // VULN: Command injection
  def runExport(request: Request): String = {
    val format = request.queryString.getOrElse("format", "csv")
    val cmd = s"data-export --format $format --output /tmp/export"
    Runtime.getRuntime.exec(cmd)
    "Export started"
  }

  // VULN: Deserialization
  def importData(request: Request): Any = {
    val data = java.util.Base64.getDecoder.decode(request.body)
    val ois = new ObjectInputStream(new ByteArrayInputStream(data))
    ois.readObject()
  }

  // VULN: JNDI injection
  def lookupResource(request: Request): Any = {
    val name = request.queryString.getOrElse("resource", "")
    val ctx = new javax.naming.InitialContext()
    ctx.lookup(name)
  }

  // VULN: Path traversal
  def downloadFile(request: Request): String = {
    val filename = request.queryString.getOrElse("file", "")
    val path = s"/var/data/exports/$filename"
    scala.io.Source.fromFile(path).mkString
  }

  // Safe version
  def downloadFileSafe(request: Request): String = {
    val filename = new File(request.queryString.getOrElse("file", "")).getName
    val path = new File(s"/var/data/exports/$filename")
    val canonical = path.getCanonicalPath
    if (!canonical.startsWith(new File("/var/data/exports").getCanonicalPath)) {
      throw new SecurityException("Invalid path")
    }
    scala.io.Source.fromFile(path).mkString
  }

  // VULN: Template injection
  def renderTemplate(request: Request): String = {
    val template = request.queryString.getOrElse("template", "")
    val data = request.body
    var result = template
    result
  }

  // VULN: SQL injection in admin query
  def adminQuery(request: Request): List[Map[String, Any]] = {
    val sql = request.queryString.getOrElse("sql", "")
    repository.executeRawQuery(sql)
  }

  // VULN: Deep path traversal chain (10+ hops)
  // request.queryString -> extractFileParams -> resolveFilePath -> normalizeFilePath
  //   -> repository.readDataFile -> buildFilePath -> openFileStream -> Source.fromFile
  def readDataFile(request: Request): String = {
    val rawPath = request.queryString.getOrElse("path", "")
    val rawBase = request.queryString.getOrElse("base", "/var/data")
    val params = extractFileParams(rawPath, rawBase)
    val resolved = resolveFilePath(params)
    repository.readDataFile(resolved)
  }

  private def extractFileParams(path: String, base: String): (String, String) = {
    val cleanPath = path.trim
    val cleanBase = base.trim
    (cleanPath, cleanBase)
  }

  private def resolveFilePath(params: (String, String)): String = {
    val fullPath = s"${params._2}/${params._1}"
    fullPath
  }
}
