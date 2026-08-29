package com.streaming.api

import java.sql.Connection
import scala.collection.mutable.ListBuffer

case class SearchCriteria(rawQuery: String, sortField: String, limit: String) {
  val filters: ListBuffer[String] = ListBuffer.empty

  def validate(): Unit = {
    if (rawQuery.length > 500) throw new IllegalArgumentException("Query too long")
  }

  // VULN: SQL injection in filter building
  def buildFilter(): Unit = {
    if (rawQuery.nonEmpty) {
      filters += s"name LIKE '%$rawQuery%'"
    }
    if (sortField.nonEmpty) {
      filters += s"ORDER BY $sortField"
    }
  }

  def toSQL: String = {
    val sql = new StringBuilder("SELECT * FROM data_records")
    if (filters.nonEmpty) {
      sql.append(" WHERE ")
      sql.append(filters.mkString(" AND "))
    }
    sql.append(s" LIMIT $limit")
    sql.toString()
  }
}

case class SearchParams(query: String, sortBy: String, limit: String, page: Int)

case class AnalyticsRequest(
  metric: String,
  groupBy: String,
  dateRange: String,
  filters: String,
  outputFormat: String
)

class DataService(db: Connection) {
  private val repository = new Repository(db)

  // Deep Chain: search -> validateCriteria -> normalizeCriteria -> enrichCriteria -> buildFilter -> repository
  def search(query: String, sortBy: String, limit: String): List[Map[String, Any]] = {
    val criteria = SearchCriteria(query, sortBy, limit)
    val validated = validateCriteria(criteria)
    val normalized = normalizeCriteria(validated)
    val enriched = enrichCriteria(normalized)
    enriched.buildFilter()
    repository.findByFilter(enriched)
  }

  private def validateCriteria(c: SearchCriteria): SearchCriteria = {
    c.validate()
    c
  }

  private def normalizeCriteria(c: SearchCriteria): SearchCriteria = {
    val trimmedQuery = c.rawQuery.trim.toLowerCase
    SearchCriteria(trimmedQuery, c.sortField, c.limit)
  }

  private def enrichCriteria(c: SearchCriteria): SearchCriteria = {
    val enrichedSort = if (c.sortField.isEmpty) "created_at" else c.sortField
    SearchCriteria(c.rawQuery, enrichedSort, c.limit)
  }

  // Deep Chain: processSearch -> extractQuery -> parseParams -> validateParams -> applyDefaults -> search
  def processSearch(params: SearchParams): List[Map[String, Any]] = {
    val extracted = extractQuery(params)
    val validated = validateSearchParams(extracted)
    val withDefaults = applySearchDefaults(validated)
    search(withDefaults.query, withDefaults.sortBy, withDefaults.limit)
  }

  private def extractQuery(params: SearchParams): SearchParams = {
    val cleaned = params.query.replaceAll("\\s+", " ").trim
    SearchParams(cleaned, params.sortBy, params.limit, params.page)
  }

  private def validateSearchParams(params: SearchParams): SearchParams = {
    if (params.query.length > 1000) {
      throw new IllegalArgumentException("Search query too long")
    }
    params
  }

  private def applySearchDefaults(params: SearchParams): SearchParams = {
    val sort = if (params.sortBy.isEmpty) "relevance" else params.sortBy
    val lim = if (params.limit.isEmpty) "25" else params.limit
    SearchParams(params.query, sort, lim, params.page)
  }

  // VULN: Deep analytics chain - SQL injection through 5+ hops in DataService alone
  // Full chain: ApiController.runAnalytics -> parseAnalyticsRequest -> validateAnalyticsRequest
  //   -> buildAnalyticsQuery -> optimizeQuery -> repository.executeRawQuery -> stmt.executeQuery
  def runAnalytics(request: AnalyticsRequest): List[Map[String, Any]] = {
    val validated = validateAnalyticsRequest(request)
    val query = buildAnalyticsQuery(validated)
    val optimized = optimizeQuery(query)
    repository.executeAnalyticsQuery(optimized)
  }

  private def validateAnalyticsRequest(req: AnalyticsRequest): AnalyticsRequest = {
    if (req.metric.isEmpty) throw new IllegalArgumentException("Metric required")
    if (req.groupBy.isEmpty) throw new IllegalArgumentException("GroupBy required")
    req
  }

  private def buildAnalyticsQuery(req: AnalyticsRequest): String = {
    val base = s"SELECT ${req.groupBy}, ${req.metric}(value) as result FROM data_records"
    val withFilters = if (req.filters.nonEmpty) {
      s"$base WHERE ${req.filters}"
    } else {
      base
    }
    val withGroupBy = s"$withFilters GROUP BY ${req.groupBy}"
    withGroupBy
  }

  private def optimizeQuery(query: String): String = {
    val optimized = query.replaceAll("\\s+", " ").trim
    optimized
  }

  // VULN: Deep export chain - command injection through multiple hops
  // Full chain: ApiController.exportAnalytics -> prepareExport -> buildExportCommand
  //   -> integrations.executeExport -> Runtime.exec
  def prepareExport(format: String, query: String, destination: String): String = {
    val exportQuery = buildExportQuery(query)
    val exportCmd = buildExportCommand(format, exportQuery, destination)
    exportCmd
  }

  private def buildExportQuery(query: String): String = {
    val cleaned = query.trim
    s"($cleaned)"
  }

  private def buildExportCommand(format: String, query: String, dest: String): String = {
    val cmd = s"analytics-export --format $format --query $query --dest $dest"
    cmd
  }

  def searchSafe(query: String, sortBy: String): List[Map[String, Any]] = {
    repository.findByFilterSafe(query, sortBy)
  }

  def getById(id: String): Option[Map[String, Any]] = {
    repository.findById(id)
  }

  def create(data: String): Map[String, Any] = {
    repository.create(data)
  }

  def update(id: String, data: String): Map[String, Any] = {
    repository.update(id, data)
  }

  def delete(id: String): Boolean = {
    repository.delete(id)
  }

  def getStats(): Map[String, Any] = {
    repository.getStats()
  }

  def aggregateByDate(startDate: String, endDate: String): List[Map[String, Any]] = {
    repository.aggregateByDate(startDate, endDate)
  }

  // VULN: SQL injection in custom aggregation
  def customAggregation(groupBy: String, metric: String): List[Map[String, Any]] = {
    val sql = s"SELECT $groupBy, $metric(value) as result FROM data_records GROUP BY $groupBy"
    repository.executeRawQuery(sql)
  }
}

class StreamProcessor {
  private val handlers = scala.collection.mutable.Map.empty[String, String => Unit]

  def registerHandler(eventType: String, handler: String => Unit): Unit = {
    handlers(eventType) = handler
  }

  def process(eventType: String, data: String): Unit = {
    handlers.get(eventType).foreach(handler => handler(data))
  }

  def processAll(events: List[(String, String)]): Unit = {
    events.foreach { case (eventType, data) => process(eventType, data) }
  }
}

class EventBus {
  private val subscribers = scala.collection.mutable.Map.empty[String, ListBuffer[String => Unit]]

  def subscribe(topic: String, handler: String => Unit): Unit = {
    subscribers.getOrElseUpdate(topic, ListBuffer.empty) += handler
  }

  def publish(topic: String, data: String): Unit = {
    subscribers.getOrElse(topic, ListBuffer.empty).foreach(handler => handler(data))
  }

  def unsubscribe(topic: String): Unit = {
    subscribers.remove(topic)
  }
}

class MetricsCollector(db: Connection) {
  private val repository = new Repository(db)

  def recordMetric(name: String, value: Double): Unit = {
    val sql = "INSERT INTO metrics (name, value, timestamp) VALUES (?, ?, datetime('now'))"
    val stmt = db.prepareStatement(sql)
    stmt.setString(1, name)
    stmt.setDouble(2, value)
    stmt.executeUpdate()
  }

  def getMetrics(name: String, hours: Int = 24): List[Map[String, Any]] = {
    val stmt = db.prepareStatement(
      "SELECT * FROM metrics WHERE name = ? AND timestamp > datetime('now', ?)"
    )
    stmt.setString(1, name)
    stmt.setString(2, s"-$hours hours")
    val rs = stmt.executeQuery()
    Repository.resultSetToList(rs)
  }
}
