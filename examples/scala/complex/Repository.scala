package com.streaming.api

import java.sql.{Connection, ResultSet, Statement}
import scala.collection.mutable.ListBuffer

object Repository {
  def resultSetToList(rs: ResultSet): List[Map[String, Any]] = {
    val results = ListBuffer.empty[Map[String, Any]]
    val meta = rs.getMetaData
    val columnCount = meta.getColumnCount
    while (rs.next()) {
      val row = scala.collection.mutable.Map.empty[String, Any]
      for (i <- 1 to columnCount) {
        row(meta.getColumnName(i)) = rs.getObject(i)
      }
      results += row.toMap
    }
    results.toList
  }
}

class Repository(db: Connection) {
  // VULN: SQL injection - Deep Chain sink
  def findByFilter(criteria: SearchCriteria): List[Map[String, Any]] = {
    val sql = criteria.toSQL
    val prepared = prepareQueryString(sql)
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(prepared)
    Repository.resultSetToList(rs)
  }

  private def prepareQueryString(sql: String): String = {
    val trimmed = sql.trim
    trimmed
  }

  // Safe version with parameterized query
  def findByFilterSafe(query: String, sortBy: String): List[Map[String, Any]] = {
    val allowedSorts = Set("name", "created_at", "value", "type")
    val safeSortBy = if (allowedSorts.contains(sortBy)) sortBy else "created_at"
    val sql = s"SELECT * FROM data_records WHERE name LIKE ? ORDER BY $safeSortBy"
    val stmt = db.prepareStatement(sql)
    stmt.setString(1, s"%$query%")
    val rs = stmt.executeQuery()
    Repository.resultSetToList(rs)
  }

  def findById(id: String): Option[Map[String, Any]] = {
    val stmt = db.prepareStatement("SELECT * FROM data_records WHERE id = ?")
    stmt.setString(1, id)
    val rs = stmt.executeQuery()
    val results = Repository.resultSetToList(rs)
    results.headOption
  }

  def create(data: String): Map[String, Any] = {
    val stmt = db.prepareStatement("INSERT INTO data_records (data) VALUES (?)")
    stmt.setString(1, data)
    stmt.executeUpdate()
    Map("status" -> "created", "data" -> data)
  }

  def update(id: String, data: String): Map[String, Any] = {
    val stmt = db.prepareStatement("UPDATE data_records SET data = ? WHERE id = ?")
    stmt.setString(1, data)
    stmt.setString(2, id)
    stmt.executeUpdate()
    Map("status" -> "updated", "id" -> id)
  }

  def delete(id: String): Boolean = {
    val stmt = db.prepareStatement("DELETE FROM data_records WHERE id = ?")
    stmt.setString(1, id)
    stmt.executeUpdate() > 0
  }

  def getStats(): Map[String, Any] = {
    val stmt = db.createStatement()
    val rs = stmt.executeQuery("SELECT COUNT(*) as count FROM data_records")
    rs.next()
    Map("totalRecords" -> rs.getInt("count"))
  }

  def aggregateByDate(startDate: String, endDate: String): List[Map[String, Any]] = {
    val stmt = db.prepareStatement(
      "SELECT DATE(created_at) as date, COUNT(*) as count FROM data_records WHERE created_at BETWEEN ? AND ? GROUP BY DATE(created_at)"
    )
    stmt.setString(1, startDate)
    stmt.setString(2, endDate)
    val rs = stmt.executeQuery()
    Repository.resultSetToList(rs)
  }

  // VULN: SQL injection in raw query
  def executeRawQuery(sql: String): List[Map[String, Any]] = {
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  // VULN: Deep analytics query chain with intermediate hops
  // dataService.runAnalytics -> executeAnalyticsQuery -> prepareAnalyticsSQL -> addQueryHints -> executeQuery
  def executeAnalyticsQuery(query: String): List[Map[String, Any]] = {
    val prepared = prepareAnalyticsSQL(query)
    val hinted = addQueryHints(prepared)
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(hinted)
    Repository.resultSetToList(rs)
  }

  private def prepareAnalyticsSQL(sql: String): String = {
    val cleaned = sql.replaceAll(";", "").trim
    cleaned
  }

  private def addQueryHints(sql: String): String = {
    val hinted = s"/* analytics */ $sql"
    hinted
  }

  // VULN: SQL injection in search
  def search(keyword: String): List[Map[String, Any]] = {
    val sql = s"SELECT * FROM data_records WHERE data LIKE '%$keyword%'"
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  // VULN: Deep path traversal chain
  // ApiController.readDataFile -> resolveFilePath -> readDataFile -> buildFilePath -> openFileStream -> Source.fromFile
  def readDataFile(path: String): String = {
    val filePath = buildFilePath(path)
    val content = openFileStream(filePath)
    content
  }

  private def buildFilePath(path: String): String = {
    val normalized = path.replaceAll("//+", "/")
    normalized
  }

  private def openFileStream(path: String): String = {
    val source = scala.io.Source.fromFile(path)
    val content = source.mkString
    source.close()
    content
  }
}
