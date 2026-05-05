package com.streaming.api

import java.sql.{Connection, Statement, ResultSet}
import java.io.{File, FileWriter, BufferedWriter}
import scala.collection.mutable.ListBuffer
import scala.concurrent.{Future, ExecutionContext}
import scala.util.{Try, Success, Failure}

// --- Case classes for pattern matching ---

sealed trait UserInput
case class SearchInput(query: String, filters: Map[String, String]) extends UserInput
case class CommandInput(program: String, args: List[String]) extends UserInput
case class FileInput(path: String, encoding: String) extends UserInput

case class QueryParts(select: String, from: String, where: String, orderBy: String)

case class ExportRequest(format: String, destination: String, data: String)

// --- Companion object with factory ---

object QueryBuilder {
  // VULN 8 (Companion object factory -> SQL injection):
  // System.getenv("QUERY_TEMPLATE") -> QueryBuilder.fromTemplate(tpl)
  //   -> QueryBuilder(tpl) constructor -> qb.buildSQL() -> s"" interpolation -> stmt.executeQuery
  // The companion factory passes env input straight into the query template field.
  def fromTemplate(template: String): QueryBuilder = {
    val trimmed = template.trim
    new QueryBuilder(trimmed)
  }

  def fromEnv(): QueryBuilder = {
    val tpl = System.getenv("QUERY_TEMPLATE")
    fromTemplate(tpl)
  }
}

class QueryBuilder(template: String) {
  private var conditions = ListBuffer.empty[String]

  def addCondition(cond: String): QueryBuilder = {
    conditions += cond
    this
  }

  def buildSQL(): String = {
    val base = template
    if (conditions.nonEmpty) {
      s"$base WHERE ${conditions.mkString(" AND ")}"
    } else {
      base
    }
  }
}

// --- Main class exercising advanced Scala patterns ---

class AdvancedPatterns(db: Connection)(implicit ec: ExecutionContext) {

  // VULN 1 (Pattern matching with case class extraction -> SQL injection):
  // readLine() -> SearchInput(query, filters) -> case SearchInput(q, f) =>
  //   extractSearchTerm(q) -> buildSearchQuery(term) -> s"SELECT ... $term ..."
  //   -> stmt.executeQuery(sql)
  // Taint flows through case class construction and unapply extraction.
  def processUserSearch(): String = {
    val userQuery = scala.io.StdIn.readLine("Search query: ")
    val term = extractSearchTerm(userQuery)
    val sql = buildSearchQuery(term)
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    "search executed"
  }

  def handleUserInput(input: UserInput): String = {
    input match {
      case SearchInput(query, filters) =>
        val term = extractSearchTerm(query)
        val sql = buildSearchQuery(term)
        val stmt = db.createStatement()
        val rs = stmt.executeQuery(sql)
        "search executed"

      case CommandInput(program, args) =>
        val cmd = assembleCommand(program, args)
        new ProcessBuilder(cmd).start()
        "command executed"

      case FileInput(path, encoding) =>
        val resolved = resolvePath(path)
        scala.io.Source.fromFile(resolved, encoding).mkString
    }
  }

  private def extractSearchTerm(raw: String): String = {
    val trimmed = raw.trim.toLowerCase
    trimmed
  }

  private def buildSearchQuery(term: String): String = {
    val sql = s"SELECT * FROM records WHERE name LIKE '%$term%'"
    sql
  }

  private def assembleCommand(program: String, args: List[String]): String = {
    val joined = args.mkString(" ")
    s"$program $joined"
  }

  private def resolvePath(path: String): String = {
    val normalized = path.replaceAll("//+", "/")
    s"/var/data/$normalized"
  }

  // VULN 2 (For-comprehension / flatMap chain -> SQL injection):
  // System.getenv("REPORT_FIELDS") -> parseFields(raw) -> for { field <- fields; validated <- validateField(field) }
  //   yield validated -> validFields.mkString(", ") -> s"SELECT $columns FROM ..." -> stmt.executeQuery
  // Taint propagates through the for-comprehension's flatMap/map desugaring.
  def generateReport(): List[Map[String, Any]] = {
    val rawFields = System.getenv("REPORT_FIELDS")
    val fields = parseFields(rawFields)
    val validFields = for {
      field <- fields
      validated <- validateFieldName(field)
    } yield validated
    val columns = validFields.mkString(", ")
    val sql = s"SELECT $columns FROM analytics_data"
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  private def parseFields(raw: String): List[String] = {
    val parts = raw.split(",").toList
    parts.map(_.trim).filter(_.nonEmpty)
  }

  private def validateFieldName(field: String): Option[String] = {
    if (field.length > 64) None
    else Some(field)
  }

  // VULN 3 (Partial function -> command injection):
  // scala.io.StdIn.readLine() -> dispatchAction via partial function match
  //   -> case s if s.startsWith("run:") => extractCommand(s) -> executeSystemCmd(cmd) -> Runtime.exec
  // Taint passes through a PartialFunction literal's case guard and extraction.
  def dispatchAction(): String = {
    val action = scala.io.StdIn.readLine("Enter action: ")
    // Direct sink: command injection via partial function dispatch
    val cmd = extractCommand(action)
    new ProcessBuilder(cmd).start()
    val handler: PartialFunction[String, String] = {
      case s if s.startsWith("run:") =>
        val cmd = extractCommand(s)
        executeSystemCmd(cmd)
      case s if s.startsWith("query:") =>
        val sql = s.stripPrefix("query:")
        executeRawSQL(sql)
      case other =>
        s"Unknown action: $other"
    }
    handler(action)
  }

  private def extractCommand(action: String): String = {
    val cmd = action.stripPrefix("run:").trim
    cmd
  }

  private def executeSystemCmd(cmd: String): String = {
    new ProcessBuilder(cmd).start()
    s"Executed: $cmd"
  }

  private def executeRawSQL(sql: String): String = {
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    "query executed"
  }

  // VULN 4 (Implicit conversion -> SQL injection):
  // readLine() -> implicit queryToSQL conversion -> QueryParts -> qp.toFullSQL()
  //   -> s"SELECT $select FROM $from WHERE $where ORDER BY $orderBy" -> stmt.executeQuery
  // An implicit def silently converts a raw string into QueryParts that flows to SQL.
  implicit def stringToQueryParts(raw: String): QueryParts = {
    val segments = raw.split("\\|")
    val select = if (segments.length > 0) segments(0).trim else "*"
    val from = if (segments.length > 1) segments(1).trim else "records"
    val where = if (segments.length > 2) segments(2).trim else "1=1"
    val orderBy = if (segments.length > 3) segments(3).trim else "id"
    QueryParts(select, from, where, orderBy)
  }

  def runImplicitQuery(): List[Map[String, Any]] = {
    val userSpec = scala.io.StdIn.readLine("Enter query spec (select|from|where|order): ")
    val parts: QueryParts = userSpec
    val sql = toFullSQL(parts)
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  private def toFullSQL(qp: QueryParts): String = {
    s"SELECT ${qp.select} FROM ${qp.from} WHERE ${qp.where} ORDER BY ${qp.orderBy}"
  }

  // VULN 5 (Either fold -> command injection):
  // System.getenv("BACKUP_CMD") -> parseBackupConfig(env) -> Right(cmd) -> either.fold(...)
  //   -> formatBackupCommand(cmd) -> Runtime.exec
  // Taint propagates through Either.fold's right-branch function.
  def runBackup(): String = {
    val rawConfig = System.getenv("BACKUP_CMD")
    val parsed = parseBackupConfig(rawConfig)
    // Direct sink: command injection via env-configured backup command
    val formatted = formatBackupCommand(rawConfig)
    new ProcessBuilder(formatted).start()
    parsed.fold(
      error => s"Config error: $error",
      cmd => {
        val fmtCmd = formatBackupCommand(cmd)
        new ProcessBuilder(fmtCmd).start()
        "Backup started"
      }
    )
  }

  private def parseBackupConfig(raw: String): Either[String, String] = {
    if (raw == null || raw.isEmpty) Left("No backup command configured")
    else Right(raw.trim)
  }

  private def formatBackupCommand(cmd: String): String = {
    val formatted = s"/bin/sh -c $cmd"
    formatted
  }

  // VULN 6 (Option map/flatMap chain -> SQL injection):
  // System.getenv("TABLE_OVERRIDE") -> Option(env) -> .map(_.trim) -> .flatMap(validateTable)
  //   -> .map(buildTableQuery) -> .getOrElse(default) -> stmt.executeQuery
  // Taint flows through the Option monad's map/flatMap chain without sanitization.
  def queryWithTableOverride(): List[Map[String, Any]] = {
    val envTable = System.getenv("TABLE_OVERRIDE")
    val sql = Option(envTable)
      .map(_.trim)
      .flatMap(normalizeTableName)
      .map(buildTableQuery)
      .getOrElse("SELECT * FROM default_table")
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  private def normalizeTableName(name: String): Option[String] = {
    if (name.isEmpty) None
    else Some(name.toLowerCase)
  }

  private def buildTableQuery(table: String): String = {
    s"SELECT * FROM $table LIMIT 100"
  }

  // VULN 7 (Lazy val -> file write):
  // System.getenv("LOG_PATH") -> lazy val logPath -> ensureLogDir(logPath)
  //   -> writeLogEntry(logPath, readLine()) -> new FileWriter(logPath) -> fw.write(entry)
  // The lazy val defers evaluation but still carries taint when finally forced.
  lazy val logPath: String = {
    val envPath = System.getenv("LOG_PATH")
    val resolved = if (envPath != null) envPath.trim else "/tmp/app.log"
    resolved
  }

  def writeUserLog(): Unit = {
    val entry = scala.io.StdIn.readLine("Log entry: ")
    val dir = ensureLogDir(logPath)
    writeLogEntry(dir, entry)
  }

  private def ensureLogDir(path: String): String = {
    val file = new File(path)
    file.getParentFile.mkdirs()
    path
  }

  private def writeLogEntry(path: String, entry: String): Unit = {
    val fw = new FileWriter(path, true)
    val bw = new BufferedWriter(fw)
    bw.write(entry)
    bw.newLine()
    bw.close()
  }

  // VULN 9 (Case class copy -> SQL injection):
  // readLine() -> ExportRequest.copy(data = userInput) -> processExport(modified)
  //   -> buildExportSQL(req.data) -> s"INSERT ... VALUES ('$data')" -> stmt.executeQuery
  // Taint introduced via .copy() on an otherwise-safe case class instance.
  def handleExportWithOverride(): String = {
    val base = ExportRequest("csv", "/tmp/out", "SELECT 1")
    val userOverride = scala.io.StdIn.readLine("Override data query: ")
    val modified = base.copy(data = userOverride)
    processExport(modified)
  }

  private def processExport(req: ExportRequest): String = {
    val sql = buildExportSQL(req.data)
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    s"Exported to ${req.destination}"
  }

  private def buildExportSQL(data: String): String = {
    s"INSERT INTO export_queue (query) VALUES ('$data')"
  }

  // VULN 10 (Curried function -> command injection):
  // System.getenv("DEPLOY_TARGET") -> deployTo(target)(readLine()) -> buildDeployCmd(target, version)
  //   -> executeDeployment(cmd) -> Runtime.exec
  // Taint enters via both curried argument positions from separate sources.
  def deployTo(target: String)(version: String): String = {
    val cmd = buildDeployCmd(target, version)
    executeDeployment(cmd)
  }

  def triggerDeploy(): String = {
    val target = System.getenv("DEPLOY_TARGET")
    val version = scala.io.StdIn.readLine("Version to deploy: ")
    // Direct sink: command injection via deploy target and version
    val cmd = buildDeployCmd(target, version)
    new ProcessBuilder(cmd).start()
    deployTo(target)(version)
  }

  private def buildDeployCmd(target: String, version: String): String = {
    s"deploy --target $target --version $version"
  }

  private def executeDeployment(cmd: String): String = {
    new ProcessBuilder(cmd).start()
    "Deployment triggered"
  }

  // VULN 11 (Future chain map/flatMap -> SQL injection):
  // readLine() -> Future.successful(input) -> .map(sanitizeInput) -> .flatMap(lookupUser)
  //   -> .map(buildUserQuery) -> executeAsync(sql) -> stmt.executeQuery
  // Taint propagates through Future's monadic chain without actual sanitization.
  def asyncLookup(): Future[List[Map[String, Any]]] = {
    val rawInput = scala.io.StdIn.readLine("Username: ")
    // Direct sink: SQL injection via username in async lookup
    val sql = buildUserQuery(rawInput)
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    Future.successful(rawInput)
      .map(normalizeUsername)
      .flatMap(lookupUserAsync)
      .map(buildUserQuery)
      .map(executeQuerySync)
  }

  private def normalizeUsername(input: String): String = {
    input.trim.toLowerCase
  }

  private def lookupUserAsync(username: String): Future[String] = {
    Future.successful(username)
  }

  private def buildUserQuery(username: String): String = {
    s"SELECT * FROM users WHERE username = '$username'"
  }

  private def executeQuerySync(sql: String): List[Map[String, Any]] = {
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  // VULN 12 (mkString collector -> SQL injection):
  // readLine() (multi-line) -> collectInputLines() -> lines.mkString(" UNION ")
  //   -> wrapInSubquery(combined) -> s"SELECT * FROM ($combined) sub" -> stmt.executeQuery
  // Multiple tainted lines collected and joined with mkString flow into SQL.
  def batchQuery(): List[Map[String, Any]] = {
    val firstLine = scala.io.StdIn.readLine("First SQL query: ")
    val secondLine = scala.io.StdIn.readLine("SQL line (empty to finish): ")
    val thirdLine = scala.io.StdIn.readLine("SQL line (empty to finish): ")
    val combined = s"$firstLine UNION $secondLine UNION $thirdLine"
    val sql = wrapInSubquery(combined)
    val stmt = db.createStatement()
    val rs = stmt.executeQuery(sql)
    Repository.resultSetToList(rs)
  }

  private def wrapInSubquery(query: String): String = {
    s"SELECT * FROM ($query) AS combined_results"
  }

  // Exercise QueryBuilder.fromEnv and handleUserInput so their sources are reachable
  def runEnvQuery(): String = {
    val qb = QueryBuilder.fromEnv()
    val sql = qb.buildSQL()
    val stmt = db.createStatement()
    stmt.executeQuery(sql)
    sql
  }

  def runInputHandler(): String = {
    val path = scala.io.StdIn.readLine("File path: ")
    handleUserInput(FileInput(path, "UTF-8"))
  }
}

  // ============================================================
  // ADDITIONAL PATTERNS - Process operators, for-comprehensions
  // ============================================================

  // Process execution operators
  def processOperators(input: String): Unit = {
    import scala.sys.process._
    input.!        // bang operator - execute command
    input.!!       // double bang - execute and capture output
  }

  // For-comprehension with taint flow
  def forComprehensionFlow(inputs: List[String]): List[String] = {
    for {
      input <- inputs
      if input.nonEmpty
      result = input.toUpperCase  // taint propagates
    } yield result
  }

  // Case class copy with tainted field
  case class Config(host: String, command: String)

  def caseClassFlow(userCmd: String): Unit = {
    val config = Config("localhost", userCmd)
    val modified = config.copy(host = "remote")  // command field preserved
    import scala.sys.process._
    modified.command.!  // taint flows through case class copy
  }

  // Pattern matching with extraction
  def patternExtraction(input: Any): String = {
    input match {
      case s: String if s.nonEmpty => s  // type check + guard
      case (a: String, _: Int) => a     // tuple extraction
      case list: List[_] => list.mkString(",")
      case _ => "safe"
    }
  }

  // Implicit conversion flow
  implicit class StringOps(val s: String) {
    def execute(): Unit = {
      import scala.sys.process._
      s.!  // taint flows through implicit conversion
    }
  }

  def implicitFlow(input: String): Unit = {
    input.execute()  // implicit method call
  }

  // Higher-order function with taint
  def withResource[T](resource: String)(f: String => T): T = {
    f(resource)  // taint flows through HOF
  }

  def hofFlow(input: String): Unit = {
    withResource(input) { cmd =>
      import scala.sys.process._
      cmd.!
    }
  }

  // Type parameter bound
  def processAny[T <: Serializable](input: T): String = {
    input.toString
  }
