// Scala sanitizer-fixture — parallel handlers per sink family.
package sanitizer_test

import java.sql.{Connection, PreparedStatement, ResultSet, Statement}
import org.springframework.web.util.HtmlUtils

class Handlers(conn: Connection) {

  def sqlRaw(userId: String): ResultSet = {
    val stmt: Statement = conn.createStatement()
    stmt.executeQuery(s"SELECT * FROM users WHERE id = '$userId'")
  }

  def sqlSafe(userId: String): ResultSet = {
    val stmt: PreparedStatement =
      conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, userId)
    stmt.executeQuery()
  }

  def xssRaw(name: String): String = s"<p>Hello, $name</p>"

  def xssSafe(name: String): String = {
    val safe = HtmlUtils.htmlEscape(name)
    s"<p>Hello, $safe</p>"
  }
}
