package micro

import java.sql.DriverManager
import sys.process._

class AuthService {
  private val conn = DriverManager.getConnection("jdbc:sqlite:auth.db")

  def verifyToken(token: String): Option[String] = {
    val stmt = conn.createStatement()
    val query = s"SELECT user_id FROM tokens WHERE token = '$token'"
    val rs = stmt.executeQuery(query) // sink: SQL injection
    if (rs.next()) Some(rs.getString("user_id")) else None
  }

  def runAdminCommand(userId: String, cmd: String): Unit = {
    if (userId.nonEmpty) {
      val fullCmd = s"notify-admin $cmd"
      fullCmd.! // sink: command injection
    }
  }
}
