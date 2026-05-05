/**
 * Auth annotation patterns for testing decorator flow analysis.
 * Scala uses custom annotations extending StaticAnnotation.
 */

import java.sql.{Connection, DriverManager, Statement}
import scala.annotation.StaticAnnotation

// --- Custom auth annotations ---

class Authenticated extends StaticAnnotation
class AdminOnly extends StaticAnnotation
class RateLimit(maxCalls: Int) extends StaticAnnotation

// --- Controller using auth annotations ---

class UserController {

  @Authenticated
  def getProfile(userId: String): String = {
    // VULN: SQL injection in authenticated endpoint
    val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt: Statement = conn.createStatement()
    stmt.executeQuery(s"SELECT * FROM users WHERE id = $userId").toString
  }

  @Authenticated
  @RateLimit(5)
  def changePassword(oldPassword: String, newPassword: String): Unit = {
    // VULN: weak hash + SQL injection
    val md = java.security.MessageDigest.getInstance("MD5")
    val hash = md.digest(newPassword.getBytes)
    val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt: Statement = conn.createStatement()
    stmt.execute(s"UPDATE users SET password = '${new String(hash)}'")
  }

  @AdminOnly
  def deleteUser(targetId: String): Unit = {
    // VULN: SQL injection in admin-only endpoint
    val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt: Statement = conn.createStatement()
    stmt.execute(s"DELETE FROM users WHERE id = $targetId")
  }

  @AdminOnly
  def runCommand(cmd: String): String = {
    // VULN: command injection in admin-only endpoint
    val process = Runtime.getRuntime.exec(cmd)
    new String(process.getInputStream.readAllBytes())
  }
}

// --- Entry point ---

object AuthAnnotations {
  def main(args: Array[String]): Unit = {
    val ctrl = new UserController()
    val input = args(0)
    ctrl.getProfile(input)
    ctrl.deleteUser(input)
    ctrl.runCommand(input)
  }
}
