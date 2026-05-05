/**
 * Auth annotation patterns for testing decorator flow analysis.
 * Kotlin uses @Annotation syntax with concise declaration syntax.
 */

import java.sql.Connection
import java.sql.DriverManager
import java.security.MessageDigest

// --- Custom auth annotations ---

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION)
annotation class Authenticated

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION)
annotation class AdminOnly

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION)
annotation class RateLimit(val maxCalls: Int = 10)

// --- Controller using auth annotations ---

data class UserProfile(val id: String, val name: String)

class UserController {

    @Authenticated
    fun getProfile(userId: String): String {
        // VULN: SQL injection in authenticated endpoint
        val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        val stmt = conn.createStatement()
        return stmt.executeQuery("SELECT * FROM users WHERE id = $userId").toString()
    }

    @Authenticated
    @RateLimit(maxCalls = 5)
    fun changePassword(oldPassword: String, newPassword: String) {
        // VULN: weak MD5 hash + SQL injection
        val md = MessageDigest.getInstance("MD5")
        val hash = md.digest(newPassword.toByteArray())
        val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        val stmt = conn.createStatement()
        stmt.execute("UPDATE users SET password = '${String(hash)}'")
    }

    @AdminOnly
    fun deleteUser(targetId: String) {
        // VULN: SQL injection in admin-only endpoint
        val conn: Connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        val stmt = conn.createStatement()
        stmt.execute("DELETE FROM users WHERE id = $targetId")
    }

    @AdminOnly
    fun runCommand(cmd: String): String {
        // VULN: command injection in admin-only endpoint
        val process = Runtime.getRuntime().exec(cmd)
        return String(process.inputStream.readAllBytes())
    }
}

fun main(args: Array<String>) {
    val ctrl = UserController()
    val input = args[0]
    ctrl.getProfile(input)
    ctrl.deleteUser(input)
    ctrl.runCommand(input)
}
