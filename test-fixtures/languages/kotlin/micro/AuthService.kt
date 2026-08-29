package micro

import java.sql.DriverManager

class AuthService {
    private val conn = DriverManager.getConnection("jdbc:sqlite:auth.db")

    fun verifyToken(token: String): String? {
        val stmt = conn.createStatement()
        val query = "SELECT user_id FROM tokens WHERE token = '$token'"
        val rs = stmt.executeQuery(query) // sink: SQL injection
        return if (rs.next()) rs.getString("user_id") else null
    }

    fun runAdminCommand(userId: String, cmd: String) {
        if (userId.isNotEmpty()) {
            Runtime.getRuntime().exec("notify-admin $cmd") // sink: command injection
        }
    }
}
