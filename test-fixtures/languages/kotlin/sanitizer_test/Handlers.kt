// Kotlin sanitizer-fixture — mirrors the Java fixture.
package sanitizer_test

import java.sql.Connection
import org.springframework.web.util.HtmlUtils

class Handlers(private val conn: Connection) {

    fun sqlRaw(userId: String) =
        conn.createStatement().executeQuery("SELECT * FROM users WHERE id = '$userId'")

    fun sqlSafe(userId: String): java.sql.ResultSet {
        val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt.setString(1, userId)
        return stmt.executeQuery()
    }

    fun xssRaw(name: String): String = "<p>Hello, $name</p>"

    fun xssSafe(name: String): String {
        val safe = HtmlUtils.htmlEscape(name)
        return "<p>Hello, $safe</p>"
    }
}
