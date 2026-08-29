// Java sanitizer-fixture — parallel handlers per sink family.
package sanitizer_test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import org.springframework.web.util.HtmlUtils;

public class Handlers {
    private Connection conn;

    // --- SQL injection ----------------------------------------------------

    public ResultSet sqlRaw(String userId) throws Exception {
        // SOURCE userId → string-built SQL → executeQuery (SINK).
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    public ResultSet sqlSafe(String userId) throws Exception {
        // SOURCE userId → PreparedStatement bind (SANITIZER) → executeQuery.
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        return stmt.executeQuery();
    }

    // --- XSS --------------------------------------------------------------

    public String xssRaw(String name) {
        return "<p>Hello, " + name + "</p>";
    }

    public String xssSafe(String name) {
        String safe = HtmlUtils.htmlEscape(name);
        return "<p>Hello, " + safe + "</p>";
    }
}
