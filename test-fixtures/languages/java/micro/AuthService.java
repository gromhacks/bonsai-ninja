package micro;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class AuthService {
    private Connection conn;

    public AuthService() throws Exception {
        conn = DriverManager.getConnection("jdbc:sqlite:auth.db");
    }

    public String verifyToken(String token) throws Exception {
        Statement stmt = conn.createStatement();
        String query = "SELECT user_id FROM tokens WHERE token = '" + token + "'";
        ResultSet rs = stmt.executeQuery(query);  // sink: SQL injection
        if (rs.next()) {
            return rs.getString("user_id");
        }
        return null;
    }

    public void runAdminCommand(String userId, String cmd) throws Exception {
        if (userId != null) {
            Runtime.getRuntime().exec("notify-admin " + cmd);  // sink: command injection
        }
    }
}
