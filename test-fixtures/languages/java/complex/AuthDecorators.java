/**
 * Auth annotation patterns for testing decorator flow analysis.
 * Java uses @Annotation syntax for method-level metadata.
 */

import java.lang.annotation.*;
import java.sql.*;

// --- Custom auth annotations ---

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface Authenticated {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface AdminOnly {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface RateLimit {
    int maxCalls() default 10;
}

// --- Controller using auth annotations ---

class UserController {

    @Authenticated
    public String getProfile(String userId) throws SQLException {
        // VULN: SQL injection in authenticated endpoint
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId).toString();
    }

    @Authenticated
    @RateLimit(maxCalls = 5)
    public void changePassword(String oldPw, String newPw) throws Exception {
        // VULN: weak hash + SQL injection
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(newPw.getBytes());
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        stmt.execute("UPDATE users SET password = '" + new String(hash) + "'");
    }

    @AdminOnly
    public void deleteUser(String targetId) throws SQLException {
        // VULN: SQL injection in admin-only endpoint
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        stmt.execute("DELETE FROM users WHERE id = " + targetId);
    }

    @AdminOnly
    public String runCommand(String cmd) throws Exception {
        // VULN: command injection in admin-only endpoint
        Process p = Runtime.getRuntime().exec(cmd);
        return new String(p.getInputStream().readAllBytes());
    }

    public static void main(String[] args) throws Exception {
        UserController ctrl = new UserController();
        String input = args[0];
        ctrl.getProfile(input);
        ctrl.deleteUser(input);
        ctrl.runCommand(input);
    }
}
