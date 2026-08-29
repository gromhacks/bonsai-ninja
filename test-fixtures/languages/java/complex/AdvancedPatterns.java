package com.bank.api;

import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdvancedPatterns {

    private Connection connection;

    public AdvancedPatterns(Connection connection) {
        this.connection = connection;
    }

    // ============================================================
    // VULN 1: Stream API chain flowing taint to SQL
    // Chain: request.getParameter() -> stream().map().filter().collect()
    //        -> String.join() -> Statement.executeQuery()
    // The taint flows through the Stream pipeline's map/filter/collect
    // operations without sanitization, ending up in a raw SQL query.
    // ============================================================

    public void searchByTags(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tagsParam = request.getParameter("tags");
        String[] rawTags = tagsParam.split(",");

        String whereClause = Arrays.stream(rawTags)
            .map(tag -> tag.trim())
            .filter(tag -> !tag.isEmpty())
            .map(tag -> "tag = '" + tag + "'")
            .collect(Collectors.joining(" OR "));

        String sql = "SELECT * FROM accounts WHERE " + whereClause;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 2: Optional chain preserving taint
    // Chain: request.getParameter() -> Optional.ofNullable()
    //        -> .map() -> .orElse() -> Statement.executeQuery()
    // The Optional wrapper does not sanitize; .map() transforms
    // the tainted value into a SQL fragment, and .orElse() unwraps it.
    // ============================================================

    public void findAccountByAlias(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String alias = request.getParameter("alias");

        String condition = Optional.ofNullable(alias)
            .map(a -> "alias = '" + a + "'")
            .orElse("1=0");

        String sql = "SELECT * FROM accounts WHERE " + condition;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 3: Lambda as argument to method
    // Chain: request.getParameter() -> processWithTransform() lambda arg
    //        -> transform.apply() -> Statement.executeQuery()
    // The tainted value is passed to a higher-order method that
    // applies a caller-supplied lambda, which builds unsafe SQL.
    // ============================================================

    public void searchWithTransform(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("search");

        String result = processWithTransform(input, value -> "name LIKE '%" + value + "%'");

        String sql = "SELECT * FROM accounts WHERE " + result;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    private String processWithTransform(String value, Function<String, String> transform) {
        if (value == null) {
            return "1=1";
        }
        return transform.apply(value);
    }

    // ============================================================
    // VULN 4: Method reference (Class::method)
    // Chain: request.getParameter() -> List.of() -> stream()
    //        -> .map(AdvancedPatterns::toSqlLiteral) -> collect()
    //        -> Statement.executeQuery()
    // The method reference AdvancedPatterns::toSqlLiteral wraps
    // each tainted element into a SQL literal without escaping.
    // ============================================================

    public void searchByIds(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String idsParam = request.getParameter("ids");
        List<String> ids = List.of(idsParam.split(","));

        String inClause = ids.stream()
            .map(AdvancedPatterns::toSqlLiteral)
            .collect(Collectors.joining(", "));

        String sql = "SELECT * FROM accounts WHERE id IN (" + inClause + ")";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    private static String toSqlLiteral(String value) {
        return "'" + value.trim() + "'";
    }

    // ============================================================
    // VULN 5: Try-with-resources with tainted path
    // Chain: request.getParameter() -> new File() -> new FileInputStream()
    //        -> try-with-resources block -> response output
    // The user-controlled filename is used directly to construct a
    // File path, enabling path traversal attacks.
    // ============================================================

    public void readDocument(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String docName = request.getParameter("doc");
        String basePath = "/var/bank/documents/";
        File target = new File(basePath + docName);

        try (FileInputStream fis = new FileInputStream(target);
             BufferedInputStream bis = new BufferedInputStream(fis)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }

    // ============================================================
    // VULN 6: instanceof pattern matching (Java 16+)
    // Chain: request.getParameter() -> parseInput() returns Object
    //        -> instanceof String s -> s used in SQL
    // The instanceof pattern variable `s` captures the tainted
    // string, which then flows unsanitized into a SQL statement.
    // ============================================================

    public void handleDynamicInput(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("filter");
        Object parsed = parseInput(raw);

        if (parsed instanceof String s) {
            String sql = "SELECT * FROM accounts WHERE " + s;
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            writeResults(response, rs);
        }
    }

    private Object parseInput(String raw) {
        if (raw == null) {
            return Integer.valueOf(0);
        }
        return raw;
    }

    // ============================================================
    // VULN 7: Switch expression (Java 14+)
    // Chain: request.getParameter("type") -> switch expression
    //        -> each branch builds SQL with request.getParameter("q")
    //        -> Statement.executeQuery()
    // The switch expression selects which SQL template to use, but
    // all branches incorporate the tainted query parameter.
    // ============================================================

    public void queryByType(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String type = request.getParameter("type");
        String queryValue = request.getParameter("q");

        String sql = switch (type) {
            case "name" -> "SELECT * FROM accounts WHERE name = '" + queryValue + "'";
            case "email" -> "SELECT * FROM accounts WHERE email = '" + queryValue + "'";
            case "status" -> "SELECT * FROM accounts WHERE status = '" + queryValue + "'";
            default -> "SELECT * FROM accounts WHERE id = '" + queryValue + "'";
        };

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 8: Record class storing tainted data
    // Chain: request.getParameter() -> new AuditEntry(userId, action)
    //        -> record accessor entry.action() -> SQL concatenation
    //        -> Statement.executeQuery()
    // The record stores the tainted value and its accessor returns
    // it without sanitization, flowing into a raw SQL query.
    // ============================================================

    public record AuditEntry(String userId, String action, long timestamp) {
        public String toWhereClause() {
            return "user_id = '" + userId + "' AND action = '" + action + "'";
        }
    }

    public void searchAuditLog(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("userId");
        String action = request.getParameter("action");
        AuditEntry entry = new AuditEntry(userId, action, System.currentTimeMillis());

        String clause = entry.toWhereClause();
        String sql = "SELECT * FROM audit_log WHERE " + clause;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 9: StringBuilder fluent append chain to SQL
    // Chain: request.getParameter() -> StringBuilder.append() chain
    //        -> .toString() -> Statement.executeQuery()
    // Multiple tainted parameters are appended into a StringBuilder
    // via fluent method chaining, building an injectable SQL query.
    // ============================================================

    public void advancedSearch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String city = request.getParameter("city");
        String minBalance = request.getParameter("minBalance");

        String sql = new StringBuilder("SELECT * FROM accounts WHERE 1=1")
            .append(" AND name LIKE '%").append(name).append("%'")
            .append(" AND city = '").append(city).append("'")
            .append(" AND balance >= ").append(minBalance)
            .toString();

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 10: CompletableFuture chain
    // Chain: request.getParameter() -> CompletableFuture.supplyAsync()
    //        -> .thenApply() builds SQL -> .thenApply() executes query
    // The tainted value flows through the async pipeline: the first
    // stage wraps it, the second builds SQL, the third executes it.
    // ============================================================

    public void asyncSearch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String keyword = request.getParameter("keyword");

        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> keyword)
            .thenApply(k -> "SELECT * FROM accounts WHERE name LIKE '%" + k + "%'");

        String sql = future.get(5, TimeUnit.SECONDS);
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 11: Custom @FunctionalInterface with command injection
    // Chain: request.getParameter() -> CommandBuilder.build()
    //        -> Runtime.exec()
    // A custom functional interface is used to build a command
    // string from tainted input, then executed via Runtime.exec().
    // ============================================================

    @FunctionalInterface
    interface CommandBuilder {
        String build(String input);
    }

    public void exportData(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String format = request.getParameter("format");

        CommandBuilder builder = fmt -> "data-export --format " + fmt + " --output /tmp/export";
        String command = builder.build(format);
        Process process = Runtime.getRuntime().exec(command);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            response.getWriter().write(output.toString());
        }
    }

    // ============================================================
    // VULN 12: Stream reduce accumulating tainted fragments
    // Chain: request.getParameter() -> split -> stream().reduce()
    //        -> accumulated SQL string -> Statement.executeQuery()
    // The stream reduce operation concatenates tainted fragments
    // into a single SQL WHERE clause without sanitization.
    // ============================================================

    public void filterByMultiple(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filtersParam = request.getParameter("filters");
        String[] parts = filtersParam.split(";");

        String whereClause = Arrays.stream(parts)
            .reduce("1=1", (acc, part) -> acc + " AND " + part);

        String sql = "SELECT * FROM accounts WHERE " + whereClause;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        writeResults(response, rs);
    }

    // ============================================================
    // VULN 13: ProcessBuilder with tainted arguments list
    // Chain: request.getParameter() -> List.of() -> new ProcessBuilder()
    //        -> .start()
    // User-controlled values are placed into a ProcessBuilder
    // argument list, enabling command injection.
    // ============================================================

    public void runDiagnostic(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        String port = request.getParameter("port");

        List<String> command = new ArrayList<>();
        command.add("nmap");
        command.add("-p");
        command.add(port);
        command.add(host);

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            response.getWriter().write(output.toString());
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private void writeResults(HttpServletResponse response, ResultSet rs) throws Exception {
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        ResultSetMetaData meta = rs.getMetaData();
        int cols = meta.getColumnCount();
        out.write("[");
        boolean first = true;
        while (rs.next()) {
            if (!first) out.write(",");
            out.write("{");
            for (int i = 1; i <= cols; i++) {
                if (i > 1) out.write(",");
                out.write("\"" + meta.getColumnName(i) + "\":\"" + rs.getString(i) + "\"");
            }
            out.write("}");
            first = false;
        }
        out.write("]");
    }

    // ============================================================
    // ADDITIONAL PATTERNS - Annotation-based dispatch, inheritance
    // ============================================================

    // Annotation processing (simulated - actual annotations need framework)
    // @RequestMapping("/api/exec")
    public String annotatedHandler(String userInput) throws Exception {
        // Annotation marks this as HTTP handler entry point
        return Runtime.getRuntime().exec(userInput).toString();
    }

    // Inheritance chain with virtual dispatch
    abstract static class BaseHandler {
        abstract String handle(String data);
        String process(String data) {
            return handle(data);  // virtual dispatch to subclass
        }
    }

    static class SqlHandler extends BaseHandler {
        @Override
        String handle(String data) {
            // Override reaches SQL sink
            return "SELECT * FROM t WHERE id = " + data;
        }
    }

    // Switch expression (Java 14+)
    static String switchExpression(String type, String payload) {
        return switch (type) {
            case "exec" -> payload;  // taint flows through switch arm
            case "safe" -> "sanitized";
            default -> throw new IllegalArgumentException(type);
        };
    }

    // Try-with-resources flow
    static void tryWithResources(String query) throws Exception {
        try (var conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:test");
             var stmt = conn.createStatement()) {
            stmt.executeQuery(query);  // taint through try-with-resources
        }
    }

    // Varargs propagation
    static void varargsSink(String... commands) {
        for (String cmd : commands) {
            try { Runtime.getRuntime().exec(cmd); } catch (Exception e) {}
        }
    }

    // Builder pattern with taint
    static class QueryBuilder {
        private StringBuilder query = new StringBuilder();
        QueryBuilder select(String cols) { query.append("SELECT ").append(cols); return this; }
        QueryBuilder from(String table) { query.append(" FROM ").append(table); return this; }
        QueryBuilder where(String cond) { query.append(" WHERE ").append(cond); return this; }
        String build() { return query.toString(); }
    }
}

    // Enum with behavior
    enum CommandType {
        EXEC("exec"),
        QUERY("query");
        final String value;
        CommandType(String v) { this.value = v; }
    }
