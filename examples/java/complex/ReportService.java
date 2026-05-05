package com.bank.api;

import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.naming.InitialContext;

public class ReportService {

    private Connection connection;

    public ReportService(Connection connection) {
        this.connection = connection;
    }

    public String generateAccountReport(String accountId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
            "SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY created_at DESC"
        );
        stmt.setString(1, accountId);
        stmt.setString(2, accountId);
        ResultSet rs = stmt.executeQuery();
        StringBuilder report = new StringBuilder();
        report.append("Transaction Report\n");
        report.append("==================\n");
        while (rs.next()) {
            report.append(String.format("From: %s, To: %s, Amount: %.2f\n",
                rs.getString("from_account"),
                rs.getString("to_account"),
                rs.getDouble("amount")));
        }
        return report.toString();
    }

    // VULN: SQL injection in report generation
    public String generateCustomReport(String query) throws Exception {
        String sql = "SELECT * FROM transactions WHERE " + query;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        StringBuilder report = new StringBuilder();
        ResultSetMetaData meta = rs.getMetaData();
        int cols = meta.getColumnCount();
        while (rs.next()) {
            for (int i = 1; i <= cols; i++) {
                report.append(meta.getColumnName(i)).append(": ").append(rs.getString(i)).append(", ");
            }
            report.append("\n");
        }
        return report.toString();
    }

    // VULN: Command injection in PDF export
    public byte[] exportToPdf(String reportContent, String outputPath) throws Exception {
        String tempFile = "/tmp/report_" + System.currentTimeMillis() + ".txt";
        FileWriter writer = new FileWriter(tempFile);
        writer.write(reportContent);
        writer.close();

        String cmd = "wkhtmltopdf " + tempFile + " " + outputPath;
        Runtime.getRuntime().exec(cmd);

        File pdfFile = new File(outputPath);
        FileInputStream fis = new FileInputStream(pdfFile);
        byte[] content = new byte[(int) pdfFile.length()];
        fis.read(content);
        fis.close();
        return content;
    }

    // VULN: SSRF via report webhook
    public void sendReportWebhook(String webhookUrl, String reportData) throws Exception {
        URL url = new URL(webhookUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        OutputStream os = conn.getOutputStream();
        os.write(reportData.getBytes());
        os.close();
        conn.getResponseCode();
    }

    // VULN: JNDI injection in datasource lookup
    public Connection getDatasource(String jndiName) throws Exception {
        InitialContext ctx = new InitialContext();
        javax.sql.DataSource ds = (javax.sql.DataSource) ctx.lookup(jndiName);
        return ds.getConnection();
    }

    public Map<String, Object> getReportMetadata(String reportId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM reports WHERE id = ?");
        stmt.setString(1, reportId);
        ResultSet rs = stmt.executeQuery();
        Map<String, Object> metadata = new HashMap<>();
        if (rs.next()) {
            metadata.put("id", rs.getString("id"));
            metadata.put("type", rs.getString("type"));
            metadata.put("created_at", rs.getString("created_at"));
        }
        return metadata;
    }

    public void archiveReport(String reportId, String archivePath) throws Exception {
        Map<String, Object> metadata = getReportMetadata(reportId);
        String content = generateAccountReport((String) metadata.get("account_id"));
        FileWriter writer = new FileWriter(archivePath + "/" + reportId + ".txt");
        writer.write(content);
        writer.close();
    }

    // VULN: Template injection
    public String renderReport(String templateStr, Map<String, Object> data) throws Exception {
        String result = templateStr;
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            result = result.replace("${" + entry.getKey() + "}", entry.getValue().toString());
        }
        return result;
    }
}
