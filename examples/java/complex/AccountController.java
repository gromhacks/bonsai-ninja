package com.bank.api;

import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;

public class AccountController {

    private AccountService accountService;
    private ReportService reportService;
    private SecurityUtils securityUtils;

    public AccountController(AccountService accountService, ReportService reportService) {
        this.accountService = accountService;
        this.reportService = reportService;
        this.securityUtils = new SecurityUtils();
    }

    // ============================================================
    // Account Search (VULN: SQL Injection - Deep Chain)
    // ============================================================

    public void searchAccounts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("query");
        String sortBy = request.getParameter("sort");
        String limit = request.getParameter("limit");
        List<Map<String, Object>> results = accountService.searchAccounts(query, sortBy, limit);
        writeJsonResponse(response, results);
    }

    public void searchAccountsSafe(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("query");
        String sortBy = request.getParameter("sort");
        List<Map<String, Object>> results = accountService.searchAccountsSafe(query, sortBy);
        writeJsonResponse(response, results);
    }

    // ============================================================
    // Account Management
    // ============================================================

    public void getAccount(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String accountId = request.getParameter("id");
        Map<String, Object> account = accountService.getAccountById(accountId);
        writeJsonResponse(response, account);
    }

    public void createAccount(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String type = request.getParameter("type");
        Map<String, Object> account = accountService.createAccount(name, email, type);
        writeJsonResponse(response, account);
    }

    public void transfer(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fromId = request.getParameter("from");
        String toId = request.getParameter("to");
        String amount = request.getParameter("amount");
        Map<String, Object> result = accountService.transfer(fromId, toId, Double.parseDouble(amount));
        writeJsonResponse(response, result);
    }

    // ============================================================
    // XSS Vulnerabilities
    // ============================================================

    public void getAccountStatement(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String accountId = request.getParameter("id");
        String format = request.getParameter("format");
        Map<String, Object> account = accountService.getAccountById(accountId);

        // VULN: XSS - unsanitized output
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Account Statement for " + request.getParameter("name") + "</h1>");
        out.println("<p>Account: " + accountId + "</p>");
        out.println("</body></html>");
    }

    public void getAccountStatementSafe(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safeName = SecurityUtils.escapeHtml(name);
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Account Statement for " + safeName + "</h1>");
        out.println("</body></html>");
    }

    // ============================================================
    // Command Injection
    // ============================================================

    public void generateReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String reportType = request.getParameter("type");
        String dateRange = request.getParameter("range");
        // VULN: Command injection
        String cmd = "report-generator --type " + reportType + " --range " + dateRange;
        Process process = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line);
        }
        response.getWriter().write(output.toString());
    }

    // ============================================================
    // XXE Vulnerability
    // ============================================================

    public void importAccounts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: XXE - external entities enabled
        InputStream xmlInput = request.getInputStream();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xmlInput);
        String rootTag = doc.getDocumentElement().getTagName();
        response.getWriter().write("Imported document: " + rootTag);
    }

    public void importAccountsSafe(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Safe: XXE protection enabled
        InputStream xmlInput = request.getInputStream();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xmlInput);
        response.getWriter().write("Imported safely");
    }

    // ============================================================
    // SSRF
    // ============================================================

    public void fetchExternalData(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: SSRF
        String url = request.getParameter("url");
        URL targetUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        response.getWriter().write(result.toString());
    }

    // ============================================================
    // JNDI Injection
    // ============================================================

    public void lookupResource(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: JNDI injection
        String resourceName = request.getParameter("resource");
        javax.naming.InitialContext ctx = new javax.naming.InitialContext();
        Object resource = ctx.lookup(resourceName);
        response.getWriter().write("Found: " + resource.toString());
    }

    // ============================================================
    // Deserialization
    // ============================================================

    public void restoreSession(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: Insecure deserialization
        InputStream is = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(is);
        Object session = ois.readObject();
        response.getWriter().write("Session restored: " + session.toString());
    }

    // ============================================================
    // Path Traversal
    // ============================================================

    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: Path traversal
        String filename = request.getParameter("file");
        String basePath = "/var/bank/reports/";
        File file = new File(basePath + filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }

    // ============================================================
    // EL Injection
    // ============================================================

    public void evaluateExpression(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // VULN: EL injection
        String expression = request.getParameter("expr");
        javax.el.ExpressionFactory factory = javax.el.ExpressionFactory.newInstance();
        javax.el.ELContext context = null;
        javax.el.ValueExpression ve = factory.createValueExpression(context, expression, String.class);
        Object result = ve.getValue(context);
        response.getWriter().write("Result: " + result);
    }

    // ============================================================
    // Log Injection
    // ============================================================

    public void auditAction(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String action = request.getParameter("action");
        String userId = request.getParameter("userId");
        // VULN: Log injection
        System.out.println("AUDIT: User " + userId + " performed action: " + action);
        response.getWriter().write("Logged");
    }

    // ============================================================
    // Helpers
    // ============================================================

    private void writeJsonResponse(HttpServletResponse response, Object data) throws Exception {
        response.setContentType("application/json");
        response.getWriter().write(data.toString());
    }

    private void writeJsonResponse(HttpServletResponse response, List<?> data) throws Exception {
        response.setContentType("application/json");
        response.getWriter().write(data.toString());
    }
}
