package com.bank.api;

import java.sql.*;
import java.io.*;
import java.util.*;
import java.util.function.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CrossModuleHandler {

    private AccountController accountController;
    private AccountService accountService;
    private AccountRepository accountRepository;
    private ReportService reportService;
    private SecurityUtils securityUtils;
    private Connection connection;

    // Static field for Chain B (module-level variable equivalent)
    private static String cachedReportQuery;

    public CrossModuleHandler(Connection connection) {
        this.connection = connection;
        this.accountRepository = new AccountRepository(connection);
        this.accountService = new AccountService(accountRepository);
        this.reportService = new ReportService(connection);
        this.securityUtils = new SecurityUtils();
        this.accountController = new AccountController(accountService, reportService);
    }

    // ============================================================
    // Chain A: 10+ hops across 4 files (deep interprocedural)
    //
    // Full chain (12 hops, 4 files):
    //   CrossModuleHandler.deepChainEntry()
    //     -> request.getParameter("query")              [SOURCE: HTTP input]
    //     -> buildSearchRequest(query)                   [hop 1: CrossModuleHandler]
    //     -> normalizeQuery(raw)                         [hop 2: CrossModuleHandler]
    //     -> enrichQuery(normalized)                     [hop 3: CrossModuleHandler]
    //     -> new AccountService.SearchCriteria(enriched) [hop 4: AccountService]
    //     -> criteria.validate()                         [hop 5: AccountService - passthrough]
    //     -> criteria.buildFilter()                      [hop 6: AccountService - SQL concat]
    //     -> accountRepository.findByFilter(criteria)    [hop 7: AccountRepository]
    //     -> criteria.getSQL()                           [hop 8: AccountService]
    //     -> connection.createStatement()                [hop 9: AccountRepository]
    //     -> stmt.executeQuery(sql)                      [SINK: SQL injection]
    //     -> generateReport(results)                     [hop 10: back in CrossModuleHandler]
    //     -> reportService.renderReport(template, data)  [hop 11: ReportService]
    //     -> response.getWriter().write(rendered)        [hop 12: output]
    //
    // The tainted query parameter flows through 3 intermediate
    // methods in CrossModuleHandler, into AccountService.SearchCriteria
    // which builds a SQL fragment, then into AccountRepository.findByFilter
    // which executes the unsanitized SQL via Statement.executeQuery().
    // ============================================================

    public void deepChainEntry(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("query");
        String sortBy = request.getParameter("sort");
        String limit = request.getParameter("limit");

        String searchQuery = buildSearchRequest(query);
        AccountService.SearchCriteria criteria = new AccountService.SearchCriteria(searchQuery, sortBy, limit);
        criteria.validate();
        criteria.buildFilter();

        List<Map<String, Object>> results = accountRepository.findByFilter(criteria);
        String rendered = generateReport(results, request.getParameter("template"));
        response.getWriter().write(rendered);
    }

    private String buildSearchRequest(String raw) {
        String normalized = normalizeQuery(raw);
        return enrichQuery(normalized);
    }

    private String normalizeQuery(String raw) {
        if (raw == null) return "";
        return raw.trim().toLowerCase();
    }

    private String enrichQuery(String normalized) {
        if (normalized.isEmpty()) return normalized;
        return normalized;
    }

    private String generateReport(List<Map<String, Object>> results, String templateStr) throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("count", String.valueOf(results.size()));
        data.put("results", results.toString());
        String template = templateStr != null ? templateStr : "Results: ${results} (${count} found)";
        return reportService.renderReport(template, data);
    }

    // ============================================================
    // Chain B: Static field (module-level variable equivalent)
    //
    // Full chain:
    //   storeReportFilter()
    //     -> request.getParameter("reportFilter")  [SOURCE: HTTP input]
    //     -> cachedReportQuery = filter             [WRITE to static field]
    //
    //   executeStoredReport()
    //     -> cachedReportQuery                      [READ from static field]
    //     -> reportService.generateCustomReport()   [hop 1: ReportService]
    //     -> "SELECT * FROM transactions WHERE " + query  [hop 2: SQL concat]
    //     -> Statement.executeQuery(sql)            [SINK: SQL injection]
    //
    // The tainted input is stored in a static field by one handler
    // and later retrieved by a different handler, which passes it
    // to ReportService.generateCustomReport() where it becomes
    // part of an unsanitized SQL query.
    // ============================================================

    public void storeReportFilter(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filter = request.getParameter("reportFilter");
        cachedReportQuery = filter;
        response.getWriter().write("Filter stored");
    }

    public void executeStoredReport(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (cachedReportQuery == null) {
            response.getWriter().write("No filter stored");
            return;
        }
        String report = reportService.generateCustomReport(cachedReportQuery);
        response.getWriter().write(report);
    }

    // ============================================================
    // Chain C: Callback / functional interface pattern
    //
    // Full chain:
    //   callbackChainEntry()
    //     -> request.getParameter("account")          [SOURCE: HTTP input]
    //     -> executeWithAudit(accountId, callback)     [hop 1: passes lambda]
    //     -> callback.apply(input)                     [hop 2: invokes lambda]
    //     -> lambda calls accountService.getAccountById(id)  [hop 3: AccountService]
    //     -> accountRepository.findById(id)            [hop 4: AccountRepository]
    //     -> PreparedStatement with id                 [hop 5: safe query]
    //     -> result stored in auditData                [hop 6]
    //     -> reportService.exportToPdf(content, path)  [hop 7: ReportService]
    //     -> Runtime.getRuntime().exec(cmd)            [SINK: command injection]
    //
    // A functional interface (Function<String, String>) is used as a
    // callback parameter. The tainted account ID flows through the
    // callback, and the result eventually reaches exportToPdf where
    // the output path derived from user input hits Runtime.exec().
    // ============================================================

    public void callbackChainEntry(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String accountId = request.getParameter("account");
        String outputPath = request.getParameter("outputPath");

        Function<String, String> lookupCallback = id -> {
            try {
                Map<String, Object> account = accountService.getAccountById(id);
                return account != null ? account.toString() : "not found";
            } catch (Exception e) {
                return "error: " + e.getMessage();
            }
        };

        String auditData = executeWithAudit(accountId, lookupCallback);
        byte[] pdf = reportService.exportToPdf(auditData, outputPath);
        response.getOutputStream().write(pdf);
    }

    private String executeWithAudit(String input, Function<String, String> callback) {
        String result = callback.apply(input);
        logAuditEvent("callback_executed", input);
        return result;
    }

    private void logAuditEvent(String eventType, String detail) {
        System.out.println("AUDIT [" + eventType + "]: " + detail);
    }

    // ============================================================
    // Chain D: Re-exported wrapper
    //
    // Full chain:
    //   reexportedWrapper()
    //     -> request.getParameter("webhookUrl")      [SOURCE: HTTP input]
    //     -> request.getParameter("accountId")       [SOURCE: HTTP input]
    //     -> buildReportContent(accountId)            [hop 1: CrossModuleHandler]
    //     -> reportService.generateAccountReport(id) [hop 2: ReportService]
    //     -> wraps into JSON via formatForWebhook()  [hop 3: CrossModuleHandler]
    //     -> sendNotification(url, payload)           [hop 4: CrossModuleHandler]
    //     -> reportService.sendReportWebhook(url, p) [hop 5: ReportService]
    //     -> new URL(webhookUrl)                      [hop 6: URL construction]
    //     -> url.openConnection()                     [SINK: SSRF]
    //
    // The handler wraps ReportService calls through local helper
    // methods. The tainted webhook URL passes through two wrapper
    // methods before reaching ReportService.sendReportWebhook(),
    // which opens a connection to the attacker-controlled URL.
    // ============================================================

    public void reexportedWrapper(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String webhookUrl = request.getParameter("webhookUrl");
        String accountId = request.getParameter("accountId");

        String content = buildReportContent(accountId);
        String payload = formatForWebhook(content);
        sendNotification(webhookUrl, payload);
        response.getWriter().write("Notification sent");
    }

    private String buildReportContent(String accountId) throws Exception {
        return reportService.generateAccountReport(accountId);
    }

    private String formatForWebhook(String content) {
        return "{\"report\": \"" + content.replace("\"", "\\\"") + "\"}";
    }

    private void sendNotification(String url, String payload) throws Exception {
        reportService.sendReportWebhook(url, payload);
    }

    // ============================================================
    // Chain E: Recursive chain
    //
    // Full chain:
    //   recursiveSearch()
    //     -> request.getParameter("query")           [SOURCE: HTTP input]
    //     -> expandWildcards(query, depth=3)          [hop 1: CrossModuleHandler]
    //     -> expandWildcards(partial, depth=2)        [hop 2: recursive call]
    //     -> expandWildcards(partial, depth=1)        [hop 3: recursive call]
    //     -> expandWildcards(partial, depth=0)        [hop 4: base case returns]
    //     -> accountRepository.customQuery(expanded)  [hop 5: AccountRepository]
    //     -> "SELECT * FROM accounts WHERE " + clause [hop 6: SQL concat]
    //     -> Statement.executeQuery(sql)              [SINK: SQL injection]
    //
    // The tainted query passes through a recursive method that
    // expands wildcard patterns. Each recursive call preserves
    // the tainted data. At the base case, the expanded (still
    // tainted) string flows into AccountRepository.customQuery()
    // which concatenates it into raw SQL.
    // ============================================================

    public void recursiveSearch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("query");
        String expanded = expandWildcards(query, 3);
        List<Map<String, Object>> results = accountRepository.customQuery(expanded);
        response.setContentType("application/json");
        response.getWriter().write(results.toString());
    }

    private String expandWildcards(String pattern, int depth) {
        if (depth <= 0 || pattern == null) {
            return pattern;
        }
        String partial = pattern.replace("*", "%");
        if (partial.contains("?")) {
            partial = partial.replace("?", "_");
        }
        return expandWildcards(partial, depth - 1);
    }
}
