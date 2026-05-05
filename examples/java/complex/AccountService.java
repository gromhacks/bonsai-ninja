package com.bank.api;

import java.sql.*;
import java.util.*;

public class AccountService {

    private AccountRepository repository;

    public AccountService(AccountRepository repository) {
        this.repository = repository;
    }

    // ============================================================
    // Deep Chain: Search with SQL injection
    // ============================================================

    public List<Map<String, Object>> searchAccounts(String query, String sortBy, String limit) throws Exception {
        SearchCriteria criteria = new SearchCriteria(query, sortBy, limit);
        criteria.validate();
        criteria.buildFilter();
        return repository.findByFilter(criteria);
    }

    public List<Map<String, Object>> searchAccountsSafe(String query, String sortBy) throws Exception {
        return repository.findByFilterSafe(query, sortBy);
    }

    // ============================================================
    // Account Operations
    // ============================================================

    public Map<String, Object> getAccountById(String accountId) throws Exception {
        return repository.findById(accountId);
    }

    public Map<String, Object> createAccount(String name, String email, String type) throws Exception {
        Map<String, Object> account = new HashMap<>();
        account.put("name", name);
        account.put("email", email);
        account.put("type", type);
        account.put("balance", 0.0);
        return repository.create(account);
    }

    public Map<String, Object> transfer(String fromId, String toId, double amount) throws Exception {
        Map<String, Object> fromAccount = repository.findById(fromId);
        Map<String, Object> toAccount = repository.findById(toId);

        if (fromAccount == null || toAccount == null) {
            throw new IllegalArgumentException("Account not found");
        }

        double fromBalance = (Double) fromAccount.get("balance");
        if (fromBalance < amount) {
            throw new IllegalArgumentException("Insufficient funds");
        }

        repository.updateBalance(fromId, fromBalance - amount);
        repository.updateBalance(toId, (Double) toAccount.get("balance") + amount);

        Map<String, Object> result = new HashMap<>();
        result.put("status", "success");
        result.put("amount", amount);
        result.put("from", fromId);
        result.put("to", toId);
        return result;
    }

    public List<Map<String, Object>> getTransactionHistory(String accountId) throws Exception {
        return repository.getTransactions(accountId);
    }

    public Map<String, Object> getAccountSummary(String accountId) throws Exception {
        Map<String, Object> account = repository.findById(accountId);
        List<Map<String, Object>> transactions = repository.getTransactions(accountId);
        Map<String, Object> summary = new HashMap<>();
        summary.put("account", account);
        summary.put("transactionCount", transactions.size());
        summary.put("recentTransactions", transactions.subList(0, Math.min(5, transactions.size())));
        return summary;
    }

    // ============================================================
    // Search Criteria (part of deep chain)
    // ============================================================

    public static class SearchCriteria {
        private String rawQuery;
        private String sortField;
        private String limit;
        private List<String> filters;

        public SearchCriteria(String rawQuery, String sortField, String limit) {
            this.rawQuery = rawQuery;
            this.sortField = sortField;
            this.limit = limit;
            this.filters = new ArrayList<>();
        }

        public void validate() {
            if (rawQuery != null && rawQuery.length() > 500) {
                throw new IllegalArgumentException("Query too long");
            }
        }

        public void buildFilter() {
            if (rawQuery != null && !rawQuery.isEmpty()) {
                filters.add("name LIKE '%" + rawQuery + "%'");
            }
            if (sortField != null) {
                filters.add("ORDER BY " + sortField);
            }
        }

        public String getSQL() {
            StringBuilder sql = new StringBuilder("SELECT * FROM accounts");
            if (!filters.isEmpty()) {
                sql.append(" WHERE ");
                sql.append(String.join(" AND ", filters));
            }
            if (limit != null) {
                sql.append(" LIMIT ").append(limit);
            }
            return sql.toString();
        }

        public List<String> getFilters() {
            return filters;
        }
    }
}
