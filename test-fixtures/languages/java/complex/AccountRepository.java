package com.bank.api;

import java.sql.*;
import java.util.*;

public class AccountRepository {

    private Connection connection;

    public AccountRepository(Connection connection) {
        this.connection = connection;
    }

    public Map<String, Object> findById(String accountId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM accounts WHERE id = ?");
        stmt.setString(1, accountId);
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) {
            return resultSetToMap(rs);
        }
        return null;
    }

    public Map<String, Object> create(Map<String, Object> data) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
            "INSERT INTO accounts (name, email, type, balance) VALUES (?, ?, ?, ?)",
            Statement.RETURN_GENERATED_KEYS
        );
        stmt.setString(1, (String) data.get("name"));
        stmt.setString(2, (String) data.get("email"));
        stmt.setString(3, (String) data.get("type"));
        stmt.setDouble(4, (Double) data.get("balance"));
        stmt.executeUpdate();
        ResultSet keys = stmt.getGeneratedKeys();
        if (keys.next()) {
            data.put("id", keys.getString(1));
        }
        return data;
    }

    // VULN: SQL injection - Deep Chain sink
    public List<Map<String, Object>> findByFilter(AccountService.SearchCriteria criteria) throws Exception {
        String sql = criteria.getSQL();
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return resultSetToList(rs);
    }

    // Safe version with parameterized query
    public List<Map<String, Object>> findByFilterSafe(String query, String sortBy) throws Exception {
        Set<String> allowedSorts = new HashSet<>(Arrays.asList("name", "email", "balance", "created_at"));
        String safeSortBy = allowedSorts.contains(sortBy) ? sortBy : "name";
        String sql = "SELECT * FROM accounts WHERE name LIKE ? ORDER BY " + safeSortBy;
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, "%" + query + "%");
        ResultSet rs = stmt.executeQuery();
        return resultSetToList(rs);
    }

    public void updateBalance(String accountId, double newBalance) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("UPDATE accounts SET balance = ? WHERE id = ?");
        stmt.setDouble(1, newBalance);
        stmt.setString(2, accountId);
        stmt.executeUpdate();
    }

    public List<Map<String, Object>> getTransactions(String accountId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
            "SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY created_at DESC"
        );
        stmt.setString(1, accountId);
        stmt.setString(2, accountId);
        ResultSet rs = stmt.executeQuery();
        return resultSetToList(rs);
    }

    public void logTransaction(String fromId, String toId, double amount) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
            "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)"
        );
        stmt.setString(1, fromId);
        stmt.setString(2, toId);
        stmt.setDouble(3, amount);
        stmt.executeUpdate();
    }

    // VULN: SQL injection in custom query
    public List<Map<String, Object>> customQuery(String whereClause) throws Exception {
        String sql = "SELECT * FROM accounts WHERE " + whereClause;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return resultSetToList(rs);
    }

    public void deleteAccount(String accountId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("DELETE FROM accounts WHERE id = ?");
        stmt.setString(1, accountId);
        stmt.executeUpdate();
    }

    private Map<String, Object> resultSetToMap(ResultSet rs) throws Exception {
        ResultSetMetaData meta = rs.getMetaData();
        Map<String, Object> row = new HashMap<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            row.put(meta.getColumnName(i), rs.getObject(i));
        }
        return row;
    }

    private List<Map<String, Object>> resultSetToList(ResultSet rs) throws Exception {
        List<Map<String, Object>> results = new ArrayList<>();
        while (rs.next()) {
            results.add(resultSetToMap(rs));
        }
        return results;
    }
}
