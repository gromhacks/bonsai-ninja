package com.bank.app

import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.sql.Statement

class DatabaseHelper(private val connectionString: String) {
    private var connection: Connection? = null

    fun getConnection(): Connection {
        if (connection == null || connection!!.isClosed) {
            connection = DriverManager.getConnection(connectionString)
        }
        return connection!!
    }

    // VULN: SQL injection - Deep Chain sink
    fun findByFilter(criteria: SearchCriteria): List<Map<String, Any>> {
        val sql = criteria.toSQL()
        val conn = getConnection()
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery(sql)
        return resultSetToList(rs)
    }

    // Safe version
    fun findByFilterSafe(query: String, sortBy: String): List<Map<String, Any>> {
        val allowedSorts = setOf("name", "balance", "created_at")
        val safeSortBy = if (sortBy in allowedSorts) sortBy else "name"
        val sql = "SELECT * FROM accounts WHERE name LIKE ? ORDER BY $safeSortBy"
        val conn = getConnection()
        val stmt = conn.prepareStatement(sql)
        stmt.setString(1, "%$query%")
        val rs = stmt.executeQuery()
        return resultSetToList(rs)
    }

    fun getAccount(accountId: String): Map<String, Any>? {
        // VULN: SQL injection
        val sql = "SELECT * FROM accounts WHERE id = '$accountId'"
        val conn = getConnection()
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery(sql)
        val results = resultSetToList(rs)
        return results.firstOrNull()
    }

    // Safe version
    fun getAccountSafe(accountId: String): Map<String, Any>? {
        val conn = getConnection()
        val stmt = conn.prepareStatement("SELECT * FROM accounts WHERE id = ?")
        stmt.setString(1, accountId)
        val rs = stmt.executeQuery()
        val results = resultSetToList(rs)
        return results.firstOrNull()
    }

    fun updateBalance(accountId: String, newBalance: Double) {
        val conn = getConnection()
        val stmt = conn.prepareStatement("UPDATE accounts SET balance = ? WHERE id = ?")
        stmt.setDouble(1, newBalance)
        stmt.setString(2, accountId)
        stmt.executeUpdate()
    }

    fun getTransactions(accountId: String): List<Map<String, Any>> {
        val conn = getConnection()
        val stmt = conn.prepareStatement(
            "SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY created_at DESC"
        )
        stmt.setString(1, accountId)
        stmt.setString(2, accountId)
        val rs = stmt.executeQuery()
        return resultSetToList(rs)
    }

    // VULN: SQL injection in executeQuery
    fun executeQuery(sql: String): List<Map<String, Any>> {
        val conn = getConnection()
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery(sql)
        return resultSetToList(rs)
    }

    fun executeQuerySafe(sql: String, params: List<String>): List<Map<String, Any>> {
        val conn = getConnection()
        val stmt = conn.prepareStatement(sql)
        params.forEachIndexed { index, value ->
            stmt.setString(index + 1, value)
        }
        val rs = stmt.executeQuery()
        return resultSetToList(rs)
    }

    private fun resultSetToList(rs: ResultSet): List<Map<String, Any>> {
        val results = mutableListOf<Map<String, Any>>()
        val meta = rs.metaData
        val columnCount = meta.columnCount
        while (rs.next()) {
            val row = mutableMapOf<String, Any>()
            for (i in 1..columnCount) {
                row[meta.getColumnName(i)] = rs.getObject(i) ?: ""
            }
            results.add(row)
        }
        return results
    }

    fun close() {
        connection?.close()
        connection = null
    }
}
