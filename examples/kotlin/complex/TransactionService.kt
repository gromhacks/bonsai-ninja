package com.bank.app

class SearchCriteria(val rawQuery: String, val sortField: String, val limit: Int = 50) {
    val filters = mutableListOf<String>()

    fun validate() {
        if (rawQuery.length > 500) throw IllegalArgumentException("Query too long")
    }

    // VULN: SQL injection in filter building
    fun buildFilter() {
        if (rawQuery.isNotEmpty()) {
            filters.add("name LIKE '%$rawQuery%'")
        }
        if (sortField.isNotEmpty()) {
            filters.add("ORDER BY $sortField")
        }
    }

    fun toSQL(): String {
        val sql = StringBuilder("SELECT * FROM accounts")
        if (filters.isNotEmpty()) {
            sql.append(" WHERE ")
            sql.append(filters.joinToString(" AND "))
        }
        sql.append(" LIMIT $limit")
        return sql.toString()
    }
}

class TransactionService {
    // Deep Chain: search -> criteria -> dbHelper
    fun searchAccounts(query: String, sortBy: String, dbHelper: DatabaseHelper): List<Map<String, Any>> {
        val criteria = SearchCriteria(query, sortBy)
        criteria.validate()
        criteria.buildFilter()
        return dbHelper.findByFilter(criteria)
    }

    fun searchAccountsSafe(query: String, sortBy: String, dbHelper: DatabaseHelper): List<Map<String, Any>> {
        return dbHelper.findByFilterSafe(query, sortBy)
    }

    fun transfer(toAccount: String, amount: Double, dbHelper: DatabaseHelper): Map<String, Any> {
        val recipient = dbHelper.getAccount(toAccount) ?: throw IllegalArgumentException("Account not found")
        val currentBalance = recipient["balance"] as? Double ?: 0.0
        dbHelper.updateBalance(toAccount, currentBalance + amount)
        return mapOf("status" to "success", "amount" to amount, "to" to toAccount)
    }

    fun getTransactionHistory(accountId: String, dbHelper: DatabaseHelper): List<Map<String, Any>> {
        return dbHelper.getTransactions(accountId)
    }

    fun getAccountSummary(accountId: String, dbHelper: DatabaseHelper): Map<String, Any> {
        val account = dbHelper.getAccount(accountId) ?: return emptyMap()
        val transactions = dbHelper.getTransactions(accountId)
        return mapOf(
            "account" to account,
            "transactionCount" to transactions.size,
            "recentTransactions" to transactions.take(5)
        )
    }

    // VULN: SQL injection in custom query
    fun customSearch(whereClause: String, dbHelper: DatabaseHelper): List<Map<String, Any>> {
        val sql = "SELECT * FROM transactions WHERE $whereClause"
        return dbHelper.executeQuery(sql)
    }
}

class PaymentProcessor {
    // VULN: SSRF via payment gateway URL
    fun processPayment(gatewayUrl: String, amount: Double, merchantId: String): String {
        val url = java.net.URL("$gatewayUrl/charge?amount=$amount&merchant=$merchantId")
        val conn = url.openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "POST"
        return conn.inputStream.bufferedReader().readText()
    }

    // Safe version
    fun processPaymentSafe(amount: Double, merchantId: String): String {
        val url = java.net.URL("https://api.payment-gateway.com/charge?amount=$amount&merchant=$merchantId")
        val conn = url.openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "POST"
        return conn.inputStream.bufferedReader().readText()
    }

    fun refund(transactionId: String, amount: Double): Map<String, Any> {
        return mapOf("status" to "refunded", "transactionId" to transactionId, "amount" to amount)
    }
}

class BillPayService(private val dbHelper: DatabaseHelper) {
    fun payBill(accountId: String, billerCode: String, amount: Double): Map<String, Any> {
        val account = dbHelper.getAccount(accountId) ?: throw IllegalArgumentException("Account not found")
        val balance = account["balance"] as? Double ?: 0.0
        if (balance < amount) throw IllegalArgumentException("Insufficient funds")
        dbHelper.updateBalance(accountId, balance - amount)
        return mapOf("status" to "paid", "billerCode" to billerCode, "amount" to amount)
    }

    fun getScheduledPayments(accountId: String): List<Map<String, Any>> {
        return dbHelper.executeQuery("SELECT * FROM scheduled_payments WHERE account_id = '$accountId'")
    }
}
