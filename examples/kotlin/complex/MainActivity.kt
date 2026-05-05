package com.bank.app

import java.io.*
import java.net.URL
import java.sql.DriverManager
import java.sql.Statement

class Intent(val extras: Map<String, String?> = emptyMap(), val dataUri: String? = null) {
    fun getStringExtra(key: String): String? = extras[key]
    val data: DeepLinkData? get() = dataUri?.let { DeepLinkData(it) }
}

class DeepLinkData(private val uri: String) {
    fun getQueryParameter(key: String): String? {
        val query = uri.substringAfter("?", "")
        return query.split("&")
            .map { it.split("=", limit = 2) }
            .firstOrNull { it[0] == key }
            ?.getOrNull(1)
    }
}

class WebView {
    fun loadUrl(url: String) { println("Loading URL: $url") }
    fun loadData(data: String, mimeType: String, encoding: String) { println("Loading data") }
    fun addJavascriptInterface(obj: Any, name: String) { println("Added JS interface: $name") }
    val settings = WebSettings()
}

class WebSettings {
    var javaScriptEnabled: Boolean = false
    var allowFileAccess: Boolean = false
}

class MainActivity {
    private val transactionService = TransactionService()
    private val dbHelper = DatabaseHelper("jdbc:sqlite:bank.db")
    private val networkClient = NetworkClient()
    private val securityUtils = SecurityUtils()
    private var webView: WebView? = null

    // Deep link handling
    // VULN: Deep link injection - user controls URL via intent
    fun handleDeepLink(intent: Intent) {
        val action = intent.getStringExtra("action")
        val data = intent.data

        when (action) {
            "transfer" -> {
                val amount = data?.getQueryParameter("amount")
                val toAccount = data?.getQueryParameter("to")
                if (amount != null && toAccount != null) {
                    transactionService.transfer(toAccount, amount.toDouble(), dbHelper)
                }
            }
            "view" -> {
                val accountId = data?.getQueryParameter("id")
                if (accountId != null) {
                    val account = dbHelper.getAccount(accountId)
                    println("Account: $account")
                }
            }
            "webview" -> {
                // VULN: Loading arbitrary URL from deep link
                val url = data?.getQueryParameter("url")
                if (url != null) {
                    webView?.loadUrl(url)
                }
            }
        }
    }

    // Safe deep link handling
    fun handleDeepLinkSafe(intent: Intent) {
        val action = intent.getStringExtra("action")
        val data = intent.data

        when (action) {
            "view" -> {
                val accountId = data?.getQueryParameter("id")
                if (accountId != null && SecurityUtils.isValidAccountId(accountId)) {
                    val account = dbHelper.getAccountSafe(accountId)
                    println("Account: $account")
                }
            }
        }
    }

    // VULN: WebView XSS
    fun displayAccountInfo(intent: Intent) {
        val accountName = intent.getStringExtra("name") ?: "Unknown"
        val balance = intent.getStringExtra("balance") ?: "0"
        // VULN: Unsanitized data loaded into WebView
        val html = "<html><body><h1>Account: $accountName</h1><p>Balance: $$balance</p></body></html>"
        webView?.loadData(html, "text/html", "UTF-8")
    }

    // Safe version
    fun displayAccountInfoSafe(intent: Intent) {
        val accountName = SecurityUtils.escapeHtml(intent.getStringExtra("name") ?: "Unknown")
        val balance = SecurityUtils.escapeHtml(intent.getStringExtra("balance") ?: "0")
        val html = "<html><body><h1>Account: $accountName</h1><p>Balance: $$balance</p></body></html>"
        webView?.loadData(html, "text/html", "UTF-8")
    }

    // VULN: SQL injection via intent data - Deep Chain
    fun searchAccounts(intent: Intent) {
        val query = intent.getStringExtra("query") ?: return
        val sortBy = intent.getStringExtra("sort") ?: "name"
        val results = transactionService.searchAccounts(query, sortBy, dbHelper)
        println("Results: $results")
    }

    // Safe version
    fun searchAccountsSafe(intent: Intent) {
        val query = intent.getStringExtra("query") ?: return
        val sortBy = intent.getStringExtra("sort") ?: "name"
        val results = transactionService.searchAccountsSafe(query, sortBy, dbHelper)
        println("Results: $results")
    }

    // VULN: Command injection
    fun runDiagnostics(intent: Intent) {
        val command = intent.getStringExtra("command") ?: return
        val process = Runtime.getRuntime().exec("diagnostics $command")
        val output = process.inputStream.bufferedReader().readText()
        println("Diagnostics: $output")
    }

    // VULN: Intent handler - exported activity
    fun handleExternalIntent(intent: Intent) {
        val action = intent.getStringExtra("action")
        val payload = intent.getStringExtra("payload")
        when (action) {
            "execute" -> {
                // VULN: Arbitrary code path from external intent
                processPayload(payload ?: "")
            }
        }
    }

    private fun processPayload(payload: String) {
        // VULN: Deserialization from external input
        val bytes = java.util.Base64.getDecoder().decode(payload)
        val ois = ObjectInputStream(ByteArrayInputStream(bytes))
        val obj = ois.readObject()
        println("Deserialized: $obj")
    }

    // VULN: Log injection
    fun logUserAction(intent: Intent) {
        val userId = intent.getStringExtra("userId") ?: "unknown"
        val action = intent.getStringExtra("action") ?: "unknown"
        println("USER_ACTION: userId=$userId action=$action")
    }

    // VULN: Biometric bypass - weak check
    fun authenticateWithBiometrics(callback: (Boolean) -> Unit) {
        // Simulated biometric auth - VULN: result can be spoofed
        val result = true
        callback(result)
    }
}

fun main() {
    val app = MainActivity()
    val intent = Intent(mapOf("query" to "test", "sort" to "name"))
    app.searchAccounts(intent)
}
