package com.bank.app

import java.io.*
import java.net.HttpURLConnection
import java.net.URL

class NetworkClient {
    private val baseUrl: String = "https://api.bank.example.com"
    private val timeout: Int = 30000

    fun get(endpoint: String): String {
        val url = URL("$baseUrl$endpoint")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = timeout
        return conn.inputStream.bufferedReader().readText()
    }

    fun post(endpoint: String, body: String): String {
        val url = URL("$baseUrl$endpoint")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.outputStream.write(body.toByteArray())
        return conn.inputStream.bufferedReader().readText()
    }

    // VULN: SSRF - user-controlled URL
    fun fetchExternal(targetUrl: String): String {
        val url = URL(targetUrl)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        return conn.inputStream.bufferedReader().readText()
    }

    // Safe version
    fun fetchExternalSafe(targetUrl: String): String {
        val url = URL(targetUrl)
        val blocked = listOf("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254")
        if (url.host in blocked) {
            throw SecurityException("Blocked host: ${url.host}")
        }
        if (url.protocol !in listOf("http", "https")) {
            throw SecurityException("Invalid protocol: ${url.protocol}")
        }
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        return conn.inputStream.bufferedReader().readText()
    }

    // VULN: Path traversal in file download
    fun downloadFile(filename: String): ByteArray {
        val path = "/var/app/downloads/$filename"
        return File(path).readBytes()
    }

    // Safe version
    fun downloadFileSafe(filename: String): ByteArray {
        val safeName = File(filename).name
        val path = File("/var/app/downloads", safeName)
        val canonical = path.canonicalPath
        if (!canonical.startsWith(File("/var/app/downloads").canonicalPath)) {
            throw SecurityException("Invalid path")
        }
        return path.readBytes()
    }
}

class WebhookService(private val db: DatabaseHelper) {
    data class WebhookConfig(val url: String, val secret: String, val events: List<String>)

    private val webhooks = mutableListOf<WebhookConfig>()

    fun register(config: WebhookConfig) {
        webhooks.add(config)
    }

    // VULN: SSRF via webhook URL
    fun notify(event: String, data: String) {
        webhooks.filter { event in it.events }.forEach { webhook ->
            val url = URL(webhook.url)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.outputStream.write(data.toByteArray())
            conn.responseCode
        }
    }

    fun listWebhooks(): List<WebhookConfig> = webhooks.toList()
}

class CacheManager {
    private val cache = mutableMapOf<String, CacheEntry>()

    data class CacheEntry(val data: String, val expiresAt: Long)

    fun get(key: String): String? {
        val entry = cache[key] ?: return null
        if (System.currentTimeMillis() > entry.expiresAt) {
            cache.remove(key)
            return null
        }
        return entry.data
    }

    fun set(key: String, data: String, ttlMs: Long = 60000) {
        cache[key] = CacheEntry(data, System.currentTimeMillis() + ttlMs)
    }

    fun delete(key: String) = cache.remove(key)
    fun clear() = cache.clear()
}
