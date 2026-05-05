package com.streaming.api

import java.io._
import java.net.{HttpURLConnection, URL}

class Integrations {
  // VULN: SSRF via webhook URL
  def sendWebhook(webhookUrl: String, payload: String): String = {
    val url = new URL(webhookUrl)
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setDoOutput(true)
    conn.setRequestProperty("Content-Type", "application/json")
    val os = conn.getOutputStream
    os.write(payload.getBytes)
    os.close()
    val status = conn.getResponseCode
    s"Webhook sent: $status"
  }

  // VULN: Deep SSRF chain - dispatchWebhook with intermediate URL processing
  // ApiController.triggerWebhook -> extractWebhookParams -> prepareWebhookPayload
  //   -> dispatchWebhook -> resolveEndpoint -> buildConnection -> sendRequest -> URL
  def dispatchWebhook(webhookUrl: String, payload: String): String = {
    val resolved = resolveEndpoint(webhookUrl)
    val conn = buildConnection(resolved)
    val result = sendRequest(conn, payload)
    result
  }

  private def resolveEndpoint(endpoint: String): String = {
    val resolved = if (endpoint.startsWith("http")) endpoint else s"https://$endpoint"
    resolved
  }

  private def buildConnection(endpoint: String): HttpURLConnection = {
    val url = new URL(endpoint)
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setDoOutput(true)
    conn.setRequestProperty("Content-Type", "application/json")
    conn
  }

  private def sendRequest(conn: HttpURLConnection, payload: String): String = {
    val os = conn.getOutputStream
    os.write(payload.getBytes)
    os.close()
    val status = conn.getResponseCode
    s"Request sent: $status"
  }

  // Safe version
  def sendWebhookSafe(webhookUrl: String, payload: String): String = {
    val url = new URL(webhookUrl)
    val blocked = List("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254")
    if (blocked.contains(url.getHost)) {
      throw new SecurityException(s"Blocked host: ${url.getHost}")
    }
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setDoOutput(true)
    val os = conn.getOutputStream
    os.write(payload.getBytes)
    os.close()
    s"Webhook sent: ${conn.getResponseCode}"
  }

  // VULN: SSRF via external API
  def fetchExternalData(apiUrl: String): String = {
    val url = new URL(apiUrl)
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    val reader = new BufferedReader(new InputStreamReader(conn.getInputStream))
    val response = new StringBuilder
    var line = reader.readLine()
    while (line != null) {
      response.append(line)
      line = reader.readLine()
    }
    reader.close()
    response.toString()
  }

  // VULN: Deep command injection chain
  // ApiController.exportAnalytics -> extractExportParams -> validateExportParams -> buildExportConfig
  //   -> dataService.prepareExport -> buildExportQuery -> buildExportCommand
  //   -> executeExport -> formatCommand -> runSystemCommand -> Runtime.exec
  def executeExport(command: String): String = {
    val formatted = formatCommand(command)
    val result = runSystemCommand(formatted)
    result
  }

  private def formatCommand(cmd: String): String = {
    val formatted = cmd.trim
    formatted
  }

  private def runSystemCommand(cmd: String): String = {
    Runtime.getRuntime.exec(cmd)
    "Command executed"
  }

  // VULN: Command injection in data export
  def exportToCloud(provider: String, bucket: String, path: String): String = {
    val cmd = s"cloud-upload --provider $provider --bucket $bucket --path $path"
    Runtime.getRuntime.exec(cmd)
    "Upload started"
  }

  // Safe version
  def exportToCloudSafe(provider: String, bucket: String, path: String): String = {
    val allowedProviders = Set("aws", "gcp", "azure")
    if (!allowedProviders.contains(provider)) {
      throw new IllegalArgumentException(s"Invalid provider: $provider")
    }
    val pb = new ProcessBuilder("cloud-upload", "--provider", provider, "--bucket", bucket, "--path", path)
    pb.start()
    "Upload started"
  }
}

class NotificationService(apiUrl: String, apiKey: String) {
  // VULN: SSRF via notification endpoint
  def send(notificationType: String, message: String, recipient: String): String = {
    val url = new URL(s"$apiUrl/send")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setDoOutput(true)
    conn.setRequestProperty("Authorization", s"Bearer $apiKey")
    val payload = s"""{"type":"$notificationType","message":"$message","to":"$recipient"}"""
    conn.getOutputStream.write(payload.getBytes)
    s"Notification sent: ${conn.getResponseCode}"
  }

  def sendBatch(notifications: List[(String, String, String)]): List[String] = {
    notifications.map { case (t, m, r) => send(t, m, r) }
  }
}

class CacheClient(host: String, port: Int) {
  private val cache = scala.collection.mutable.Map.empty[String, (String, Long)]

  def get(key: String): Option[String] = {
    cache.get(key).flatMap { case (value, expiry) =>
      if (System.currentTimeMillis() > expiry) {
        cache.remove(key)
        None
      } else {
        Some(value)
      }
    }
  }

  def set(key: String, value: String, ttlMs: Long = 60000): Unit = {
    cache(key) = (value, System.currentTimeMillis() + ttlMs)
  }

  def delete(key: String): Unit = cache.remove(key)
  def clear(): Unit = cache.clear()
}
