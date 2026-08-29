package com.streaming.api

import java.security.{MessageDigest, SecureRandom}
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Validators {
  def escapeHtml(input: String): String = {
    input
      .replace("&", "&amp;")
      .replace("<", "&lt;")
      .replace(">", "&gt;")
      .replace("\"", "&quot;")
      .replace("'", "&#x27;")
  }

  def sanitizeSql(input: String): String = {
    input.replace("'", "''").replace("\\", "\\\\")
  }

  def isValidEmail(email: String): Boolean = {
    email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")
  }

  def isValidIdentifier(id: String): Boolean = {
    id.matches("^[A-Za-z0-9_-]+$")
  }

  def sanitizeFilename(filename: String): String = {
    new java.io.File(filename).getName.replaceAll("[^a-zA-Z0-9._-]", "")
  }

  def isValidUrl(url: String): Boolean = {
    try {
      val parsed = new java.net.URL(url)
      val blocked = List("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254")
      !blocked.contains(parsed.getHost) && List("http", "https").contains(parsed.getProtocol)
    } catch {
      case _: Exception => false
    }
  }
}

class TokenManager(secret: String) {
  def generateToken(payload: String): String = {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(secret.getBytes, "HmacSHA256"))
    val signature = Base64.getEncoder.encodeToString(mac.doFinal(payload.getBytes))
    val encodedPayload = Base64.getEncoder.encodeToString(payload.getBytes)
    s"$encodedPayload.$signature"
  }

  def verifyToken(token: String): Option[String] = {
    val parts = token.split("\\.")
    if (parts.length != 2) return None
    val payload = parts(0)
    val signature = parts(1)
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(secret.getBytes, "HmacSHA256"))
    val decodedPayload = Base64.getDecoder.decode(payload)
    val expected = Base64.getEncoder.encodeToString(mac.doFinal(decodedPayload))
    if (MessageDigest.isEqual(signature.getBytes, expected.getBytes)) {
      Some(new String(decodedPayload))
    } else {
      None
    }
  }
}

class PasswordHasher {
  def hash(password: String): String = {
    val salt = new Array[Byte](16)
    new SecureRandom().nextBytes(salt)
    val md = MessageDigest.getInstance("SHA-256")
    md.update(salt)
    val hashed = md.digest(password.getBytes)
    Base64.getEncoder.encodeToString(salt) + ":" + Base64.getEncoder.encodeToString(hashed)
  }

  def verify(password: String, stored: String): Boolean = {
    val parts = stored.split(":")
    if (parts.length != 2) return false
    val salt = Base64.getDecoder.decode(parts(0))
    val storedHash = Base64.getDecoder.decode(parts(1))
    val md = MessageDigest.getInstance("SHA-256")
    md.update(salt)
    val computedHash = md.digest(password.getBytes)
    MessageDigest.isEqual(computedHash, storedHash)
  }
}

class RateLimiter(maxRequests: Int, windowMs: Long) {
  private val requests = scala.collection.mutable.Map.empty[String, List[Long]]

  def allow(key: String): Boolean = {
    val now = System.currentTimeMillis()
    val windowStart = now - windowMs
    val timestamps = requests.getOrElse(key, List.empty).filter(_ > windowStart)
    if (timestamps.length >= maxRequests) {
      false
    } else {
      requests(key) = timestamps :+ now
      true
    }
  }

  def reset(key: String): Unit = requests.remove(key)
}
