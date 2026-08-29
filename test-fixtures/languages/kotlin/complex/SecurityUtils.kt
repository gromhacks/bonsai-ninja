package com.bank.app

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecurityUtils {
    companion object {
        fun escapeHtml(input: String): String {
            return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
        }

        fun isValidAccountId(id: String): Boolean {
            return id.matches(Regex("^[A-Za-z0-9-]+$"))
        }

        fun isValidEmail(email: String): Boolean {
            return email.matches(Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$"))
        }

        fun hashPassword(password: String): String {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            val md = MessageDigest.getInstance("SHA-256")
            md.update(salt)
            val hash = md.digest(password.toByteArray())
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash)
        }

        fun verifyPassword(password: String, stored: String): Boolean {
            val parts = stored.split(":")
            if (parts.size != 2) return false
            val salt = Base64.getDecoder().decode(parts[0])
            val storedHash = Base64.getDecoder().decode(parts[1])
            val md = MessageDigest.getInstance("SHA-256")
            md.update(salt)
            val computedHash = md.digest(password.toByteArray())
            return MessageDigest.isEqual(computedHash, storedHash)
        }

        fun generateToken(): String {
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        fun hmacSign(data: String, secret: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
            return Base64.getEncoder().encodeToString(mac.doFinal(data.toByteArray()))
        }

        fun hmacVerify(data: String, signature: String, secret: String): Boolean {
            val computed = hmacSign(data, secret)
            return MessageDigest.isEqual(computed.toByteArray(), signature.toByteArray())
        }

        fun encrypt(plaintext: String, key: String): ByteArray {
            val keyBytes = key.toByteArray().copyOf(16)
            val secretKey = SecretKeySpec(keyBytes, "AES")
            val iv = ByteArray(16)
            SecureRandom().nextBytes(iv)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
            val encrypted = cipher.doFinal(plaintext.toByteArray())
            return iv + encrypted
        }

        fun sanitizeFilename(filename: String): String {
            return filename.replace(Regex("[^a-zA-Z0-9._-]"), "")
        }

        fun sanitizeLogEntry(entry: String): String {
            return entry.replace("\n", " ").replace("\r", " ")
        }
    }
}
