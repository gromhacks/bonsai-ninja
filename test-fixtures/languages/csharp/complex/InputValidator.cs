using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace HealthcareAPI.Validation
{
    public class InputValidator
    {
        public static string EscapeHtml(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            return input
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&#x27;");
        }

        public static string SanitizeSql(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            return input.Replace("'", "''").Replace("\\", "\\\\");
        }

        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email)) return false;
            var regex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
            return regex.IsMatch(email);
        }

        public static bool IsValidPatientId(string id)
        {
            if (string.IsNullOrEmpty(id)) return false;
            var regex = new Regex(@"^[A-Za-z0-9-]+$");
            return regex.IsMatch(id);
        }

        public static bool IsValidSSN(string ssn)
        {
            if (string.IsNullOrEmpty(ssn)) return false;
            var regex = new Regex(@"^\d{3}-\d{2}-\d{4}$");
            return regex.IsMatch(ssn);
        }

        public static string SanitizeFilename(string filename)
        {
            if (string.IsNullOrEmpty(filename)) return "";
            string name = System.IO.Path.GetFileName(filename);
            var invalidChars = System.IO.Path.GetInvalidFileNameChars();
            foreach (char c in invalidChars)
            {
                name = name.Replace(c.ToString(), "");
            }
            return name;
        }

        public static bool IsValidUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) return false;
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri result)) return false;
            if (result.Scheme != "http" && result.Scheme != "https") return false;
            var blocked = new List<string> { "localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254" };
            return !blocked.Contains(result.Host);
        }

        public static string HashPassword(string password, string salt)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] combined = System.Text.Encoding.UTF8.GetBytes(salt + password);
                byte[] hash = sha256.ComputeHash(combined);
                return Convert.ToBase64String(hash);
            }
        }

        public static string GenerateToken()
        {
            byte[] bytes = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes);
        }

        public static bool VerifyToken(string token, string expected)
        {
            if (token == null || expected == null) return false;
            if (token.Length != expected.Length) return false;
            int result = 0;
            for (int i = 0; i < token.Length; i++)
            {
                result |= token[i] ^ expected[i];
            }
            return result == 0;
        }

        // Weak sanitizer - does not fully prevent SQL injection
        public static string WeakSanitize(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            string cleaned = input.Trim();
            return cleaned;
        }

        // Validate and transform - passes taint through
        public static string ValidateAndNormalize(string input)
        {
            if (string.IsNullOrEmpty(input)) return "default";
            string normalized = input.Trim().ToLower();
            return normalized;
        }
    }
}
