/**
 * Auth attribute patterns for testing decorator flow analysis.
 * C# uses [Attribute] syntax for method-level metadata.
 */

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace AuthDecoratorExample
{
    // --- Custom auth attributes ---

    [AttributeUsage(AttributeTargets.Method)]
    public class AuthenticatedAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class AdminOnlyAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class RateLimitAttribute : Attribute
    {
        public int MaxCalls { get; }
        public RateLimitAttribute(int maxCalls) { MaxCalls = maxCalls; }
    }

    // --- Controller using auth attributes ---

    public class UserController
    {
        [Authenticated]
        public string GetProfile(string userId)
        {
            // VULN: SQL injection in authenticated endpoint
            var conn = new SqlConnection("Server=localhost;Database=db;");
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);
            conn.Open();
            return cmd.ExecuteScalar().ToString();
        }

        [Authenticated]
        [RateLimit(5)]
        public void ChangePassword(string oldPassword, string newPassword)
        {
            // VULN: weak MD5 hash + SQL injection
            var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(newPassword));
            string hashStr = BitConverter.ToString(hash);
            var conn = new SqlConnection("Server=localhost;Database=db;");
            var cmd = new SqlCommand("UPDATE users SET password = '" + hashStr + "'", conn);
            conn.Open();
            cmd.ExecuteNonQuery();
        }

        [AdminOnly]
        public void DeleteUser(string targetId)
        {
            // VULN: SQL injection in admin-only endpoint
            var conn = new SqlConnection("Server=localhost;Database=db;");
            var cmd = new SqlCommand("DELETE FROM users WHERE id = " + targetId, conn);
            conn.Open();
            cmd.ExecuteNonQuery();
        }

        [AdminOnly]
        public string RunCommand(string cmd)
        {
            // VULN: command injection in admin-only endpoint
            var process = Process.Start(cmd);
            process.WaitForExit();
            return process.StandardOutput.ReadToEnd();
        }

        public static void Main(string[] args)
        {
            var ctrl = new UserController();
            string input = args[0];
            ctrl.GetProfile(input);
            ctrl.DeleteUser(input);
            ctrl.RunCommand(input);
        }
    }
}
