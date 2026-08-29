// C# sanitizer-fixture — parallel handlers per sink family.
using System;
using System.Data.SqlClient;
using System.Text.Encodings.Web;

namespace SanitizerTest
{
    public class Handlers
    {
        private SqlConnection conn;

        // --- SQL injection -----------------------------------------------

        public void SqlRaw(string userId)
        {
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = '" + userId + "'", conn);
            cmd.ExecuteReader();
        }

        public void SqlSafe(string userId)
        {
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", userId);
            cmd.ExecuteReader();
        }

        // --- XSS ---------------------------------------------------------

        public string XssRaw(string name) => "<p>Hello, " + name + "</p>";

        public string XssSafe(string name)
        {
            var safe = HtmlEncoder.Default.Encode(name);
            return "<p>Hello, " + safe + "</p>";
        }
    }
}
