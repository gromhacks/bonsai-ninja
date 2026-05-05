using System.Data.SqlClient;
using System.Diagnostics;

namespace Micro
{
    public class AuthService
    {
        private readonly string _connStr = "Server=localhost;Database=auth;";

        public string VerifyToken(string token)
        {
            using var conn = new SqlConnection(_connStr);
            conn.Open();
            var query = "SELECT user_id FROM tokens WHERE token = '" + token + "'";
            var cmd = new SqlCommand(query, conn); // sink: SQL injection
            var result = cmd.ExecuteScalar();
            return result?.ToString();
        }

        public void RunAdminCommand(string userId, string cmd)
        {
            if (userId != null)
            {
                Process.Start("notify-admin", cmd); // sink: command injection
            }
        }
    }
}
