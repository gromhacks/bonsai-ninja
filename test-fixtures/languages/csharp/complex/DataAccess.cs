using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace HealthcareAPI.Data
{
    public class DataAccess
    {
        private readonly string _connectionString;

        public DataAccess(string connectionString)
        {
            _connectionString = connectionString;
        }

        // VULN: SQL injection - receives raw SQL from callers
        public List<Dictionary<string, object>> ExecuteRawQuery(string sql)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadAllResults(reader);
        }

        // VULN: SQL injection - receives raw SQL, executes non-query
        public int ExecuteRawUpdate(string sql)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            return cmd.ExecuteNonQuery();
        }

        // VULN: SQL injection - receives raw SQL, returns scalar
        public object ExecuteRawScalar(string sql)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            return cmd.ExecuteScalar();
        }

        // VULN: SQL injection via raw ID lookup - concatenates ID directly
        public Dictionary<string, object> FindByIdRaw(string id)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            string sql = "SELECT * FROM patients WHERE id = '" + id + "'";
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            var results = ReadAllResults(reader);
            return results.Count > 0 ? results[0] : null;
        }

        // VULN: SQL injection via raw insert
        public Dictionary<string, object> InsertRaw(string sql)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            cmd.ExecuteNonQuery();
            var result = new Dictionary<string, object>();
            result["status"] = "inserted";
            return result;
        }

        // Safe version with parameterized query
        public List<Dictionary<string, object>> FindByFilterSafe(string query, string sortBy)
        {
            var allowedSorts = new HashSet<string> { "name", "dob", "created_at" };
            string safeSortBy = allowedSorts.Contains(sortBy) ? sortBy : "name";
            string sql = "SELECT * FROM patients WHERE name LIKE @query ORDER BY " + safeSortBy;
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@query", "%" + query + "%");
            var reader = cmd.ExecuteReader();
            return ReadAllResults(reader);
        }

        public Dictionary<string, object> FindById(string id)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM patients WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            var reader = cmd.ExecuteReader();
            var results = ReadAllResults(reader);
            return results.Count > 0 ? results[0] : null;
        }

        public Dictionary<string, object> Create(Dictionary<string, object> data)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(
                "INSERT INTO patients (name, dob, ssn) VALUES (@name, @dob, @ssn); SELECT SCOPE_IDENTITY()", conn);
            cmd.Parameters.AddWithValue("@name", data["name"]);
            cmd.Parameters.AddWithValue("@dob", data["dob"]);
            cmd.Parameters.AddWithValue("@ssn", data["ssn"]);
            var id = cmd.ExecuteScalar();
            data["id"] = id;
            return data;
        }

        public void Update(string id, Dictionary<string, object> updates)
        {
            var setClauses = new List<string>();
            foreach (var key in updates.Keys)
            {
                setClauses.Add(key + " = @" + key);
            }
            string sql = "UPDATE patients SET " + string.Join(", ", setClauses) + " WHERE id = @id";
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            foreach (var kvp in updates)
            {
                cmd.Parameters.AddWithValue("@" + kvp.Key, kvp.Value);
            }
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        }

        public void Delete(string id)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand("DELETE FROM patients WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        }

        public List<Dictionary<string, object>> GetHistory(string patientId)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM medical_history WHERE patient_id = @pid ORDER BY visit_date DESC", conn);
            cmd.Parameters.AddWithValue("@pid", patientId);
            var reader = cmd.ExecuteReader();
            return ReadAllResults(reader);
        }

        public Dictionary<string, object> CreateAppointment(Dictionary<string, object> data)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(
                "INSERT INTO appointments (patient_id, doctor_id, date_time, status) VALUES (@pid, @did, @dt, @status)", conn);
            cmd.Parameters.AddWithValue("@pid", data["patient_id"]);
            cmd.Parameters.AddWithValue("@did", data["doctor_id"]);
            cmd.Parameters.AddWithValue("@dt", data["date_time"]);
            cmd.Parameters.AddWithValue("@status", data["status"]);
            cmd.ExecuteNonQuery();
            return data;
        }

        public List<Dictionary<string, object>> GetAppointments(string patientId)
        {
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM appointments WHERE patient_id = @pid", conn);
            cmd.Parameters.AddWithValue("@pid", patientId);
            var reader = cmd.ExecuteReader();
            return ReadAllResults(reader);
        }

        // VULN: Path traversal via file export
        public void ExportToFile(string outputPath, string data)
        {
            File.WriteAllText(outputPath, data);
        }

        // VULN: Path traversal via file read
        public string ReadFromFile(string filePath)
        {
            return File.ReadAllText(filePath);
        }

        // VULN: Command injection via backup tool
        public void BackupTable(string tableName, string outputDir)
        {
            string cmd = "pg_dump --table=" + tableName + " --output=" + outputDir + "/backup.sql";
            Process.Start("sh", "-c " + cmd);
        }

        // VULN: SSRF via data sync
        public async Task<string> SyncFromRemote(string remoteUrl)
        {
            var client = new HttpClient();
            var response = await client.GetAsync(remoteUrl);
            return await response.Content.ReadAsStringAsync();
        }

        // VULN: SQL injection via dynamic table name
        public List<Dictionary<string, object>> QueryDynamicTable(string tableName, string columns)
        {
            string sql = "SELECT " + columns + " FROM " + tableName;
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadAllResults(reader);
        }

        // VULN: Log injection via database error logging
        public void LogDatabaseError(string operation, string errorMessage)
        {
            string logEntry = "[DB_ERROR] operation=" + operation + " error=" + errorMessage;
            Console.WriteLine(logEntry);
        }

        private List<Dictionary<string, object>> ReadAllResults(SqlDataReader reader)
        {
            var results = new List<Dictionary<string, object>>();
            while (reader.Read())
            {
                var row = new Dictionary<string, object>();
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    row[reader.GetName(i)] = reader.GetValue(i);
                }
                results.Add(row);
            }
            return results;
        }
    }
}
