using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Threading.Tasks;

namespace HealthcareAPI.Services
{
    // Helper that builds SQL strings from user input
    public static class QueryBuilder
    {
        // VULN: SQL injection - concatenates user input into SQL
        public static string BuildSearchQuery(string searchTerm, string sortField, string limit)
        {
            string sql = "SELECT * FROM patients WHERE name LIKE '%" + searchTerm + "%'";
            sql = AppendOrderBy(sql, sortField);
            sql = AppendLimit(sql, limit);
            return sql;
        }

        // VULN: Adds unsanitized ORDER BY clause
        public static string AppendOrderBy(string sql, string sortField)
        {
            if (!string.IsNullOrEmpty(sortField))
            {
                sql = sql + " ORDER BY " + sortField;
            }
            return sql;
        }

        // VULN: Adds unsanitized LIMIT clause
        public static string AppendLimit(string sql, string limit)
        {
            if (!string.IsNullOrEmpty(limit))
            {
                sql = sql + " LIMIT " + limit;
            }
            return sql;
        }

        // VULN: Builds a filter query from raw user input
        public static string BuildFilterQuery(string tableName, string filterColumn, string filterValue)
        {
            string sql = "SELECT * FROM " + tableName + " WHERE " + filterColumn + " = '" + filterValue + "'";
            return sql;
        }

        // VULN: Builds a report query with date range from user input
        public static string BuildReportQuery(string reportType, string startDate, string endDate)
        {
            string sql = "SELECT * FROM " + reportType + " WHERE created_at BETWEEN '" + startDate + "' AND '" + endDate + "'";
            return sql;
        }

        // VULN: Builds a custom WHERE clause
        public static string BuildWhereClause(string baseQuery, string condition)
        {
            string sql = baseQuery + " WHERE " + condition;
            return sql;
        }

        // VULN: Builds aggregate query from user input
        public static string BuildAggregateQuery(string groupField, string filterExpr)
        {
            string sql = "SELECT " + groupField + ", COUNT(*) FROM patients WHERE " + filterExpr + " GROUP BY " + groupField;
            return sql;
        }

        // VULN: Builds join query from user input
        public static string BuildJoinQuery(string tableName, string joinColumn, string filterValue)
        {
            string sql = "SELECT p.*, t.* FROM patients p JOIN " + tableName + " t ON p.id = t." + joinColumn + " WHERE t.value = '" + filterValue + "'";
            return sql;
        }

        // VULN: Builds update statement from user input
        public static string BuildUpdateStatement(string tableName, string setClause, string whereClause)
        {
            string sql = "UPDATE " + tableName + " SET " + setClause + " WHERE " + whereClause;
            return sql;
        }

        // VULN: Builds delete statement from user input
        public static string BuildDeleteStatement(string tableName, string whereClause)
        {
            string sql = "DELETE FROM " + tableName + " WHERE " + whereClause;
            return sql;
        }

        // VULN: Builds subquery from user input
        public static string BuildSubQuery(string innerQuery, string outerFilter)
        {
            string sql = "SELECT * FROM (" + innerQuery + ") sub WHERE " + outerFilter;
            return sql;
        }
    }

    public class PatientService
    {
        private readonly DataAccess _dataAccess;

        public PatientService(DataAccess dataAccess)
        {
            _dataAccess = dataAccess;
        }

        // VULN: Deep chain - builds SQL from user input
        public List<Dictionary<string, object>> SearchPatients(string query, string sortBy, string limit)
        {
            string sql = QueryBuilder.BuildSearchQuery(query, sortBy, limit);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // Safe version
        public List<Dictionary<string, object>> SearchPatientsSafe(string query, string sortBy)
        {
            return _dataAccess.FindByFilterSafe(query, sortBy);
        }

        // VULN: SQL injection via raw ID lookup
        public Dictionary<string, object> GetPatientById(string patientId)
        {
            return _dataAccess.FindByIdRaw(patientId);
        }

        // VULN: SQL injection via insert
        public Dictionary<string, object> CreatePatient(string name, string dob, string ssn)
        {
            string sql = "INSERT INTO patients (name, dob, ssn) VALUES ('" + name + "', '" + dob + "', '" + ssn + "')";
            return _dataAccess.InsertRaw(sql);
        }

        public void UpdatePatient(string patientId, Dictionary<string, object> updates)
        {
            _dataAccess.Update(patientId, updates);
        }

        public void DeletePatient(string patientId)
        {
            _dataAccess.Delete(patientId);
        }

        public List<Dictionary<string, object>> GetPatientHistory(string patientId)
        {
            return _dataAccess.GetHistory(patientId);
        }

        // VULN: SQL injection - builds filter from raw user input
        public List<Dictionary<string, object>> FilterPatients(string column, string value)
        {
            string sql = QueryBuilder.BuildFilterQuery("patients", column, value);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: SQL injection - custom report query from user input
        public List<Dictionary<string, object>> GetPatientReport(string reportType, string startDate, string endDate)
        {
            string sql = QueryBuilder.BuildReportQuery(reportType, startDate, endDate);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: SQL injection - count with raw WHERE clause
        public object CountByCondition(string condition)
        {
            string sql = "SELECT COUNT(*) FROM patients WHERE " + condition;
            return _dataAccess.ExecuteRawScalar(sql);
        }

        // VULN: SQL injection - delete with raw WHERE clause
        public int DeleteByCondition(string condition)
        {
            string sql = "DELETE FROM patients WHERE " + condition;
            return _dataAccess.ExecuteRawUpdate(sql);
        }

        // VULN: SQL injection via batch update
        public int BatchUpdateStatus(string statusFilter, string newStatus)
        {
            string setClause = "status = '" + newStatus + "'";
            string whereClause = "status = '" + statusFilter + "'";
            string sql = QueryBuilder.BuildUpdateStatement("patients", setClause, whereClause);
            return _dataAccess.ExecuteRawUpdate(sql);
        }

        // VULN: SQL injection via aggregation
        public List<Dictionary<string, object>> AggregateByField(string groupField, string filterExpr)
        {
            string sql = QueryBuilder.BuildAggregateQuery(groupField, filterExpr);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: SQL injection via join
        public List<Dictionary<string, object>> GetPatientWithRelated(string relatedTable, string joinCol, string filterVal)
        {
            string sql = QueryBuilder.BuildJoinQuery(relatedTable, joinCol, filterVal);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: Path traversal via export
        public void ExportPatientData(string patientId, string outputPath)
        {
            string data = "Patient export data for " + patientId;
            _dataAccess.ExportToFile(outputPath, data);
        }

        // VULN: SQL injection via delete statement builder
        public int PurgeRecords(string tableName, string whereClause)
        {
            string sql = QueryBuilder.BuildDeleteStatement(tableName, whereClause);
            return _dataAccess.ExecuteRawUpdate(sql);
        }

        // VULN: SQL injection via subquery
        public List<Dictionary<string, object>> ExecuteSubQuery(string innerQuery, string outerFilter)
        {
            string sql = QueryBuilder.BuildSubQuery(innerQuery, outerFilter);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: Path traversal via data export to file
        public void ExportQueryResults(string condition, string outputPath)
        {
            string sql = "SELECT * FROM patients WHERE " + condition;
            string data = sql;
            File.WriteAllText(outputPath, data);
        }

        // VULN: SQL injection via search with pagination
        public List<Dictionary<string, object>> SearchWithPagination(string searchTerm, string page, string pageSize)
        {
            string offset = page;
            string sql = "SELECT * FROM patients WHERE name LIKE '%" + searchTerm + "%' LIMIT " + pageSize + " OFFSET " + offset;
            return _dataAccess.ExecuteRawQuery(sql);
        }

        public Dictionary<string, object> GetPatientSummary(string patientId)
        {
            var patient = GetPatientById(patientId);
            var history = GetPatientHistory(patientId);
            var summary = new Dictionary<string, object>
            {
                { "patient", patient },
                { "historyCount", history.Count },
                { "recentVisits", history.GetRange(0, Math.Min(5, history.Count)) }
            };
            return summary;
        }
    }

    public class AppointmentService
    {
        private readonly DataAccess _dataAccess;

        public AppointmentService(DataAccess dataAccess)
        {
            _dataAccess = dataAccess;
        }

        public Dictionary<string, object> CreateAppointment(string patientId, string doctorId, DateTime dateTime)
        {
            var data = new Dictionary<string, object>
            {
                { "patient_id", patientId },
                { "doctor_id", doctorId },
                { "date_time", dateTime },
                { "status", "scheduled" }
            };
            return _dataAccess.CreateAppointment(data);
        }

        public List<Dictionary<string, object>> GetAppointments(string patientId)
        {
            return _dataAccess.GetAppointments(patientId);
        }

        // VULN: SQL injection via appointment search
        public List<Dictionary<string, object>> SearchAppointments(string filter)
        {
            string baseQuery = "SELECT * FROM appointments";
            string sql = QueryBuilder.BuildWhereClause(baseQuery, filter);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: SQL injection via date range
        public List<Dictionary<string, object>> GetAppointmentsByDateRange(string startDate, string endDate)
        {
            string sql = QueryBuilder.BuildReportQuery("appointments", startDate, endDate);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // VULN: SQL injection via doctor schedule lookup
        public List<Dictionary<string, object>> GetDoctorSchedule(string doctorId, string dateFilter)
        {
            string sql = "SELECT * FROM appointments WHERE doctor_id = '" + doctorId + "' AND " + dateFilter;
            return _dataAccess.ExecuteRawQuery(sql);
        }
    }

    // Audit logging service with multi-hop chains
    public class AuditService
    {
        private readonly DataAccess _dataAccess;

        public AuditService(DataAccess dataAccess)
        {
            _dataAccess = dataAccess;
        }

        // VULN: SQL injection via audit log query
        public List<Dictionary<string, object>> SearchAuditLogs(string userId, string action, string dateRange)
        {
            string sql = BuildAuditQuery(userId, action, dateRange);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        private string BuildAuditQuery(string userId, string action, string dateRange)
        {
            string sql = "SELECT * FROM audit_log WHERE user_id = '" + userId + "' AND action = '" + action + "' AND " + dateRange;
            return sql;
        }

        // VULN: Log injection via audit record
        public void LogAction(string userId, string action, string details)
        {
            string logEntry = FormatAuditEntry(userId, action, details);
            Console.WriteLine(logEntry);
        }

        private string FormatAuditEntry(string userId, string action, string details)
        {
            string entry = "[AUDIT] user=" + userId + " action=" + action + " details=" + details;
            return entry;
        }

        // VULN: SQL injection via audit report
        public List<Dictionary<string, object>> GenerateAuditReport(string reportFilter)
        {
            string sql = "SELECT user_id, action, COUNT(*) FROM audit_log WHERE " + reportFilter + " GROUP BY user_id, action";
            return _dataAccess.ExecuteRawQuery(sql);
        }
    }
}
