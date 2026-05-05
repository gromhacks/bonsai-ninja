using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace HealthcareAPI.Advanced
{
    // Record type with tainted fields
    public record PatientRecord(string Name, string Ssn, string Diagnosis);

    // Delegate type for processing pipeline
    public delegate string DataProcessor(string input);

    public class AdvancedPatterns
    {
        private readonly string _connectionString;
        private readonly DataAccess _dataAccess;
        private readonly PatientService _patientService;
        private readonly ReportGenerator _reportGenerator;
        private readonly DataProcessor _processor;

        // Event that fires when data is processed
        public event DataProcessor OnDataProcessed;

        public AdvancedPatterns(string connectionString, DataAccess dataAccess, PatientService patientService, ReportGenerator reportGenerator)
        {
            _connectionString = connectionString;
            _dataAccess = dataAccess;
            _patientService = patientService;
            _reportGenerator = reportGenerator;
            _processor = TransformData;
        }

        // -------------------------------------------------------------------
        // VULN 1: LINQ method chain building SQL - 3-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> HandleLinqSearch(string userFilter, string sortColumn)
        {
            var fragments = new List<string> { "name", "dob", "status" };

            string sql = fragments
                .Where(col => col != "status")
                .Select(col => col + " LIKE '%" + userFilter + "%'")
                .Aggregate((a, b) => a + " OR " + b);

            string fullQuery = "SELECT * FROM patients WHERE " + sql + " ORDER BY " + sortColumn;

            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(fullQuery, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        // -------------------------------------------------------------------
        // VULN 2: async/await chain - 4-hop chain
        // -------------------------------------------------------------------
        public async Task<List<Dictionary<string, object>>> FetchAndStoreAsync(string searchTerm)
        {
            string sql = await BuildQueryAsync(searchTerm);
            var results = await ExecuteAsync(sql);
            return results;
        }

        private async Task<string> BuildQueryAsync(string term)
        {
            await Task.Delay(10);
            string query = "SELECT * FROM patients WHERE name = '" + term + "'";
            return query;
        }

        private async Task<List<Dictionary<string, object>>> ExecuteAsync(string sql)
        {
            await Task.Delay(10);
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        // -------------------------------------------------------------------
        // VULN 3: Pattern matching (switch expression) - 2-hop chain
        // -------------------------------------------------------------------
        public void ProcessByCategory(string category, string userInput)
        {
            string command = category switch
            {
                "export" => "report-export --data " + userInput,
                "archive" => "tar -czf backup.tar " + userInput,
                "convert" => "convert-tool --input " + userInput,
                _ => "echo " + userInput
            };

            Process.Start("sh", "-c " + command);
        }

        // -------------------------------------------------------------------
        // VULN 4: String interpolation chain - 4-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> BuildInterpolatedQuery(string tableName, string condition)
        {
            string clause = FormatClause(condition);
            string query = WrapInSelect(tableName, clause);
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(query, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        private string FormatClause(string rawCondition)
        {
            string formatted = $"WHERE {rawCondition}";
            return formatted;
        }

        private string WrapInSelect(string table, string whereClause)
        {
            string sql = $"SELECT * FROM {table} {whereClause}";
            return sql;
        }

        // -------------------------------------------------------------------
        // VULN 5: Extension method chain - 3-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> RunExtensionChain(string userInput)
        {
            string enclosed = userInput.Enclose("'");
            string sql = "SELECT * FROM patients WHERE name = " + enclosed;
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        // -------------------------------------------------------------------
        // VULN 6: Record type with tainted fields - 3-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ProcessRecord(string name, string ssn, string diagnosis)
        {
            var record = new PatientRecord(name, ssn, diagnosis);
            string sql = "SELECT * FROM diagnoses WHERE code = '" + record.Diagnosis + "'";
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        // -------------------------------------------------------------------
        // VULN 7: Tuple return destructured - 3-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> HandleTupleFlow(string combinedInput)
        {
            var (table, condition) = SplitInput(combinedInput);
            string sql = "SELECT * FROM " + table + " WHERE " + condition;
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        private (string tableName, string whereClause) SplitInput(string raw)
        {
            int idx = raw.IndexOf(':');
            if (idx < 0)
            {
                return ("patients", raw);
            }
            string tablePart = raw.Substring(0, idx);
            string conditionPart = raw.Substring(idx + 1);
            return (tablePart, conditionPart);
        }

        // -------------------------------------------------------------------
        // VULN 8: Delegate/event flow - 3-hop chain
        // -------------------------------------------------------------------
        public void HandleWithDelegate(string userInput, string outputPath)
        {
            string transformed = _processor(userInput);
            File.WriteAllText(outputPath, transformed);
        }

        // -------------------------------------------------------------------
        // VULN 9: Event firing propagates taint - 2-hop chain
        // -------------------------------------------------------------------
        public void FireEvent(string rawData, string logPath)
        {
            string processed = rawData;
            if (OnDataProcessed != null)
            {
                processed = OnDataProcessed(rawData);
            }
            File.WriteAllText(logPath, processed);
        }

        // -------------------------------------------------------------------
        // VULN 10: Nullable reference - 3-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> HandleNullable(string userInput)
        {
            string filter = GetOptionalFilter(userInput);
            string effectiveFilter = filter ?? "1=1";
            string sql = "SELECT * FROM patients WHERE " + effectiveFilter;
            var conn = new SqlConnection(_connectionString);
            conn.Open();
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return ReadResults(reader);
        }

        private string GetOptionalFilter(string raw)
        {
            if (string.IsNullOrEmpty(raw))
            {
                return null;
            }
            string filter = "status = '" + raw + "'";
            return filter;
        }

        // -------------------------------------------------------------------
        // VULN 11: Expression-bodied member - 2-hop chain
        // -------------------------------------------------------------------
        public void RunExpressionBodied(string target)
        {
            string cmd = BuildCommand(target);
            Process.Start("sh", "-c " + cmd);
        }

        private string BuildCommand(string path) => "ls -la " + path;

        // -------------------------------------------------------------------
        // VULN 12: Cross-module SQL via DataAccess - 4-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> BuildAndExecuteViaDataAccess(string tableName, string whereExpr)
        {
            string query = BuildDynamicQuery(tableName, whereExpr);
            string transformed = TransformQuery(query);
            return _dataAccess.ExecuteRawQuery(transformed);
        }

        private string BuildDynamicQuery(string table, string where)
        {
            string sql = "SELECT * FROM " + table + " WHERE " + where;
            return sql;
        }

        private string TransformQuery(string query)
        {
            string transformed = query + " LIMIT 100";
            return transformed;
        }

        // -------------------------------------------------------------------
        // VULN 13: SSRF via HttpClient - 3-hop chain
        // -------------------------------------------------------------------
        public async Task<string> FetchExternalData(string endpoint, string param)
        {
            string url = BuildApiUrl(endpoint, param);
            var client = new HttpClient();
            var response = await client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }

        private string BuildApiUrl(string endpoint, string param)
        {
            string url = "https://api.example.com/" + endpoint + "?q=" + param;
            return url;
        }

        // -------------------------------------------------------------------
        // VULN 14: Path traversal via file operations - 3-hop chain
        // -------------------------------------------------------------------
        public void ProcessFileUpload(string filename, string content)
        {
            string resolvedPath = ResolveFilePath(filename);
            File.WriteAllText(resolvedPath, content);
        }

        private string ResolveFilePath(string filename)
        {
            string basePath = "/var/healthcare/uploads/";
            string fullPath = basePath + filename;
            return fullPath;
        }

        // -------------------------------------------------------------------
        // VULN 15: Command injection via multi-step build - 4-hop chain
        // -------------------------------------------------------------------
        public void RunDiagnostic(string target, string options)
        {
            string args = BuildDiagnosticArgs(target, options);
            string fullCmd = AssembleCommand("diagnostic-tool", args);
            Process.Start("sh", "-c " + fullCmd);
        }

        private string BuildDiagnosticArgs(string target, string options)
        {
            string args = "--target " + target + " " + options;
            return args;
        }

        private string AssembleCommand(string tool, string args)
        {
            string cmd = tool + " " + args;
            return cmd;
        }

        // -------------------------------------------------------------------
        // VULN 16: SQL injection via generic query - 4-hop chain through DataAccess
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ExecuteGenericQuery(string baseTable, string filter, string sortCol)
        {
            string query = "SELECT * FROM " + baseTable;
            string filtered = ApplyFilter(query, filter);
            string sorted = ApplySort(filtered, sortCol);
            return _dataAccess.ExecuteRawQuery(sorted);
        }

        private string ApplyFilter(string query, string filter)
        {
            string result = query + " WHERE " + filter;
            return result;
        }

        private string ApplySort(string query, string sortCol)
        {
            string result = query + " ORDER BY " + sortCol;
            return result;
        }

        // -------------------------------------------------------------------
        // VULN 17: Log injection - 2-hop chain
        // -------------------------------------------------------------------
        public void LogPatientAction(string patientId, string action)
        {
            string message = FormatLogMessage(patientId, action);
            Console.WriteLine(message);
        }

        private string FormatLogMessage(string id, string action)
        {
            string msg = "[PATIENT] id=" + id + " action=" + action;
            return msg;
        }

        // -------------------------------------------------------------------
        // VULN 18: Unsafe reflection - 3-hop chain
        // -------------------------------------------------------------------
        public object InstantiateHandler(string handlerType)
        {
            Type resolved = ResolveType(handlerType);
            return Activator.CreateInstance(resolved);
        }

        private Type ResolveType(string typeName)
        {
            string fullName = "HealthcareAPI.Handlers." + typeName;
            Type type = Type.GetType(fullName);
            return type;
        }

        // -------------------------------------------------------------------
        // VULN 19: Cross-module SQL injection via PatientService - 5-hop chain
        // AdvancedPatterns -> PatientService.FilterPatients -> QueryBuilder
        //   -> DataAccess.ExecuteRawQuery -> SqlCommand
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> SearchViaService(string column, string value)
        {
            string normalizedCol = column.Trim();
            string normalizedVal = value.Trim();
            return _patientService.FilterPatients(normalizedCol, normalizedVal);
        }

        // -------------------------------------------------------------------
        // VULN 20: Cross-module command injection via ReportGenerator - 5-hop chain
        // AdvancedPatterns -> ReportGenerator.ExportToFormat -> CommandBuilder
        //   -> Process.Start
        // -------------------------------------------------------------------
        public void ExportViaReportGenerator(string format, string destPath)
        {
            string normalizedFormat = format.Trim();
            _reportGenerator.ExportToFormat("/tmp/report.html", normalizedFormat, destPath);
        }

        // -------------------------------------------------------------------
        // VULN 21: Cross-module path traversal via ReportGenerator - 4-hop chain
        // AdvancedPatterns -> ReportGenerator.ReadReport -> File.ReadAllText
        // -------------------------------------------------------------------
        public string ReadReportViaGenerator(string filename)
        {
            string normalized = filename.Trim();
            return _reportGenerator.ReadReport(normalized);
        }

        // -------------------------------------------------------------------
        // VULN 22: Cross-module SSRF via ReportGenerator - 4-hop chain
        // AdvancedPatterns -> ReportGenerator.SendReportWebhook -> HttpClient.PostAsync
        // -------------------------------------------------------------------
        public async Task SendNotification(string webhookUrl, string message)
        {
            string url = webhookUrl.Trim();
            await _reportGenerator.SendReportWebhook(url, message);
        }

        // -------------------------------------------------------------------
        // VULN 23: SQL injection via dynamic table query in DataAccess - 3-hop chain
        // AdvancedPatterns -> DataAccess.QueryDynamicTable -> SqlCommand
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> QueryDynamic(string tableName, string columns)
        {
            return _dataAccess.QueryDynamicTable(tableName, columns);
        }

        // -------------------------------------------------------------------
        // VULN 24: Command injection via DataAccess backup - 3-hop chain
        // AdvancedPatterns -> DataAccess.BackupTable -> Process.Start
        // -------------------------------------------------------------------
        public void BackupPatientTable(string tableName, string outputDir)
        {
            _dataAccess.BackupTable(tableName, outputDir);
        }

        // -------------------------------------------------------------------
        // VULN 25: SSRF via DataAccess sync - 3-hop chain
        // AdvancedPatterns -> DataAccess.SyncFromRemote -> HttpClient.GetAsync
        // -------------------------------------------------------------------
        public async Task<string> SyncData(string remoteUrl)
        {
            return await _dataAccess.SyncFromRemote(remoteUrl);
        }

        // -------------------------------------------------------------------
        // Helper methods
        // -------------------------------------------------------------------
        private string TransformData(string input)
        {
            string result = "PROCESSED: " + input;
            return result;
        }

        private List<Dictionary<string, object>> ReadResults(SqlDataReader reader)
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

    // Extension method class
    public static class StringExtensions
    {
        public static string Enclose(this string value, string delimiter)
        {
            string result = delimiter + value + delimiter;
            return result;
        }
    }

    // Entry point that provides actual sources for all vulnerability chains
    public class AdvancedPatternsEntryPoint
    {
        public static void RunAllChains()
        {
            var connString = "Server=.;Database=Healthcare;Trusted_Connection=True;";
            var dataAccess = new DataAccess(connString);
            var patientService = new PatientService(dataAccess);
            var reportGenerator = new ReportGenerator(dataAccess, "/tmp/reports");
            var auditService = new AuditService(dataAccess);
            var patterns = new AdvancedPatterns(connString, dataAccess, patientService, reportGenerator);

            // VULN 1: Console.ReadLine -> LINQ SQL injection
            string filter = Console.ReadLine();
            string sortCol = Console.ReadLine();
            patterns.HandleLinqSearch(filter, sortCol);

            // VULN 2: Console.ReadLine -> async/await SQL injection
            string searchTerm = Console.ReadLine();
            patterns.FetchAndStoreAsync(searchTerm);

            // VULN 3: Console.ReadLine -> pattern matching -> command injection
            string category = Console.ReadLine();
            string cmdInput = Console.ReadLine();
            patterns.ProcessByCategory(category, cmdInput);

            // VULN 4: Console.ReadLine -> interpolation -> SQL injection
            string tableName = Console.ReadLine();
            string condition = Console.ReadLine();
            patterns.BuildInterpolatedQuery(tableName, condition);

            // VULN 5: Console.ReadLine -> extension method -> SQL injection
            string extInput = Console.ReadLine();
            patterns.RunExtensionChain(extInput);

            // VULN 6: Console.ReadLine -> record type -> SQL injection
            string name = Console.ReadLine();
            string ssn = Console.ReadLine();
            string diagnosis = Console.ReadLine();
            patterns.ProcessRecord(name, ssn, diagnosis);

            // VULN 7: Console.ReadLine -> tuple destructure -> SQL injection
            string combined = Console.ReadLine();
            patterns.HandleTupleFlow(combined);

            // VULN 8: Console.ReadLine -> delegate -> File.WriteAllText
            string delegateInput = Console.ReadLine();
            string outputPath = Console.ReadLine();
            patterns.HandleWithDelegate(delegateInput, outputPath);

            // VULN 9: Console.ReadLine -> event -> File.WriteAllText
            string eventData = Console.ReadLine();
            string logPath = Console.ReadLine();
            patterns.FireEvent(eventData, logPath);

            // VULN 10: Console.ReadLine -> nullable -> SQL injection
            string nullableInput = Console.ReadLine();
            patterns.HandleNullable(nullableInput);

            // VULN 11: Environment variable -> expression-bodied -> command injection
            string target = Environment.GetEnvironmentVariable("EXPORT_TARGET");
            patterns.RunExpressionBodied(target);

            // VULN 12: Console.ReadLine -> cross-module SQL via DataAccess
            string dynTable = Console.ReadLine();
            string dynWhere = Console.ReadLine();
            patterns.BuildAndExecuteViaDataAccess(dynTable, dynWhere);

            // VULN 13: Console.ReadLine -> SSRF via HttpClient
            string apiEndpoint = Console.ReadLine();
            patterns.FetchExternalData(apiEndpoint, "test");

            // VULN 14: Console.ReadLine -> path traversal via file upload
            string uploadName = Console.ReadLine();
            patterns.ProcessFileUpload(uploadName, "content");

            // VULN 15: Console.ReadLine -> command injection via diagnostic
            string diagTarget = Console.ReadLine();
            patterns.RunDiagnostic(diagTarget, "--verbose");

            // VULN 16: Console.ReadLine -> generic query SQL injection via DataAccess
            string genericTable = Console.ReadLine();
            string genericFilter = Console.ReadLine();
            patterns.ExecuteGenericQuery(genericTable, genericFilter, "id");

            // VULN 17: Console.ReadLine -> log injection
            string logUserId = Console.ReadLine();
            patterns.LogPatientAction(logUserId, "view_record");

            // VULN 18: Console.ReadLine -> unsafe reflection
            string handlerType = Console.ReadLine();
            patterns.InstantiateHandler(handlerType);

            // VULN 19: Console.ReadLine -> cross-module via PatientService
            string svcColumn = Console.ReadLine();
            string svcValue = Console.ReadLine();
            patterns.SearchViaService(svcColumn, svcValue);

            // VULN 20: Console.ReadLine -> cross-module command injection via ReportGenerator
            string expFormat = Console.ReadLine();
            patterns.ExportViaReportGenerator(expFormat, "/tmp/output");

            // VULN 21: Console.ReadLine -> cross-module path traversal via ReportGenerator
            string reportFile = Console.ReadLine();
            patterns.ReadReportViaGenerator(reportFile);

            // VULN 22: Console.ReadLine -> cross-module SSRF via ReportGenerator
            string notifyUrl = Console.ReadLine();
            patterns.SendNotification(notifyUrl, "alert");

            // VULN 23: Console.ReadLine -> dynamic table query
            string dynTableName = Console.ReadLine();
            patterns.QueryDynamic(dynTableName, "name, dob");

            // VULN 24: Console.ReadLine -> command injection via backup
            string backupTable = Console.ReadLine();
            patterns.BackupPatientTable(backupTable, "/tmp/backups");

            // VULN 25: Console.ReadLine -> SSRF via data sync
            string syncUrl = Console.ReadLine();
            patterns.SyncData(syncUrl);
        }
    }
}

    // ============================================================
    // ADDITIONAL PATTERNS - Attributes, LINQ, inheritance, patterns
    // ============================================================

    // Attribute-based handler (simulated ASP.NET)
    // [HttpGet("/api/exec")]
    public string AttributeHandler(string input)
    {
        return Process.Start(input)?.StandardOutput.ReadToEnd() ?? "";
    }

    // LINQ chain with taint flow
    public string LinqFlow(List<string> inputs)
    {
        var result = inputs
            .Where(x => x.StartsWith("cmd:"))
            .Select(x => x.Substring(4))
            .FirstOrDefault();
        Process.Start(result);  // taint flows through LINQ chain
        return result;
    }

    // Pattern matching (C# 8+)
    public string PatternMatchFlow(object input)
    {
        return input switch
        {
            string s when s.Length > 0 => s,  // taint through pattern
            int n => n.ToString(),
            null => "empty",
            _ => throw new ArgumentException()
        };
    }

    // Inheritance chain
    public abstract class BaseService
    {
        public abstract string Process(string data);
        public string Handle(string data) => Process(data);  // virtual dispatch
    }

    public class UnsafeService : BaseService
    {
        public override string Process(string data)
        {
            System.Diagnostics.Process.Start(data);  // overridden sink
            return data;
        }
    }

    // String interpolation flow
    public void InterpolationFlow(string userInput)
    {
        var query = $"SELECT * FROM users WHERE name = '{userInput}'";
        // query contains tainted interpolated string
    }

    // Nullable reference type flow
    public void NullableFlow(string? input)
    {
        if (input is not null)
        {
            Process.Start(input);  // null-checked taint
        }
        var safe = input ?? "default";
        Process.Start(safe);  // coalesced taint
    }

    // Async stream (IAsyncEnumerable)
    public async IAsyncEnumerable<string> StreamFlow(string input)
    {
        yield return input;  // taint through async stream
        await Task.Delay(100);
        yield return input.ToUpper();
    }
}

    // Interface dispatch
    public interface ICommandRunner
    {
        void Run(string cmd);
    }

    public class ShellRunner : ICommandRunner
    {
        public void Run(string cmd) { System.Diagnostics.Process.Start(cmd); }
    }

    // Property accessors
    public class ConfigHolder
    {
        private string _command = "";
        public string Command
        {
            get; set;
        }
    }
