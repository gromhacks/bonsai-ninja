using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace HealthcareAPI.CrossModule
{
    // Delegate type used for callback chains
    public delegate string QueryTransformer(string input);

    public class CrossModuleService
    {
        private readonly PatientController _controller;
        private readonly PatientService _patientService;
        private readonly DataAccess _dataAccess;
        private readonly ReportGenerator _reportGenerator;
        private readonly AuditService _auditService;

        // Static field for cross-method taint flow
        public static string SharedFilter;

        public CrossModuleService(
            PatientController controller,
            PatientService patientService,
            DataAccess dataAccess,
            ReportGenerator reportGenerator,
            AuditService auditService)
        {
            _controller = controller;
            _patientService = patientService;
            _dataAccess = dataAccess;
            _reportGenerator = reportGenerator;
            _auditService = auditService;
        }

        // -------------------------------------------------------------------
        // CHAIN A: 7-hop chain across 4 files
        // IngestExternalData -> NormalizePayload -> EnrichPayload
        //   -> RouteToController -> Controller.FilterPatients
        //   -> Service.FilterPatients -> QueryBuilder.BuildFilterQuery
        //   -> DataAccess.ExecuteRawQuery
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> IngestExternalData(string userPayload)
        {
            string normalized = NormalizePayload(userPayload);
            string enriched = EnrichPayload(normalized);
            return RouteToController(enriched);
        }

        private string NormalizePayload(string raw)
        {
            string trimmed = raw.Trim();
            string lower = trimmed.ToLower();
            return lower;
        }

        private string EnrichPayload(string data)
        {
            string enriched = "patient_" + data;
            return enriched;
        }

        private List<Dictionary<string, object>> RouteToController(string filter)
        {
            return _controller.FilterPatients("name", filter);
        }

        // -------------------------------------------------------------------
        // CHAIN B: Static field flow
        // SetSharedFilter -> SharedFilter -> ConsumeSharedFilter -> SQL injection
        // -------------------------------------------------------------------
        public void SetSharedFilter(string userInput)
        {
            SharedFilter = userInput;
        }

        public List<Dictionary<string, object>> ConsumeSharedFilter()
        {
            string filter = SharedFilter;
            string sql = QueryBuilder.BuildWhereClause("SELECT * FROM patients", filter);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // -------------------------------------------------------------------
        // CHAIN C: Delegate/callback flow
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ExecuteWithCallback(string userQuery)
        {
            QueryTransformer transformer = BuildDangerousQuery;
            string sql = transformer(userQuery);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        private string BuildDangerousQuery(string input)
        {
            string query = "SELECT * FROM audit_log WHERE action = '" + input + "'";
            return query;
        }

        public List<Dictionary<string, object>> ExecuteWithExternalCallback(
            string userQuery, QueryTransformer callback)
        {
            string sql = callback(userQuery);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        // -------------------------------------------------------------------
        // CHAIN D: Cross-module wrapper through ReportGenerator
        // -------------------------------------------------------------------
        public string RunReportWrapper(string reportType, string startDate, string endDate)
        {
            string validatedType = ValidateAndForward(reportType);
            return _reportGenerator.GenerateCustomReport(validatedType, startDate, endDate);
        }

        private string ValidateAndForward(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return "default_report";
            }
            string forwarded = input;
            return forwarded;
        }

        // CHAIN D2: Raw SQL wrapper
        public string RunRawQueryWrapper(string rawSql)
        {
            string query = PrepareQuery(rawSql);
            return _reportGenerator.QueryAndFormat(query);
        }

        private string PrepareQuery(string sql)
        {
            string prepared = sql.Trim();
            return prepared;
        }

        // -------------------------------------------------------------------
        // CHAIN E: Recursive chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ProcessRecursive(string userInput)
        {
            string sql = RecursiveTransform(userInput, 3);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        private string RecursiveTransform(string data, int depth)
        {
            if (depth <= 0)
            {
                string terminal = "SELECT * FROM patients WHERE name = '" + data + "'";
                return terminal;
            }
            string wrapped = "(" + data + ")";
            string result = RecursiveTransform(wrapped, depth - 1);
            return result;
        }

        // -------------------------------------------------------------------
        // CHAIN F: Command injection through static field
        // -------------------------------------------------------------------
        public void ExportSharedAsCommand()
        {
            string filter = SharedFilter;
            string archiveName = "export_" + filter + ".tar.gz";
            string cmd = CommandBuilder.BuildArchiveCommand(archiveName, "/tmp/reports");
            Process.Start("sh", "-c " + cmd);
        }

        // -------------------------------------------------------------------
        // CHAIN G: Deep search pipeline - 8-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> DeepSearchPipeline(string userTerm)
        {
            string preprocessed = PreprocessTerm(userTerm);
            string formatted = FormatSearchTerm(preprocessed);
            return _controller.SearchPatients(formatted, "name", "100");
        }

        private string PreprocessTerm(string raw)
        {
            string cleaned = raw.Trim();
            return cleaned;
        }

        private string FormatSearchTerm(string term)
        {
            string formatted = term.Replace("_", " ");
            return formatted;
        }

        // -------------------------------------------------------------------
        // CHAIN H: Cross-module path traversal - 5-hop chain
        // -------------------------------------------------------------------
        public string HandleFileRequest(string userFilename)
        {
            string validated = ValidateFilename(userFilename);
            return LoadFromReports(validated);
        }

        private string ValidateFilename(string filename)
        {
            string trimmed = filename.Trim();
            return trimmed;
        }

        private string LoadFromReports(string filename)
        {
            return _reportGenerator.ReadReport(filename);
        }

        // -------------------------------------------------------------------
        // CHAIN I: Cross-module SSRF - 4-hop chain
        // -------------------------------------------------------------------
        public async Task TriggerWebhook(string userUrl, string data)
        {
            string formattedUrl = FormatWebhookUrl(userUrl);
            await _reportGenerator.SendReportWebhook(formattedUrl, data);
        }

        private string FormatWebhookUrl(string url)
        {
            string formatted = url.Trim();
            return formatted;
        }

        // -------------------------------------------------------------------
        // CHAIN J: Cross-module command injection via conversion - 5-hop chain
        // -------------------------------------------------------------------
        public void ProcessFileConversion(string inputFile, string outputFormat)
        {
            string sanitized = InputValidator.WeakSanitize(inputFile);
            _reportGenerator.ConvertFile(sanitized, outputFormat);
        }

        // -------------------------------------------------------------------
        // CHAIN K: SQL injection via join through service - 6-hop chain
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> QueryRelatedData(string tableName, string joinCol, string filterVal)
        {
            string transformedTable = TransformTableName(tableName);
            return _patientService.GetPatientWithRelated(transformedTable, joinCol, filterVal);
        }

        private string TransformTableName(string tableName)
        {
            string transformed = tableName.Trim().ToLower();
            return transformed;
        }

        // -------------------------------------------------------------------
        // CHAIN L: Cross-module SQL injection via filtered report - 6-hop chain
        // -------------------------------------------------------------------
        public string GenerateFilteredReportWrapper(string column, string value)
        {
            string normalizedCol = NormalizeFilter(column);
            string normalizedVal = NormalizeFilter(value);
            return _reportGenerator.GenerateFilteredReport(normalizedCol, normalizedVal);
        }

        private string NormalizeFilter(string input)
        {
            string normalized = input.Trim();
            return normalized;
        }

        // -------------------------------------------------------------------
        // CHAIN M: Path traversal via template loading - 5-hop chain
        // -------------------------------------------------------------------
        public string LoadReportTemplate(string templateName)
        {
            string validated = ValidateTemplateName(templateName);
            return _reportGenerator.LoadTemplate(validated);
        }

        private string ValidateTemplateName(string name)
        {
            string cleaned = name.Trim();
            return cleaned;
        }

        // -------------------------------------------------------------------
        // CHAIN N: Command injection via cleanup - 5-hop chain
        // -------------------------------------------------------------------
        public void ScheduleCleanup(string directory, string filePattern)
        {
            string formattedDir = FormatCleanupParams(directory);
            _reportGenerator.CleanupReports(formattedDir, filePattern);
        }

        private string FormatCleanupParams(string param)
        {
            string formatted = param.Trim();
            return formatted;
        }

        // -------------------------------------------------------------------
        // CHAIN O: SQL injection via audit service - 5-hop chain
        // ProcessAuditQuery -> NormalizeAuditParams -> AuditService.SearchAuditLogs
        //   -> BuildAuditQuery -> DataAccess.ExecuteRawQuery -> SqlCommand
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ProcessAuditQuery(string userId, string action)
        {
            string normalizedUser = NormalizeAuditParam(userId);
            string normalizedAction = NormalizeAuditParam(action);
            return _auditService.SearchAuditLogs(normalizedUser, normalizedAction, "date > '2024-01-01'");
        }

        private string NormalizeAuditParam(string param)
        {
            string normalized = param.Trim();
            return normalized;
        }

        // -------------------------------------------------------------------
        // CHAIN P: Log injection via audit service - 5-hop chain
        // RecordPatientAccess -> FormatAccessDetails -> AuditService.LogAction
        //   -> FormatAuditEntry -> Console.WriteLine
        // -------------------------------------------------------------------
        public void RecordPatientAccess(string userId, string patientId)
        {
            string details = FormatAccessDetails(userId, patientId);
            _auditService.LogAction(userId, "access", details);
        }

        private string FormatAccessDetails(string userId, string patientId)
        {
            string details = "User " + userId + " accessed patient " + patientId;
            return details;
        }

        // -------------------------------------------------------------------
        // CHAIN Q: SQL injection via subquery - 6-hop chain
        // ExecuteComplexQuery -> BuildInnerQuery -> PatientService.ExecuteSubQuery
        //   -> QueryBuilder.BuildSubQuery -> DataAccess.ExecuteRawQuery -> SqlCommand
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> ExecuteComplexQuery(string tableName, string filter)
        {
            string innerQuery = BuildInnerQuery(tableName);
            return _patientService.ExecuteSubQuery(innerQuery, filter);
        }

        private string BuildInnerQuery(string tableName)
        {
            string sql = "SELECT * FROM " + tableName;
            return sql;
        }

        // -------------------------------------------------------------------
        // CHAIN R: Direct SQL injection in CrossModule - 3-hop chain
        // DirectQuery -> BuildDirectSql -> DataAccess.ExecuteRawQuery
        // -------------------------------------------------------------------
        public List<Dictionary<string, object>> DirectQuery(string userFilter)
        {
            string sql = BuildDirectSql(userFilter);
            return _dataAccess.ExecuteRawQuery(sql);
        }

        private string BuildDirectSql(string filter)
        {
            string sql = "SELECT * FROM patients WHERE " + filter;
            return sql;
        }

        // -------------------------------------------------------------------
        // CHAIN S: Direct command injection in CrossModule - 2-hop chain
        // ExecuteSystemCommand -> Process.Start
        // -------------------------------------------------------------------
        public void ExecuteSystemCommand(string userCommand)
        {
            string fullCmd = "healthcare-tool " + userCommand;
            Process.Start("sh", "-c " + fullCmd);
        }

        // -------------------------------------------------------------------
        // CHAIN T: Direct path traversal in CrossModule - 2-hop chain
        // ReadConfigFile -> File.ReadAllText
        // -------------------------------------------------------------------
        public string ReadConfigFile(string configPath)
        {
            string fullPath = "/etc/healthcare/" + configPath;
            return File.ReadAllText(fullPath);
        }

        // -------------------------------------------------------------------
        // CHAIN U: Direct SSRF in CrossModule - 3-hop chain
        // FetchExternalApi -> BuildUrl -> HttpClient.GetAsync
        // -------------------------------------------------------------------
        public async Task<string> FetchExternalApi(string endpoint)
        {
            string url = BuildExternalUrl(endpoint);
            var client = new HttpClient();
            var response = await client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }

        private string BuildExternalUrl(string endpoint)
        {
            string url = "https://api.healthcare.com/" + endpoint;
            return url;
        }

        // -------------------------------------------------------------------
        // CHAIN V: Path traversal via data export - 5-hop chain
        // ExportPatientRecords -> FormatExportPath -> PatientService.ExportPatientData
        //   -> DataAccess.ExportToFile -> File.WriteAllText
        // -------------------------------------------------------------------
        public void ExportPatientRecords(string patientId, string outputDir)
        {
            string exportPath = FormatExportPath(outputDir, patientId);
            _patientService.ExportPatientData(patientId, exportPath);
        }

        private string FormatExportPath(string dir, string id)
        {
            string path = dir + "/patient_" + id + ".csv";
            return path;
        }
    }

    // Entry point that provides actual sources for all chains
    public class CrossModuleEntryPoint
    {
        public static void RunAllChains()
        {
            var connString = "Server=.;Database=Healthcare;Trusted_Connection=True;";
            var dataAccess = new DataAccess(connString);
            var patientService = new PatientService(dataAccess);
            var reportGenerator = new ReportGenerator(dataAccess, "/tmp/reports");
            var auditService = new AuditService(dataAccess);
            var controller = new PatientController(patientService, reportGenerator, dataAccess, auditService);
            var service = new CrossModuleService(controller, patientService, dataAccess, reportGenerator, auditService);

            // Chain A: Console.ReadLine -> IngestExternalData -> SQL injection
            string userInput = Console.ReadLine();
            service.IngestExternalData(userInput);

            // Chain B: Environment variable -> static field -> SQL injection
            string envFilter = Environment.GetEnvironmentVariable("PATIENT_FILTER");
            service.SetSharedFilter(envFilter);
            service.ConsumeSharedFilter();

            // Chain C: Console.ReadLine -> callback -> SQL injection
            string query = Console.ReadLine();
            service.ExecuteWithCallback(query);

            // Chain D: Console.ReadLine -> report wrapper -> SQL injection
            string reportType = Console.ReadLine();
            service.RunReportWrapper(reportType, "2024-01-01", "2024-12-31");

            // Chain D2: Console.ReadLine -> raw query wrapper -> SQL injection
            string rawSql = Console.ReadLine();
            service.RunRawQueryWrapper(rawSql);

            // Chain E: Console.ReadLine -> recursive -> SQL injection
            string recursiveInput = Console.ReadLine();
            service.ProcessRecursive(recursiveInput);

            // Chain F: env var -> command injection (uses static field)
            service.ExportSharedAsCommand();

            // Chain G: Console.ReadLine -> deep search pipeline
            string searchTerm = Console.ReadLine();
            service.DeepSearchPipeline(searchTerm);

            // Chain H: Console.ReadLine -> file request -> path traversal
            string requestedFile = Console.ReadLine();
            service.HandleFileRequest(requestedFile);

            // Chain I: Console.ReadLine -> webhook -> SSRF
            string webhookUrl = Console.ReadLine();
            service.TriggerWebhook(webhookUrl, "data");

            // Chain J: Console.ReadLine -> file conversion -> command injection
            string convertFile = Console.ReadLine();
            service.ProcessFileConversion(convertFile, "pdf");

            // Chain K: Console.ReadLine -> related data join -> SQL injection
            string tableName = Console.ReadLine();
            service.QueryRelatedData(tableName, "patient_id", "active");

            // Chain L: Console.ReadLine -> filtered report -> SQL injection
            string filterCol = Console.ReadLine();
            string filterVal = Console.ReadLine();
            service.GenerateFilteredReportWrapper(filterCol, filterVal);

            // Chain M: Console.ReadLine -> template load -> path traversal
            string templateName = Console.ReadLine();
            service.LoadReportTemplate(templateName);

            // Chain N: Console.ReadLine -> cleanup -> command injection
            string cleanupDir = Console.ReadLine();
            string cleanupPattern = Console.ReadLine();
            service.ScheduleCleanup(cleanupDir, cleanupPattern);

            // Chain O: Console.ReadLine -> audit query -> SQL injection
            string auditUser = Console.ReadLine();
            string auditAction = Console.ReadLine();
            service.ProcessAuditQuery(auditUser, auditAction);

            // Chain P: Console.ReadLine -> patient access log injection
            string accessUser = Console.ReadLine();
            service.RecordPatientAccess(accessUser, "P001");

            // Chain Q: Console.ReadLine -> complex subquery -> SQL injection
            string subTable = Console.ReadLine();
            service.ExecuteComplexQuery(subTable, "active = 1");

            // Chain R: Console.ReadLine -> direct SQL injection
            string directFilter = Console.ReadLine();
            service.DirectQuery(directFilter);

            // Chain S: Console.ReadLine -> direct command injection
            string sysCmd = Console.ReadLine();
            service.ExecuteSystemCommand(sysCmd);

            // Chain T: Console.ReadLine -> direct path traversal
            string configPath = Console.ReadLine();
            service.ReadConfigFile(configPath);

            // Chain U: Console.ReadLine -> SSRF via external API
            string apiEndpoint = Console.ReadLine();
            service.FetchExternalApi(apiEndpoint);

            // Chain V: Console.ReadLine -> export path traversal
            string exportDir = Console.ReadLine();
            service.ExportPatientRecords("P001", exportDir);
        }
    }
}
