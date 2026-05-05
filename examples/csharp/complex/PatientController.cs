using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml;

namespace HealthcareAPI.Controllers
{
    public class PatientController
    {
        private readonly PatientService _patientService;
        private readonly ReportGenerator _reportGenerator;
        private readonly InputValidator _validator;
        private readonly DataAccess _dataAccess;
        private readonly AuditService _auditService;

        public PatientController(PatientService patientService, ReportGenerator reportGenerator, DataAccess dataAccess, AuditService auditService)
        {
            _patientService = patientService;
            _reportGenerator = reportGenerator;
            _dataAccess = dataAccess;
            _auditService = auditService;
            _validator = new InputValidator();
        }

        // VULN: SQL injection via search - 5-hop cross-file chain
        public List<Dictionary<string, object>> SearchPatients(string query, string sortBy, string limit)
        {
            return _patientService.SearchPatients(query, sortBy, limit);
        }

        // Safe version
        public List<Dictionary<string, object>> SearchPatientsSafe(string query, string sortBy)
        {
            return _patientService.SearchPatientsSafe(query, sortBy);
        }

        // VULN: SQL injection via patient lookup - 4-hop chain
        public Dictionary<string, object> GetPatient(string patientId)
        {
            return _patientService.GetPatientById(patientId);
        }

        // VULN: SQL injection via patient creation - 4-hop chain
        public Dictionary<string, object> CreatePatient(string name, string dob, string ssn)
        {
            return _patientService.CreatePatient(name, dob, ssn);
        }

        // VULN: SQL injection via filter - 5-hop chain
        public List<Dictionary<string, object>> FilterPatients(string column, string value)
        {
            return _patientService.FilterPatients(column, value);
        }

        // VULN: SQL injection via report - 5-hop chain
        public List<Dictionary<string, object>> GetReport(string reportType, string startDate, string endDate)
        {
            return _patientService.GetPatientReport(reportType, startDate, endDate);
        }

        // VULN: SQL injection via count - 4-hop chain
        public object CountPatients(string condition)
        {
            return _patientService.CountByCondition(condition);
        }

        // VULN: SQL injection via delete - 4-hop chain
        public int PurgePatients(string condition)
        {
            return _patientService.DeleteByCondition(condition);
        }

        // VULN: Command injection via PDF export - 4-hop chain
        public void ExportReportToPdf(string outputPath)
        {
            string reportContent = _reportGenerator.GeneratePatientReport("P001");
            _reportGenerator.ExportToPdf(reportContent, outputPath);
        }

        // VULN: Command injection via export format - 4-hop chain
        public void ExportReport(string reportPath, string format, string destPath)
        {
            _reportGenerator.ExportToFormat(reportPath, format, destPath);
        }

        // VULN: Command injection via archive - 4-hop chain
        public void ArchiveReports(string archiveName, string directory)
        {
            _reportGenerator.ArchiveReports(archiveName, directory);
        }

        // VULN: SQL injection through ReportGenerator - 6-hop chain
        public string GenerateCustomReport(string reportType, string startDate, string endDate)
        {
            return _reportGenerator.GenerateCustomReport(reportType, startDate, endDate);
        }

        // VULN: SQL injection - raw query through report generator - 4-hop chain
        public string RunReportQuery(string rawSql)
        {
            return _reportGenerator.QueryAndFormat(rawSql);
        }

        // VULN: Command injection - direct 2-hop
        public string GenerateReport(string reportType, string dateRange)
        {
            string cmd = "report-generator --type " + reportType + " --range " + dateRange;
            Process.Start("cmd.exe", "/c " + cmd);
            return "Report generated";
        }

        // VULN: XXE - direct
        public string ImportPatientData(Stream xmlStream)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            var reader = XmlReader.Create(xmlStream, settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return doc.DocumentElement.Name;
        }

        // Safe version
        public string ImportPatientDataSafe(Stream xmlStream)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            var reader = XmlReader.Create(xmlStream, settings);
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.Load(reader);
            return doc.DocumentElement.Name;
        }

        // VULN: SSRF - direct
        public async Task<string> FetchExternalRecord(string url)
        {
            var client = new HttpClient();
            var response = await client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }

        // VULN: Deserialization - direct
        public object RestoreSession(byte[] data)
        {
            var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (var stream = new MemoryStream(data))
            {
                return formatter.Deserialize(stream);
            }
        }

        // VULN: Path traversal - direct
        public string DownloadReport(string filename)
        {
            string basePath = "/var/healthcare/reports/";
            string filePath = basePath + filename;
            return File.ReadAllText(filePath);
        }

        // Safe version
        public string DownloadReportSafe(string filename)
        {
            string basePath = "/var/healthcare/reports/";
            string safeName = Path.GetFileName(filename);
            string filePath = Path.Combine(basePath, safeName);
            string fullPath = Path.GetFullPath(filePath);
            if (!fullPath.StartsWith(Path.GetFullPath(basePath)))
            {
                throw new UnauthorizedAccessException("Invalid path");
            }
            return File.ReadAllText(fullPath);
        }

        // VULN: LDAP injection - direct
        public string SearchDirectory(string username)
        {
            string filter = "(uid=" + username + ")";
            return "LDAP search: " + filter;
        }

        // VULN: Open redirect - direct
        public string Redirect(string returnUrl)
        {
            return "Redirect to: " + returnUrl;
        }

        // VULN: Unsafe reflection - direct
        public object CreateInstance(string typeName)
        {
            Type type = Type.GetType(typeName);
            return Activator.CreateInstance(type);
        }

        // VULN: Log injection - direct
        public void AuditAction(string userId, string action)
        {
            Console.WriteLine("AUDIT: User " + userId + " performed " + action);
        }

        // VULN: Path traversal via report generator - 3-hop chain
        public string ReadPatientReport(string filename)
        {
            return _reportGenerator.ReadReport(filename);
        }

        // VULN: SSRF via report webhook - 3-hop chain
        public async Task SendWebhook(string webhookUrl, string data)
        {
            await _reportGenerator.SendReportWebhook(webhookUrl, data);
        }

        // VULN: SQL injection via batch update - 5-hop chain
        public int BatchUpdatePatients(string statusFilter, string newStatus)
        {
            return _patientService.BatchUpdateStatus(statusFilter, newStatus);
        }

        // VULN: SQL injection via aggregation - 5-hop chain
        public List<Dictionary<string, object>> AggregatePatients(string groupField, string filterExpr)
        {
            return _patientService.AggregateByField(groupField, filterExpr);
        }

        // VULN: Command injection via file conversion - 4-hop chain
        public void ConvertPatientFile(string inputFile, string outputFormat)
        {
            _reportGenerator.ConvertFile(inputFile, outputFormat);
        }

        // VULN: Path traversal via file write - 4-hop chain
        public void ExportPatientData(string patientId, string outputPath)
        {
            _patientService.ExportPatientData(patientId, outputPath);
        }

        // VULN: SQL injection via subquery - 5-hop chain
        public List<Dictionary<string, object>> RunSubQuery(string innerQuery, string outerFilter)
        {
            return _patientService.ExecuteSubQuery(innerQuery, outerFilter);
        }

        // VULN: SQL injection via purge records - 5-hop chain
        public int PurgeOldRecords(string tableName, string whereClause)
        {
            return _patientService.PurgeRecords(tableName, whereClause);
        }

        // VULN: SQL injection via audit log search - 4-hop chain
        public List<Dictionary<string, object>> SearchAuditLogs(string userId, string action, string dateRange)
        {
            return _auditService.SearchAuditLogs(userId, action, dateRange);
        }

        // VULN: Log injection via audit service - 4-hop chain
        public void LogPatientAction(string userId, string action, string details)
        {
            _auditService.LogAction(userId, action, details);
        }

        // VULN: SQL injection via audit report - 3-hop chain
        public List<Dictionary<string, object>> GetAuditReport(string reportFilter)
        {
            return _auditService.GenerateAuditReport(reportFilter);
        }

        // VULN: SQL injection via pagination search - 4-hop chain
        public List<Dictionary<string, object>> SearchWithPaging(string term, string page, string size)
        {
            return _patientService.SearchWithPagination(term, page, size);
        }

        // VULN: Path traversal via query export - 4-hop chain
        public void ExportQueryResults(string condition, string outputPath)
        {
            _patientService.ExportQueryResults(condition, outputPath);
        }

        // VULN: SQL injection via join - 5-hop chain
        public List<Dictionary<string, object>> GetRelatedData(string table, string joinCol, string filter)
        {
            return _patientService.GetPatientWithRelated(table, joinCol, filter);
        }

        // VULN: Command injection via cleanup - 4-hop chain
        public void CleanupOldReports(string directory, string pattern)
        {
            _reportGenerator.CleanupReports(directory, pattern);
        }

        // VULN: Path traversal via template loading - 3-hop chain
        public string LoadTemplate(string templateName)
        {
            return _reportGenerator.LoadTemplate(templateName);
        }

        // VULN: SQL injection via filtered report - 5-hop chain
        public string GetFilteredReport(string column, string value)
        {
            return _reportGenerator.GenerateFilteredReport(column, value);
        }
    }

    // Entry point providing sources for controller chains
    public class ControllerEntryPoint
    {
        public static void HandleRequests()
        {
            var connString = "Server=.;Database=Healthcare;Trusted_Connection=True;";
            var dataAccess = new DataAccess(connString);
            var patientService = new PatientService(dataAccess);
            var reportGenerator = new ReportGenerator(dataAccess, "/tmp/reports");
            var auditService = new AuditService(dataAccess);
            var controller = new PatientController(patientService, reportGenerator, dataAccess, auditService);

            // Source: Console.ReadLine -> SearchPatients chain
            string searchQuery = Console.ReadLine();
            controller.SearchPatients(searchQuery, "name", "100");

            // Source: Console.ReadLine -> FilterPatients chain
            string filterValue = Console.ReadLine();
            controller.FilterPatients("status", filterValue);

            // Source: Console.ReadLine -> GetReport chain
            string reportType = Console.ReadLine();
            controller.GetReport(reportType, "2024-01-01", "2024-12-31");

            // Source: Console.ReadLine -> CountPatients chain
            string countCond = Console.ReadLine();
            controller.CountPatients(countCond);

            // Source: Console.ReadLine -> PurgePatients chain
            string purgeCond = Console.ReadLine();
            controller.PurgePatients(purgeCond);

            // Source: Console.ReadLine -> ExportReportToPdf command injection
            string pdfPath = Console.ReadLine();
            controller.ExportReportToPdf(pdfPath);

            // Source: Console.ReadLine -> ExportReport command injection
            string format = Console.ReadLine();
            controller.ExportReport("/tmp/report.html", format, "/tmp/output.pdf");

            // Source: Console.ReadLine -> ArchiveReports command injection
            string archiveName = Console.ReadLine();
            controller.ArchiveReports(archiveName, "/tmp/reports");

            // Source: Console.ReadLine -> GenerateCustomReport SQL injection
            string customType = Console.ReadLine();
            controller.GenerateCustomReport(customType, "2024-01-01", "2024-12-31");

            // Source: Console.ReadLine -> RunReportQuery SQL injection
            string rawSql = Console.ReadLine();
            controller.RunReportQuery(rawSql);

            // Source: Console.ReadLine -> command injection direct
            string cmdType = Console.ReadLine();
            controller.GenerateReport(cmdType, "2024-Q1");

            // Source: Console.ReadLine -> path traversal
            string filename = Console.ReadLine();
            controller.DownloadReport(filename);

            // Source: Console.ReadLine -> SSRF
            string targetUrl = Console.ReadLine();
            controller.FetchExternalRecord(targetUrl);

            // Source: Console.ReadLine -> reflection
            string typeName = Console.ReadLine();
            controller.CreateInstance(typeName);

            // Source: Console.ReadLine -> log injection
            string userId = Console.ReadLine();
            controller.AuditAction(userId, "login");

            // Source: Console.ReadLine -> report file read path traversal
            string reportFile = Console.ReadLine();
            controller.ReadPatientReport(reportFile);

            // Source: Console.ReadLine -> batch update SQL injection
            string statusFilter = Console.ReadLine();
            controller.BatchUpdatePatients(statusFilter, "active");

            // Source: Console.ReadLine -> aggregate SQL injection
            string groupField = Console.ReadLine();
            controller.AggregatePatients(groupField, "status = 'active'");

            // Source: Console.ReadLine -> file conversion command injection
            string inputFile = Console.ReadLine();
            controller.ConvertPatientFile(inputFile, "pdf");

            // Source: Console.ReadLine -> export path traversal
            string exportPath = Console.ReadLine();
            controller.ExportPatientData("P001", exportPath);

            // Source: Console.ReadLine -> GetPatient SQL injection
            string patientId = Console.ReadLine();
            controller.GetPatient(patientId);

            // Source: environment variable -> SSRF webhook
            string webhookUrl = Environment.GetEnvironmentVariable("WEBHOOK_URL");
            controller.SendWebhook(webhookUrl, "report data");

            // Source: Console.ReadLine -> subquery SQL injection
            string innerQuery = Console.ReadLine();
            controller.RunSubQuery(innerQuery, "active = 1");

            // Source: Console.ReadLine -> purge records SQL injection
            string purgeTable = Console.ReadLine();
            controller.PurgeOldRecords(purgeTable, "created_at < '2020-01-01'");

            // Source: Console.ReadLine -> audit log search SQL injection
            string auditUserId = Console.ReadLine();
            controller.SearchAuditLogs(auditUserId, "login", "date > '2024-01-01'");

            // Source: Console.ReadLine -> audit log injection
            string logUser = Console.ReadLine();
            string logDetails = Console.ReadLine();
            controller.LogPatientAction(logUser, "view_record", logDetails);

            // Source: Console.ReadLine -> audit report SQL injection
            string auditFilter = Console.ReadLine();
            controller.GetAuditReport(auditFilter);

            // Source: Console.ReadLine -> pagination search SQL injection
            string searchTerm = Console.ReadLine();
            string pageNum = Console.ReadLine();
            controller.SearchWithPaging(searchTerm, pageNum, "50");

            // Source: Console.ReadLine -> query export path traversal
            string exportCond = Console.ReadLine();
            string exportFile = Console.ReadLine();
            controller.ExportQueryResults(exportCond, exportFile);

            // Source: Console.ReadLine -> related data join SQL injection
            string relTable = Console.ReadLine();
            controller.GetRelatedData(relTable, "patient_id", "active");

            // Source: Console.ReadLine -> cleanup command injection
            string cleanupDir = Console.ReadLine();
            controller.CleanupOldReports(cleanupDir, "*.old");

            // Source: Console.ReadLine -> template loading path traversal
            string templateName = Console.ReadLine();
            controller.LoadTemplate(templateName);

            // Source: Console.ReadLine -> filtered report SQL injection
            string filtCol = Console.ReadLine();
            controller.GetFilteredReport(filtCol, "active");

            // Source: Console.ReadLine -> CreatePatient SQL injection
            string patName = Console.ReadLine();
            string patDob = Console.ReadLine();
            controller.CreatePatient(patName, patDob, "123-45-6789");
        }
    }
}
