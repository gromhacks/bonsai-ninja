using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace HealthcareAPI.Reports
{
    // Helper for building shell commands
    public static class CommandBuilder
    {
        // VULN: Command injection - concatenates user input into command string
        public static string BuildPdfCommand(string inputPath, string outputPath)
        {
            string cmd = "wkhtmltopdf " + inputPath + " " + outputPath;
            return cmd;
        }

        // VULN: Command injection - builds export command from user input
        public static string BuildExportCommand(string format, string sourcePath, string destPath)
        {
            string cmd = "report-export --format " + format + " --src " + sourcePath + " --dest " + destPath;
            return cmd;
        }

        // VULN: Command injection - builds archive command
        public static string BuildArchiveCommand(string archiveName, string directory)
        {
            string cmd = "tar -czf " + archiveName + " " + directory;
            return cmd;
        }

        // VULN: Command injection - builds conversion command
        public static string BuildConvertCommand(string inputFile, string outputFormat)
        {
            string cmd = "convert-tool --input " + inputFile + " --format " + outputFormat;
            return cmd;
        }

        // VULN: Command injection - builds cleanup command
        public static string BuildCleanupCommand(string directory, string pattern)
        {
            string cmd = "find " + directory + " -name " + pattern + " -delete";
            return cmd;
        }
    }

    public class ReportGenerator
    {
        private readonly DataAccess _dataAccess;
        private readonly string _reportDir;

        public ReportGenerator(DataAccess dataAccess, string reportDir)
        {
            _dataAccess = dataAccess;
            _reportDir = reportDir;
        }

        public string GeneratePatientReport(string patientId)
        {
            var patient = _dataAccess.FindById(patientId);
            var history = _dataAccess.GetHistory(patientId);

            string report = "Patient Report\n";
            report += "==============\n";
            report += "Name: " + patient["name"] + "\n";
            report += "DOB: " + patient["dob"] + "\n";
            report += "Visits: " + history.Count + "\n";

            foreach (var visit in history)
            {
                report += "\n  Date: " + visit["visit_date"] + ", Reason: " + visit["reason"] + "\n";
            }

            return report;
        }

        // VULN: Command injection via PDF export - 3-hop chain
        // ReportGenerator.ExportToPdf -> CommandBuilder.BuildPdfCommand -> Process.Start
        public void ExportToPdf(string reportContent, string outputPath)
        {
            string tempFile = Path.GetTempFileName();
            File.WriteAllText(tempFile, reportContent);
            string cmd = CommandBuilder.BuildPdfCommand(tempFile, outputPath);
            Process.Start("sh", "-c " + cmd);
        }

        // Safe version
        public void ExportToPdfSafe(string reportContent, string outputPath)
        {
            string tempFile = Path.GetTempFileName();
            File.WriteAllText(tempFile, reportContent);
            string safePath = Path.GetFileName(outputPath);
            string fullOutput = Path.Combine(_reportDir, safePath);
            var startInfo = new ProcessStartInfo
            {
                FileName = "wkhtmltopdf",
                Arguments = "\"" + tempFile + "\" \"" + fullOutput + "\"",
                UseShellExecute = false
            };
            Process.Start(startInfo);
        }

        // VULN: Command injection via export format - 3-hop chain
        // ReportGenerator.ExportToFormat -> CommandBuilder.BuildExportCommand -> Process.Start
        public void ExportToFormat(string reportPath, string format, string destPath)
        {
            string cmd = CommandBuilder.BuildExportCommand(format, reportPath, destPath);
            Process.Start("cmd.exe", "/c " + cmd);
        }

        // VULN: Command injection via archive - 3-hop chain
        // ReportGenerator.ArchiveReports -> CommandBuilder.BuildArchiveCommand -> Process.Start
        public void ArchiveReports(string archiveName, string directory)
        {
            string cmd = CommandBuilder.BuildArchiveCommand(archiveName, directory);
            Process.Start("sh", "-c " + cmd);
        }

        // VULN: Command injection via file conversion - 3-hop chain
        // ReportGenerator.ConvertFile -> CommandBuilder.BuildConvertCommand -> Process.Start
        public void ConvertFile(string inputFile, string outputFormat)
        {
            string cmd = CommandBuilder.BuildConvertCommand(inputFile, outputFormat);
            Process.Start("sh", "-c " + cmd);
        }

        // VULN: Command injection via cleanup - 3-hop chain
        // ReportGenerator.CleanupReports -> CommandBuilder.BuildCleanupCommand -> Process.Start
        public void CleanupReports(string directory, string pattern)
        {
            string cmd = CommandBuilder.BuildCleanupCommand(directory, pattern);
            Process.Start("sh", "-c " + cmd);
        }

        // VULN: SQL injection through report query - 4-hop chain
        // ReportGenerator -> QueryBuilder.BuildReportQuery -> DataAccess.ExecuteRawQuery -> SqlCommand
        public string GenerateCustomReport(string reportType, string startDate, string endDate)
        {
            string sql = QueryBuilder.BuildReportQuery(reportType, startDate, endDate);
            var results = _dataAccess.ExecuteRawQuery(sql);
            string report = "Custom Report\n";
            foreach (var row in results)
            {
                foreach (var kvp in row)
                {
                    report += kvp.Key + ": " + kvp.Value + ", ";
                }
                report += "\n";
            }
            return report;
        }

        // VULN: SQL injection - raw filter passed to data access - 2-hop chain
        // ReportGenerator -> DataAccess.ExecuteRawQuery -> SqlCommand
        public string QueryAndFormat(string rawSql)
        {
            var results = _dataAccess.ExecuteRawQuery(rawSql);
            string output = "";
            foreach (var row in results)
            {
                foreach (var kvp in row)
                {
                    output += kvp.Key + "=" + kvp.Value + " ";
                }
                output += "\n";
            }
            return output;
        }

        // VULN: SSRF via webhook
        public async Task SendReportWebhook(string webhookUrl, string reportData)
        {
            var client = new HttpClient();
            var content = new StringContent(reportData);
            await client.PostAsync(webhookUrl, content);
        }

        // VULN: Path traversal in report reading
        public string ReadReport(string filename)
        {
            string path = _reportDir + "/" + filename;
            return File.ReadAllText(path);
        }

        // Safe version
        public string ReadReportSafe(string filename)
        {
            string safeName = Path.GetFileName(filename);
            string path = Path.Combine(_reportDir, safeName);
            string fullPath = Path.GetFullPath(path);
            if (!fullPath.StartsWith(Path.GetFullPath(_reportDir)))
            {
                throw new UnauthorizedAccessException("Invalid path");
            }
            return File.ReadAllText(fullPath);
        }

        public Dictionary<string, object> GetReportStats()
        {
            var stats = new Dictionary<string, object>();
            var files = Directory.GetFiles(_reportDir, "*.pdf");
            stats["totalReports"] = files.Length;
            return stats;
        }

        // VULN: Template injection
        public string RenderTemplate(string template, Dictionary<string, string> data)
        {
            string result = template;
            foreach (var kvp in data)
            {
                result = result.Replace("${" + kvp.Key + "}", kvp.Value);
            }
            return result;
        }

        // VULN: SQL injection via report with filter - 4-hop chain
        // ReportGenerator -> QueryBuilder.BuildFilterQuery -> DataAccess.ExecuteRawQuery -> SqlCommand
        public string GenerateFilteredReport(string filterColumn, string filterValue)
        {
            string sql = QueryBuilder.BuildFilterQuery("report_data", filterColumn, filterValue);
            var results = _dataAccess.ExecuteRawQuery(sql);
            string report = "Filtered Report\n";
            foreach (var row in results)
            {
                report += row.ToString() + "\n";
            }
            return report;
        }

        // VULN: Path traversal via template file read - 2-hop chain
        // ReportGenerator -> DataAccess.ReadFromFile -> File.ReadAllText
        public string LoadTemplate(string templateName)
        {
            string templatePath = _reportDir + "/templates/" + templateName;
            return _dataAccess.ReadFromFile(templatePath);
        }
    }

        // VULN: Command injection via mail export
        public void MailReport(string recipientEmail, string reportPath)
        {
            string cmd = "mail -s 'Report' " + recipientEmail + " < " + reportPath;
            Process.Start("sh", "-c " + cmd);
        }

        // VULN: SQL injection via report aggregation - 3-hop chain
        public string AggregateReport(string groupBy, string having)
        {
            string sql = "SELECT " + groupBy + ", COUNT(*) FROM reports GROUP BY " + groupBy + " HAVING " + having;
            var results = _dataAccess.ExecuteRawQuery(sql);
            string report = "";
            foreach (var row in results)
            {
                report += row.ToString() + "\n";
            }
            return report;
        }

        // VULN: Path traversal via report write
        public void SaveReport(string outputPath, string content)
        {
            string fullPath = _reportDir + "/" + outputPath;
            File.WriteAllText(fullPath, content);
        }
    }

    public class FHIRClient
    {
        private readonly string _baseUrl;
        private readonly HttpClient _client;

        public FHIRClient(string baseUrl)
        {
            _baseUrl = baseUrl;
            _client = new HttpClient();
        }

        // VULN: SSRF via FHIR endpoint
        public async Task<string> GetPatientResource(string patientId)
        {
            string url = _baseUrl + "/Patient/" + patientId;
            var response = await _client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }

        // VULN: SSRF via search
        public async Task<string> SearchPatients(string query)
        {
            string url = _baseUrl + "/Patient?name=" + query;
            var response = await _client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }

        // VULN: SSRF via custom endpoint
        public async Task<string> FetchResource(string resourceType, string resourceId)
        {
            string url = _baseUrl + "/" + resourceType + "/" + resourceId;
            var response = await _client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }
    }

    // Entry point for ReportGenerator chains
    public class ReportEntryPoint
    {
        public static void RunReportChains()
        {
            var connString = "Server=.;Database=Healthcare;Trusted_Connection=True;";
            var dataAccess = new DataAccess(connString);
            var reportGenerator = new ReportGenerator(dataAccess, "/tmp/reports");

            // Source: Console.ReadLine -> mail report command injection
            string email = Console.ReadLine();
            reportGenerator.MailReport(email, "/tmp/report.pdf");

            // Source: Console.ReadLine -> aggregate report SQL injection
            string groupBy = Console.ReadLine();
            string having = Console.ReadLine();
            reportGenerator.AggregateReport(groupBy, having);

            // Source: Console.ReadLine -> save report path traversal
            string savePath = Console.ReadLine();
            reportGenerator.SaveReport(savePath, "report content");

            // Source: Console.ReadLine -> template loading path traversal
            string tmplName = Console.ReadLine();
            reportGenerator.LoadTemplate(tmplName);

            // Source: Console.ReadLine -> filtered report SQL injection
            string fColumn = Console.ReadLine();
            string fValue = Console.ReadLine();
            reportGenerator.GenerateFilteredReport(fColumn, fValue);

            // Source: Console.ReadLine -> read report path traversal
            string readFile = Console.ReadLine();
            reportGenerator.ReadReport(readFile);

            // Source: Console.ReadLine -> SSRF webhook
            string hookUrl = Console.ReadLine();
            reportGenerator.SendReportWebhook(hookUrl, "data");

            // Source: Console.ReadLine -> export PDF command injection
            string pdfOutput = Console.ReadLine();
            reportGenerator.ExportToPdf("content", pdfOutput);

            // Source: Console.ReadLine -> archive command injection
            string archName = Console.ReadLine();
            reportGenerator.ArchiveReports(archName, "/tmp/reports");

            // Source: Console.ReadLine -> convert command injection
            string convertInput = Console.ReadLine();
            reportGenerator.ConvertFile(convertInput, "pdf");

            // Source: Console.ReadLine -> cleanup command injection
            string cleanDir = Console.ReadLine();
            reportGenerator.CleanupReports(cleanDir, "*.old");

            // Source: Console.ReadLine -> export format command injection
            string expFormat = Console.ReadLine();
            reportGenerator.ExportToFormat("/tmp/report", expFormat, "/tmp/out");

            // FHIR client SSRF chains
            var fhir = new FHIRClient("https://fhir.example.com");

            // Source: Console.ReadLine -> FHIR SSRF
            string fhirPatient = Console.ReadLine();
            fhir.GetPatientResource(fhirPatient);

            // Source: Console.ReadLine -> FHIR search SSRF
            string fhirQuery = Console.ReadLine();
            fhir.SearchPatients(fhirQuery);

            // Source: Console.ReadLine -> FHIR fetch resource SSRF
            string fhirType = Console.ReadLine();
            string fhirId = Console.ReadLine();
            fhir.FetchResource(fhirType, fhirId);
        }
    }
}
