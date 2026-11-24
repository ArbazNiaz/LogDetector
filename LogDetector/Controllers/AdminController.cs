using System.Diagnostics;
using System.Text;
using LogDetector.Models;
using LogDetector.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace LogDetector.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogBatchRepository _batchRepo;
        private readonly IThreatLogRepository _threatRepo;
        private readonly IBlockedIpRepository _blockedIpRepo;
        private readonly IWorkerTelemetryRepository _telemetryRepo;

        public AdminController(
            UserManager<ApplicationUser> userManager,
            ILogBatchRepository batchRepo,
            IThreatLogRepository threatRepo,
            IBlockedIpRepository blockedIpRepo,
            IWorkerTelemetryRepository telemetryRepo)
        {
            _userManager = userManager;
            _batchRepo = batchRepo;
            _threatRepo = threatRepo;
            _blockedIpRepo = blockedIpRepo;
            _telemetryRepo = telemetryRepo;
        }

        // Full Admin Panel View
        [HttpGet]
        public async Task<IActionResult> Dashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            ViewBag.FullName = user?.FullName ?? User.Identity?.Name ?? "Security Admin";
            return View();
        }

        // Called via $.ajax({ url: '/Admin/UploadLogFile', type: 'POST', data: formData, ... })
        [HttpPost]
        public async Task<IActionResult> UploadLogFile(IFormFile? logFile)
        {
            if (logFile == null || logFile.Length == 0)
            {
                return BadRequest(new { success = false, message = "Please select a valid .log or .txt file." });
            }

            string uploader = User.Identity?.Name ?? "admin@logdetective.local";
            using var stream = logFile.OpenReadStream();
            var batch = await ParseAndStoreStreamAsync(stream, logFile.FileName, uploader);

            return Json(new
            {
                success = true,
                message = $"Parsed {batch.TotalLinesParsed:N0} lines in {batch.ParseDurationMs}ms ({batch.ThreatsDetected} threats detected).",
                batch
            });
        }

        // Called via $.post('/Admin/RunSampleScan')
        [HttpPost]
        public async Task<IActionResult> RunSampleScan()
        {
            string uploader = User.Identity?.Name ?? "admin@logdetective.local";
            using var sampleStream = GenerateSampleLogStream();
            var batch = await ParseAndStoreStreamAsync(sampleStream, $"server_access_{DateTime.UtcNow:HHmmss}.log", uploader);

            return Json(new
            {
                success = true,
                message = $"Server log scan complete: {batch.TotalLinesParsed} lines parsed, {batch.ThreatsDetected} threats stored via Dapper.",
                batch
            });
        }

        // Called via $.post('/Admin/ResolveThreat', { id })
        [HttpPost]
        public async Task<IActionResult> ResolveThreat(int id)
        {
            bool updated = await _threatRepo.MarkAsResolvedAsync(id);
            return Json(new { success = updated });
        }

        // Called via $.post('/Admin/BlockIp', { ipAddress, reason })
        [HttpPost]
        public async Task<IActionResult> BlockIp(string ipAddress, string reason)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                return BadRequest(new { success = false, message = "IP Address is required." });
            }

            var item = new BlockedIp
            {
                IpAddress = ipAddress.Trim(),
                Reason = string.IsNullOrWhiteSpace(reason) ? "Flagged malicious activity" : reason.Trim(),
                BlockedBy = User.Identity?.Name ?? "Admin",
                BlockedAt = DateTime.UtcNow
            };

            int id = await _blockedIpRepo.BlockIpAsync(item);
            return Json(new { success = true, id });
        }

        // Called via $.post('/Admin/UnblockIp', { id })
        [HttpPost]
        public async Task<IActionResult> UnblockIp(int id)
        {
            bool removed = await _blockedIpRepo.UnblockIpAsync(id);
            return Json(new { success = removed });
        }

        // Called via $.post('/Admin/DeleteBatch', { id })
        [HttpPost]
        public async Task<IActionResult> DeleteBatch(int id)
        {
            bool deleted = await _batchRepo.DeleteBatchAsync(id);
            return Json(new { success = deleted });
        }

        private async Task<LogBatch> ParseAndStoreStreamAsync(Stream stream, string fileName, string uploadedByEmail)
        {
            var stopwatch = Stopwatch.StartNew();
            int totalLines = 0;
            var detectedThreats = new List<ThreatLog>();

            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                totalLines++;

                var threat = InspectLineWithSpan(line.AsSpan().Trim());
                if (threat != null)
                {
                    detectedThreats.Add(threat);
                }
            }

            stopwatch.Stop();
            double elapsedMs = Math.Round(Math.Max(stopwatch.Elapsed.TotalMilliseconds, 0.5), 2);

            var batch = new LogBatch
            {
                FileName = fileName,
                TotalLinesParsed = totalLines,
                ThreatsDetected = detectedThreats.Count,
                ParseDurationMs = elapsedMs,
                UploadedByEmail = uploadedByEmail,
                UploadedAt = DateTime.UtcNow
            };

            int batchId = await _batchRepo.InsertBatchAsync(batch);
            batch.Id = batchId;

            if (detectedThreats.Count > 0)
            {
                foreach (var t in detectedThreats)
                {
                    t.LogBatchId = batchId;
                }
                await _threatRepo.BulkInsertThreatsAsync(detectedThreats);
            }

            await _telemetryRepo.LogTelemetryEventAsync(new WorkerTelemetryLog
            {
                EventLevel = detectedThreats.Count > 0 ? "WRN" : "INF",
                Message = $"Server Parser processed '{fileName}' ({totalLines:N0} lines) via ReadOnlySpan<char> in {elapsedMs}ms — {detectedThreats.Count} threats flagged.",
                LinesProcessed = totalLines,
                ElapsedMs = elapsedMs,
                CreatedAt = DateTime.UtcNow
            });

            return batch;
        }

        private static ThreatLog? InspectLineWithSpan(ReadOnlySpan<char> lineSpan)
        {
            int firstSpace = lineSpan.IndexOf(' ');
            ReadOnlySpan<char> ipSpan = firstSpace > 0 ? lineSpan[..firstSpace] : "192.168.1.100".AsSpan();

            string method = "GET";
            string targetUri = lineSpan.Length > 120 ? lineSpan[..120].ToString() : lineSpan.ToString();

            int firstQuote = lineSpan.IndexOf('"');
            if (firstQuote >= 0 && firstQuote + 1 < lineSpan.Length)
            {
                var afterQuote = lineSpan[(firstQuote + 1)..];
                int methodSpace = afterQuote.IndexOf(' ');
                if (methodSpace > 0)
                {
                    method = afterQuote[..methodSpace].ToString();
                    var uriStart = afterQuote[(methodSpace + 1)..];
                    int uriEnd = uriStart.IndexOf(' ');
                    if (uriEnd < 0) uriEnd = uriStart.IndexOf('"');
                    if (uriEnd > 0)
                    {
                        targetUri = uriStart[..uriEnd].ToString();
                    }
                }
            }

            if (ContainsOrdinalIgnoreCase(lineSpan, "UNION SELECT") ||
                ContainsOrdinalIgnoreCase(lineSpan, "' OR '1'='1") ||
                ContainsOrdinalIgnoreCase(lineSpan, "OR 1=1") ||
                ContainsOrdinalIgnoreCase(lineSpan, "DROP TABLE"))
            {
                return BuildThreat(ipSpan, method, targetUri, "SQL Injection", "HIGH");
            }

            if (ContainsOrdinalIgnoreCase(lineSpan, "<script") ||
                ContainsOrdinalIgnoreCase(lineSpan, "onerror=") ||
                ContainsOrdinalIgnoreCase(lineSpan, "onload=") ||
                ContainsOrdinalIgnoreCase(lineSpan, "<svg"))
            {
                return BuildThreat(ipSpan, method, targetUri, "Cross-Site Scripting", "HIGH");
            }

            if (ContainsOrdinalIgnoreCase(lineSpan, "../") ||
                ContainsOrdinalIgnoreCase(lineSpan, "/etc/passwd") ||
                ContainsOrdinalIgnoreCase(lineSpan, "win.ini"))
            {
                return BuildThreat(ipSpan, method, targetUri, "Directory Traversal", "HIGH");
            }

            if ((ContainsOrdinalIgnoreCase(lineSpan, "/login") || ContainsOrdinalIgnoreCase(lineSpan, "/auth")) &&
                (ContainsOrdinalIgnoreCase(lineSpan, " 401 ") || ContainsOrdinalIgnoreCase(lineSpan, " 403 ")))
            {
                return BuildThreat(ipSpan, method, targetUri, "Brute-Force (401)", "MEDIUM");
            }

            return null;
        }

        private static bool ContainsOrdinalIgnoreCase(ReadOnlySpan<char> span, string pattern)
            => span.IndexOf(pattern.AsSpan(), StringComparison.OrdinalIgnoreCase) >= 0;

        private static ThreatLog BuildThreat(ReadOnlySpan<char> ipSpan, string method, string uri, string type, string severity)
        {
            return new ThreatLog
            {
                Timestamp = DateTime.UtcNow,
                SourceIp = ipSpan.Length <= 45 ? ipSpan.ToString() : "0.0.0.0",
                HttpMethod = method.Length <= 10 ? method : "GET",
                TargetUri = uri.Length <= 500 ? uri : uri[..500],
                ThreatType = type,
                Severity = severity,
                IsResolved = false
            };
        }

        private static Stream GenerateSampleLogStream()
        {
            var sb = new StringBuilder();
            sb.AppendLine("192.168.1.10 - - [24/Nov/2026:19:45:01 +0500] \"GET /index.html HTTP/1.1\" 200 2048");
            sb.AppendLine("192.168.1.45 - - [24/Nov/2026:19:45:02 +0500] \"GET /products?cat=1 UNION SELECT null,version()-- HTTP/1.1\" 500 512");
            sb.AppendLine("10.0.0.88 - - [24/Nov/2026:19:45:03 +0500] \"POST /auth/login HTTP/1.1\" 401 128");
            sb.AppendLine("10.0.0.88 - - [24/Nov/2026:19:45:04 +0500] \"POST /auth/login HTTP/1.1\" 401 128");
            sb.AppendLine("172.16.0.12 - - [24/Nov/2026:19:45:05 +0500] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 1024");
            sb.AppendLine("203.0.113.77 - - [24/Nov/2026:19:45:06 +0500] \"GET /download?file=../../../../etc/passwd HTTP/1.1\" 403 256");
            sb.AppendLine("192.168.1.22 - - [24/Nov/2026:19:45:07 +0500] \"GET /api/status HTTP/1.1\" 200 64");
            sb.AppendLine("45.33.32.156 - - [24/Nov/2026:19:45:08 +0500] \"GET /api/v1/users?id=' OR '1'='1 HTTP/1.1\" 500 310");
            return new MemoryStream(Encoding.UTF8.GetBytes(sb.ToString()));
        }
    }
}
