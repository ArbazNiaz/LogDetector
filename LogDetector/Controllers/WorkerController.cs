using LogDetector.Models;
using LogDetector.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace LogDetector.Controllers
{
    [Authorize(Roles = "Admin,Viewer")]
    public class MonitorController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogBatchRepository _batchRepo;
        private readonly IThreatLogRepository _threatRepo;
        private readonly IBlockedIpRepository _blockedIpRepo;
        private readonly IWorkerTelemetryRepository _telemetryRepo;

        public MonitorController(
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

        // Read-Only Server Analysis & Monitor View
        [HttpGet]
        public async Task<IActionResult> Dashboard()
        {
            var user = await _userManager.GetUserAsync(User);
            ViewBag.FullName = user?.FullName ?? User.Identity?.Name ?? "Log Viewer";
            return View();
        }

        // Shared $.get('/Monitor/GetAnalysisData') endpoint used by both Admin Panel and Monitor View
        [HttpGet]
        public async Task<IActionResult> GetAnalysisData(string? severity = "ALL", string? search = "")
        {
            var totalLines = await _batchRepo.GetTotalLinesParsedAsync();
            var activeThreats = await _threatRepo.GetActiveThreatCountAsync();
            var avgThroughput = await _telemetryRepo.GetAverageThroughputAsync();
            var breakdown = await _threatRepo.GetThreatBreakdownAsync();
            var threats = await _threatRepo.GetThreatsAsync(severity, search);
            var batches = await _batchRepo.GetRecentBatchesAsync(8);
            var blockedIps = await _blockedIpRepo.GetAllBlockedIpsAsync();
            var telemetry = await _telemetryRepo.GetRecentTelemetryAsync(15);

            return Json(new
            {
                totalLines,
                activeThreats,
                avgThroughput = Math.Round(avgThroughput, 0),
                breakdown,
                threats,
                batches,
                blockedIps,
                telemetry
            });
        }
    }
}
