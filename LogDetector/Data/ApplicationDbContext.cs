using LogDetector.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LogDetector.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : IdentityDbContext<ApplicationUser>(options)
    {
        public DbSet<LogBatch> LogBatches { get; set; }
        public DbSet<ThreatLog> ThreatLogs { get; set; }
        public DbSet<BlockedIp> BlockedIps { get; set; }
        public DbSet<WorkerTelemetryLog> WorkerTelemetryLogs { get; set; }
    }
}
