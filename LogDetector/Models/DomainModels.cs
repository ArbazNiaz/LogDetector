using System.ComponentModel.DataAnnotations;

namespace LogDetector.Models
{
    public class LogBatch
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string FileName { get; set; } = string.Empty;

        public int TotalLinesParsed { get; set; }
        public int ThreatsDetected { get; set; }
        public double ParseDurationMs { get; set; }

        [MaxLength(150)]
        public string UploadedByEmail { get; set; } = string.Empty;

        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    }

    public class ThreatLog
    {
        public int Id { get; set; }
        public int LogBatchId { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [Required]
        [MaxLength(45)]
        public string SourceIp { get; set; } = string.Empty;

        [Required]
        [MaxLength(10)]
        public string HttpMethod { get; set; } = "GET";

        [Required]
        [MaxLength(500)]
        public string TargetUri { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string ThreatType { get; set; } = string.Empty;

        [Required]
        [MaxLength(20)]
        public string Severity { get; set; } = "HIGH";

        public bool IsResolved { get; set; } = false;
    }

    public class BlockedIp
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(45)]
        public string IpAddress { get; set; } = string.Empty;

        [Required]
        [MaxLength(250)]
        public string Reason { get; set; } = string.Empty;

        [MaxLength(150)]
        public string BlockedBy { get; set; } = string.Empty;

        public DateTime BlockedAt { get; set; } = DateTime.UtcNow;
    }

    public class WorkerTelemetryLog
    {
        public int Id { get; set; }

        [MaxLength(15)]
        public string EventLevel { get; set; } = "INF";

        [Required]
        [MaxLength(500)]
        public string Message { get; set; } = string.Empty;

        public int LinesProcessed { get; set; }
        public double ElapsedMs { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class ThreatBreakdownDto
    {
        public string ThreatType { get; set; } = string.Empty;
        public int Count { get; set; }
    }
}
