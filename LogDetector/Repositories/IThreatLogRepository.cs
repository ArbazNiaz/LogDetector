using LogDetector.Models;

namespace LogDetector.Repositories
{
    public interface IThreatLogRepository
    {
        Task<IEnumerable<ThreatLog>> GetThreatsAsync(string? severity = null, string? search = null);
        Task BulkInsertThreatsAsync(IEnumerable<ThreatLog> threats);
        Task<bool> MarkAsResolvedAsync(int id);
        Task<IEnumerable<ThreatBreakdownDto>> GetThreatBreakdownAsync();
        Task<int> GetActiveThreatCountAsync();
    }
}
