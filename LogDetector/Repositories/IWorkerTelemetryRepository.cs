using LogDetector.Models;

namespace LogDetector.Repositories
{
    public interface IWorkerTelemetryRepository
    {
        Task<IEnumerable<WorkerTelemetryLog>> GetRecentTelemetryAsync(int count = 15);
        Task LogTelemetryEventAsync(WorkerTelemetryLog entry);
        Task<double> GetAverageThroughputAsync();
    }
}
