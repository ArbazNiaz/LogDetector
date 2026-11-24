using LogDetector.Models;

namespace LogDetector.Repositories
{
    public interface ILogBatchRepository
    {
        Task<IEnumerable<LogBatch>> GetRecentBatchesAsync(int count = 10);
        Task<int> InsertBatchAsync(LogBatch batch);
        Task<bool> DeleteBatchAsync(int id);
        Task<long> GetTotalLinesParsedAsync();
    }
}
