using Dapper;
using LogDetector.Data;
using LogDetector.Models;

namespace LogDetector.Repositories
{
    public class LogBatchRepository : ILogBatchRepository
    {
        private readonly ISqlConnectionFactory _connectionFactory;

        public LogBatchRepository(ISqlConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<IEnumerable<LogBatch>> GetRecentBatchesAsync(int count = 10)
        {
            const string sql = @"
                SELECT TOP (@Count) Id, FileName, TotalLinesParsed, ThreatsDetected,
                       ParseDurationMs, UploadedByEmail, UploadedAt
                FROM LogBatches
                ORDER BY UploadedAt DESC;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.QueryAsync<LogBatch>(sql, new { Count = count });
        }

        public async Task<int> InsertBatchAsync(LogBatch batch)
        {
            const string sql = @"
                INSERT INTO LogBatches (FileName, TotalLinesParsed, ThreatsDetected, ParseDurationMs, UploadedByEmail, UploadedAt)
                VALUES (@FileName, @TotalLinesParsed, @ThreatsDetected, @ParseDurationMs, @UploadedByEmail, @UploadedAt);
                SELECT CAST(SCOPE_IDENTITY() AS int);";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.ExecuteScalarAsync<int>(sql, batch);
        }

        public async Task<bool> DeleteBatchAsync(int id)
        {
            const string deleteThreatsSql = "DELETE FROM ThreatLogs WHERE LogBatchId = @Id;";
            const string deleteBatchSql = "DELETE FROM LogBatches WHERE Id = @Id;";

            using var connection = _connectionFactory.CreateConnection();
            await connection.ExecuteAsync(deleteThreatsSql, new { Id = id });
            var rows = await connection.ExecuteAsync(deleteBatchSql, new { Id = id });
            return rows > 0;
        }

        public async Task<long> GetTotalLinesParsedAsync()
        {
            const string sql = "SELECT ISNULL(SUM(CAST(TotalLinesParsed AS BIGINT)), 0) FROM LogBatches;";
            using var connection = _connectionFactory.CreateConnection();
            return await connection.ExecuteScalarAsync<long>(sql);
        }
    }
}
