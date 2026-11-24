using Dapper;
using LogDetector.Data;
using LogDetector.Models;

namespace LogDetector.Repositories
{
    public class WorkerTelemetryRepository : IWorkerTelemetryRepository
    {
        private readonly ISqlConnectionFactory _connectionFactory;

        public WorkerTelemetryRepository(ISqlConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<IEnumerable<WorkerTelemetryLog>> GetRecentTelemetryAsync(int count = 15)
        {
            const string sql = @"
                SELECT TOP (@Count) Id, EventLevel, Message, LinesProcessed, ElapsedMs, CreatedAt
                FROM WorkerTelemetryLogs
                ORDER BY CreatedAt DESC, Id DESC;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.QueryAsync<WorkerTelemetryLog>(sql, new { Count = count });
        }

        public async Task LogTelemetryEventAsync(WorkerTelemetryLog entry)
        {
            const string sql = @"
                INSERT INTO WorkerTelemetryLogs (EventLevel, Message, LinesProcessed, ElapsedMs, CreatedAt)
                VALUES (@EventLevel, @Message, @LinesProcessed, @ElapsedMs, @CreatedAt);";

            using var connection = _connectionFactory.CreateConnection();
            await connection.ExecuteAsync(sql, entry);
        }

        public async Task<double> GetAverageThroughputAsync()
        {
            const string sql = @"
                SELECT ISNULL(AVG(CASE WHEN ParseDurationMs > 0
                    THEN (TotalLinesParsed * 1000.0) / ParseDurationMs
                    ELSE TotalLinesParsed * 1000.0 END), 0)
                FROM LogBatches;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.ExecuteScalarAsync<double>(sql);
        }
    }
}
