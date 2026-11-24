using Dapper;
using LogDetector.Data;
using LogDetector.Models;

namespace LogDetector.Repositories
{
    public class ThreatLogRepository : IThreatLogRepository
    {
        private readonly ISqlConnectionFactory _connectionFactory;

        public ThreatLogRepository(ISqlConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<IEnumerable<ThreatLog>> GetThreatsAsync(string? severity = null, string? search = null)
        {
            var sql = @"
                SELECT TOP 50 Id, LogBatchId, Timestamp, SourceIp, HttpMethod,
                       TargetUri, ThreatType, Severity, IsResolved
                FROM ThreatLogs
                WHERE 1 = 1";

            var parameters = new DynamicParameters();

            if (!string.IsNullOrWhiteSpace(severity) && severity != "ALL")
            {
                sql += " AND Severity = @Severity";
                parameters.Add("Severity", severity);
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                sql += " AND (SourceIp LIKE @Search OR TargetUri LIKE @Search OR ThreatType LIKE @Search)";
                parameters.Add("Search", $"%{search.Trim()}%");
            }

            sql += " ORDER BY Timestamp DESC, Id DESC;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.QueryAsync<ThreatLog>(sql, parameters);
        }

        public async Task BulkInsertThreatsAsync(IEnumerable<ThreatLog> threats)
        {
            var list = threats.ToList();
            if (list.Count == 0) return;

            const string sql = @"
                INSERT INTO ThreatLogs (LogBatchId, Timestamp, SourceIp, HttpMethod, TargetUri, ThreatType, Severity, IsResolved)
                VALUES (@LogBatchId, @Timestamp, @SourceIp, @HttpMethod, @TargetUri, @ThreatType, @Severity, @IsResolved);";

            using var connection = _connectionFactory.CreateConnection();
            await connection.ExecuteAsync(sql, list);
        }

        public async Task<bool> MarkAsResolvedAsync(int id)
        {
            const string sql = "UPDATE ThreatLogs SET IsResolved = 1 WHERE Id = @Id;";
            using var connection = _connectionFactory.CreateConnection();
            var rows = await connection.ExecuteAsync(sql, new { Id = id });
            return rows > 0;
        }

        public async Task<IEnumerable<ThreatBreakdownDto>> GetThreatBreakdownAsync()
        {
            const string sql = @"
                SELECT ThreatType, COUNT(*) AS Count
                FROM ThreatLogs
                GROUP BY ThreatType
                ORDER BY Count DESC;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.QueryAsync<ThreatBreakdownDto>(sql);
        }

        public async Task<int> GetActiveThreatCountAsync()
        {
            const string sql = "SELECT COUNT(*) FROM ThreatLogs WHERE IsResolved = 0;";
            using var connection = _connectionFactory.CreateConnection();
            return await connection.ExecuteScalarAsync<int>(sql);
        }
    }
}
