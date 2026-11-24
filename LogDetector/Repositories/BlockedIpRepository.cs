using Dapper;
using LogDetector.Data;
using LogDetector.Models;

namespace LogDetector.Repositories
{
    public class BlockedIpRepository : IBlockedIpRepository
    {
        private readonly ISqlConnectionFactory _connectionFactory;

        public BlockedIpRepository(ISqlConnectionFactory connectionFactory)
        {
            _connectionFactory = connectionFactory;
        }

        public async Task<IEnumerable<BlockedIp>> GetAllBlockedIpsAsync()
        {
            const string sql = @"
                SELECT Id, IpAddress, Reason, BlockedBy, BlockedAt
                FROM BlockedIps
                ORDER BY BlockedAt DESC;";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.QueryAsync<BlockedIp>(sql);
        }

        public async Task<int> BlockIpAsync(BlockedIp item)
        {
            const string sql = @"
                IF NOT EXISTS (SELECT 1 FROM BlockedIps WHERE IpAddress = @IpAddress)
                BEGIN
                    INSERT INTO BlockedIps (IpAddress, Reason, BlockedBy, BlockedAt)
                    VALUES (@IpAddress, @Reason, @BlockedBy, @BlockedAt);
                    SELECT CAST(SCOPE_IDENTITY() AS int);
                END
                ELSE
                BEGIN
                    SELECT Id FROM BlockedIps WHERE IpAddress = @IpAddress;
                END";

            using var connection = _connectionFactory.CreateConnection();
            return await connection.ExecuteScalarAsync<int>(sql, item);
        }

        public async Task<bool> UnblockIpAsync(int id)
        {
            const string sql = "DELETE FROM BlockedIps WHERE Id = @Id;";
            using var connection = _connectionFactory.CreateConnection();
            var rows = await connection.ExecuteAsync(sql, new { Id = id });
            return rows > 0;
        }
    }
}
