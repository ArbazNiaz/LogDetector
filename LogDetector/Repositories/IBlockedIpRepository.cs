using LogDetector.Models;

namespace LogDetector.Repositories
{
    public interface IBlockedIpRepository
    {
        Task<IEnumerable<BlockedIp>> GetAllBlockedIpsAsync();
        Task<int> BlockIpAsync(BlockedIp item);
        Task<bool> UnblockIpAsync(int id);
    }
}
