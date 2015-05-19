using System.Reflection;
using System.Threading.Tasks;

namespace SigningService.Agents
{
    public interface IKeyVaultAgent
    {
        Task<byte[]> SignAsync(string keyId, byte[] digest);
        Task<bool> CanSignAsync(PublicKey publicKey, AssemblyHashAlgorithm hashAlgorithm);
        Task<string> GetKeyIdAsync(PublicKey publicKey);
    }
}