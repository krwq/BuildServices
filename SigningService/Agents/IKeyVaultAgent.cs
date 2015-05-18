using System.Reflection;
using System.Threading.Tasks;

namespace SigningService.Agents
{
    public interface IKeyVaultAgent
    {
        Task<byte[]> Sign(byte[] digest);
        bool CanSign(byte[] publicKey, AssemblyHashAlgorithm hashAlgorithm);
    }
}