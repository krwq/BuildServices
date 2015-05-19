using System.IO;
using System.IO.Packaging;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SigningService
{
    internal interface IPackagePartSigner
    {
        Task<bool> TrySignAsync(Stream peStream);
        Task<bool> CanSignAsync(Stream peStream);
    }
}