using System.IO.Packaging;
using System.Threading.Tasks;

namespace SigningService
{
    internal interface IPackagePartSigner
    {
        Task<bool> TrySign(PackagePart packagePart);
    }
}