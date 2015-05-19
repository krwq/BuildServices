using SigningService.Agents;
using System.IO;
using System.Threading.Tasks;

namespace SigningService.Signers.StrongName
{
    public class StrongNameSigner : IPackagePartSigner
    {
        private IKeyVaultAgent _keyVaultAgent;

        public StrongNameSigner(IKeyVaultAgent keyVaultAgent)
        {
            _keyVaultAgent = keyVaultAgent;
        }

        public Task<bool> TrySignAsync(Stream peStream)
        {
            StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(_keyVaultAgent, peStream);
            return strongNameSigner.TrySignAsync();
        }

        public Task<bool> CanSignAsync(Stream peStream)
        {
            StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(_keyVaultAgent, peStream);
            return strongNameSigner.CanSignAsync();
        }
    }
}