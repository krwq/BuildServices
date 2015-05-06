using SigningService.Agents;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;

namespace SigningService
{
    public class StrongNameSignerService : IPackagePartSigner
    {
        private IKeyVaultAgent _keyVaultAgent;

        public StrongNameSignerService(IKeyVaultAgent keyVaultAgent)
        {
            _keyVaultAgent = keyVaultAgent;
        }

        public Task<bool> TrySignAsync(Stream peStream)
        {
            StrongNameSigner strongNameSigner = new StrongNameSigner(_keyVaultAgent, peStream, SHA256.Create());
            return strongNameSigner.TrySignAsync();
        }

        public bool CanSign(Stream peStream)
        {
            StrongNameSigner strongNameSigner = new StrongNameSigner(_keyVaultAgent, peStream, SHA256.Create());
            return strongNameSigner.CanSign();
        }
    }
}