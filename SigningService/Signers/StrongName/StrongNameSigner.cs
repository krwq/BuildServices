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

        public async Task<bool> TrySignAsync(Stream peStream)
        {
            StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(peStream);
            if (strongNameSigner.CanSign())
            {
                string keyId = await GetKeyVaultId(strongNameSigner);
                if (keyId == null)
                {
                    return false;
                }

                byte[] hash = strongNameSigner.ComputeHash();
                byte[] signature = await _keyVaultAgent.SignAsync(keyId, hash);
                strongNameSigner.EmbedStrongNameSignature(signature);
                return true;
            }

            return false;
        }

        public async Task<bool> CanSignAsync(Stream peStream)
        {
            StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(peStream);
            if (!strongNameSigner.CanSign())
            {
                return false;
            }
            
            string keyId = await GetKeyVaultId(strongNameSigner);
            return keyId != null;
        }

        /// <summary>
        /// Gets KeyVault KeyId related to signature public key
        /// </summary>
        internal async Task<string> GetKeyVaultId(StrongNameSignerHelper strongNameSigner)
        {
            return await _keyVaultAgent.GetRsaKeyIdAsync(strongNameSigner.PublicKeyBlob.PublicKey.Exponent, strongNameSigner.PublicKeyBlob.PublicKey.Modulus);
        }
    }
}