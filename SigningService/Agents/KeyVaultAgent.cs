using System;
using System.Text;
using System.Threading.Tasks;
using Its.Configuration;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using SigningService.Services.Configuration;
using System.Reflection;
using Microsoft.Azure.KeyVault.WebKey;
using System.Collections.Generic;

namespace SigningService.Agents
{
    public class KeyVaultAgent : IKeyVaultAgent
    {
        public async Task<byte[]> Sign(byte[] digest)
        {
            if (digest == null) throw new ArgumentNullException("digest");

            if (digest.Length != 32) throw new ArgumentException("The value must have 32 bytes", "digest");

            var client = new KeyVaultClient(GetAccessToken);

            var keyVaultSettings = Settings.Get<KeyVaultSettings>();

            var signResult =
                await client.SignAsync(
                        keyVaultSettings.KeyId,
                        keyVaultSettings.Algorithm,
                        digest);

            byte[] ret = signResult.Result;
            ByteArrayHelpers.ReverseInplace(ret);
            return ret;
        }

        public async Task<IEnumerable<JsonWebKey>> GetKeys()
        {
            var client = new KeyVaultClient(GetAccessToken);
            var keyVaultSettings = Settings.Get<KeyVaultSettings>();

            //Task<JsonWebKey> jsonWebKeyLambda =

            var keys = await client.GetKeysAsync(keyVaultSettings.Vault);

            List<JsonWebKey> ret = new List<JsonWebKey>();

            foreach (KeyItem k in keys.Value)
            {
                KeyBundle keybundle = await client.GetKeyAsync(k.Kid);
                ret.Add(keybundle.Key);
            }

            return ret;
        }

        // https://samlman.wordpress.com/2015/05/01/fun-with-azure-key-vault-services/
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var identitySettings = Settings.Get<ServiceIdentitySettings>();

            var clientId = identitySettings.ClientId;

            var clientSecret = identitySettings.ClientSecret;

            var context = new AuthenticationContext(authority, null);

            var credential = new ClientCredential(clientId, clientSecret);
            
            var result = await context.AcquireTokenAsync(resource, credential);
            
            return result.AccessToken;
        }

        public bool CanSign(byte[] publicKey, AssemblyHashAlgorithm hashAlgorithm)
        {
            if (!SupportsHashAlgorithm(hashAlgorithm))
            {
                return false;
            }

            throw new NotImplementedException();
        }

        private bool SupportsHashAlgorithm(AssemblyHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case AssemblyHashAlgorithm.Sha256:
                case AssemblyHashAlgorithm.Sha384:
                case AssemblyHashAlgorithm.Sha512:
                    return true;
            }

            return false;
        }
    }
}