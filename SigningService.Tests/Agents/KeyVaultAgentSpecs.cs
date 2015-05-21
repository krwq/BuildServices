using Its.Configuration;
using SigningService.Agents;
using SigningService.Models;
using SigningService.Signers.StrongName;
using SigningService.Tests.Utils;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace SigningService.Tests
{
    public class KeyVaultAgentSpecs
    {
        private readonly ITestOutputHelper output;

        public KeyVaultAgentSpecs(ITestOutputHelper output)
        {
            this.output = output;
        }

        public async Task PrintMetadata(Stream peImage)
        {
            StrongNameSignerHelper sns = new StrongNameSignerHelper(peImage);

            var keyVaultAgent = new KeyVaultAgent();
            PublicKey publicKey = sns.SignaturePublicKeyBlob.PublicKey;
            string keyId = await keyVaultAgent.GetRsaKeyIdAsync(publicKey.Exponent, publicKey.Modulus);
            output.WriteLine("KeyVault KeyId = {0}", keyId ?? "<None>");
            output.WriteLine(sns.ToString());
            peImage.Dispose();
        }

        [Fact]
        public async void Test()
        {
            TestAssembly sha256 = new TestAssembly("TestLib.sha256.dll", null);
            TestAssembly sha384 = new TestAssembly("TestLib.sha384.dll", null);
            TestAssembly ppsha256delay = new TestAssembly("TestLib.delay.dll", null);
            TestAssembly jscript = new TestAssembly("Microsoft.JScript.dll", null);

            Settings.Precedence = new string [] { "test" };

            await PrintMetadata(sha256.GetWritablePEImage());
            await PrintMetadata(sha384.GetWritablePEImage());
            await PrintMetadata(ppsha256delay.GetWritablePEImage());
            await PrintMetadata(jscript.GetWritablePEImage());
        }

        [Fact]
        public void When_digest_has_more_or_less_than_32_bytes_Then_it_fails_with_a_useful_message()
        {
            //var keyVaultAgent = new KeyVaultAgent();

            //var byteCount = Any.Int(0, 1024);
            //if (byteCount == 32) byteCount += Any.Int(1, 1024);

            //Action sign = () => { keyVaultAgent.SignAsync(new byte[byteCount]).Wait(); };

            //sign
            //    .ShouldThrow<ArgumentException>("Because only 32 bit digests are accepted by RSA256")
            //    .WithMessage("The value must have 32 bytes\r\nParameter name: digest");
        }

        [Fact]
        public void When_digest_is_null_Then_it_fails_with_a_useful_message()
        {
            //var keyVaultAgent = new KeyVaultAgent();
            
            //Action sign = () => keyVaultAgent.SignAsync(null).Wait();

            //sign
            //    .ShouldThrow<ArgumentNullException>("Because a digest must be provided.")
            //    .WithMessage("Value cannot be null.\r\nParameter name: digest");
        }
    }
}
