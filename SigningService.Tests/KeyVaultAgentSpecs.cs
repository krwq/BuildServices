using FluentAssertions;
using Its.Configuration;
using Its.Log.Instrumentation;
using Microsoft.Its.Recipes;
using Moq;
using SigningService.Agents;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Microsoft.Azure.KeyVault.WebKey;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;

namespace SigningService.Tests
{
    public class KeyVaultAgentSpecs
    {
        private readonly ITestOutputHelper output;

        public KeyVaultAgentSpecs(ITestOutputHelper output)
        {
            this.output = output;
        }
        public static IEnumerable<object[]> GetTestAssemblies()
        {
            return TestAssembly.GetTestAssemblies();
        }

        public void WriteLine(string format, params object[] args)
        {
            output.WriteLine(format, args);
        }

        public string ByteArrayToString(byte[] t)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(string.Format("{0:x2}", t[i]));
            }
            return sb.ToString();
        }

        public string ByteArrayToReverseString(byte[] t)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = t.Length - 1; i >= 0; i--)
            {
                sb.Append(string.Format("{0:x2}", t[i]));
            }
            return sb.ToString();
        }

        public async Task PrintMetadata(IKeyVaultAgent keyVault, Stream peImage)
        {
            StrongNameSigner sns = new StrongNameSigner(keyVault, peImage);

            sns.SetStrongNameSignedFlag();
            WriteLine("SNS dir size = {0}", sns.ExtractStrongNameSignature().Length);
            WriteLine("HashAlgorithm = {0}", sns.HashAlgorithm);
            WriteLine("Public Key Token = {0}", sns.PublicKeyToken);
            WriteLine("Public Key Modulus = {0}", ByteArrayToString(sns.PublicKey.Modulus));
            WriteLine("Public Key Exponent = {0}", sns.PublicKey.Exponent);
            string keyId = await sns.GetKeyVaultKeyIdAsync();
            WriteLine("KeyVault storing key = {0}", keyId != null ? keyId : "<None>");

            peImage.Dispose();
        }

        [Fact]
        public async void Test()
        {
            Log.EntryPosted += (sender, e) => Console.WriteLine(e.LogEntry.ToString());

            TestAssembly sha256 = new TestAssembly("TestLib.sha256.dll", null);
            TestAssembly sha384 = new TestAssembly("TestLib.sha384.dll", null);
            TestAssembly ppsha256delay = new TestAssembly("TestLib.delay.dll", null);
            TestAssembly jscript = new TestAssembly("Microsoft.JScript.dll", null);

            Settings.Precedence = new string [] { "test" };
            var keyVaultAgent = new KeyVaultAgent();

            await PrintMetadata(keyVaultAgent, sha256.GetWritablePEImage());
            await PrintMetadata(keyVaultAgent, sha384.GetWritablePEImage());
            await PrintMetadata(keyVaultAgent, ppsha256delay.GetWritablePEImage());
            await PrintMetadata(keyVaultAgent, jscript.GetWritablePEImage());
        }

        [Theory, MemberData("GetTestAssemblies")]
        public async void RealSignTest(TestAssembly testAssembly)
        {
            Settings.Precedence = new string [] { "test" };
            var keyVaultAgent = new KeyVaultAgent();

            byte[] expectedSignature = Any.Sequence(i => Any.Byte(), 256).ToArray();

            using (Stream outputPeImage = testAssembly.GetWritablePEImage())
            {
                StrongNameSigner strongNameSigner = new StrongNameSigner(keyVaultAgent, outputPeImage);
                bool result = await strongNameSigner.TrySignAsync();
                result.Should().BeTrue();
                //strongNameSigner.ComputeHash().Should().BeEquivalentTo(testAssembly.StrongNameSignatureHash);
                //strongNameSigner.ExtractStrongNameSignature().Should().BeEquivalentTo(expectedSignature);
            }
        }

        [Theory, MemberData("GetTestAssemblies")]
        public async void When_digest_has_32_bytes_the_response_has_256_bytes(TestAssembly testAssembly)
        {
            var keyVaultAgentMock = new Mock<IKeyVaultAgent>(MockBehavior.Strict);

            string keyId = Any.String(1, 10);
            byte[] expectedSignature = Any.Sequence(i => Any.Byte(), 256).ToArray();

            var keyIdExpr = It.Is<string>(s => !string.IsNullOrEmpty(s));
            var digestExpr = It.Is<byte[]>(d => d.SequenceEqual(testAssembly.StrongNameSignatureHash));

            keyVaultAgentMock
                .Setup(k => k.SignAsync(keyIdExpr, digestExpr))
                .Returns(Task.FromResult(expectedSignature));
            keyVaultAgentMock
                .Setup(k => k.GetKeyIdAsync(It.IsAny<PublicKey>()))
                .Returns(Task.FromResult(keyId));
            keyVaultAgentMock
                .Setup(k => k.CanSignAsync(It.IsAny<PublicKey>(), It.IsAny<AssemblyHashAlgorithm>()))
                .Returns(Task.FromResult(true));

            using (Stream outputPeImage = testAssembly.GetWritablePEImage())
            {
                StrongNameSigner strongNameSigner = new StrongNameSigner(keyVaultAgentMock.Object, outputPeImage);
                bool result = await strongNameSigner.TrySignAsync();
                result.Should().BeTrue();
                strongNameSigner.ComputeHash().Should().BeEquivalentTo(testAssembly.StrongNameSignatureHash);
                strongNameSigner.ExtractStrongNameSignature().Should().BeEquivalentTo(expectedSignature);
            }

            keyVaultAgentMock.Verify(k => k.SignAsync(keyIdExpr, digestExpr), Times.Once);
        }

        [Fact]
        public async void When_digest_has_more_or_less_than_32_bytes_Then_it_fails_with_a_useful_message()
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
        public async void When_digest_is_null_Then_it_fails_with_a_useful_message()
        {
            //var keyVaultAgent = new KeyVaultAgent();
            
            //Action sign = () => keyVaultAgent.SignAsync(null).Wait();

            //sign
            //    .ShouldThrow<ArgumentNullException>("Because a digest must be provided.")
            //    .WithMessage("Value cannot be null.\r\nParameter name: digest");
        }
    }
}
