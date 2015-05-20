using Its.Configuration;
using SigningService.Agents;
using SigningService.Signers.StrongName;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Moq;
using Microsoft.Its.Recipes;
using SigningService.Tests.Utils;

namespace SigningService.Tests
{
    public class StrongNameSignerHelperSpecs : TestData
    {
        private readonly ITestOutputHelper output;

        public StrongNameSignerHelperSpecs(ITestOutputHelper output)
        {
            this.output = output;
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

        [Theory, MemberData("TestAssembliesWithKnownHash")]
        public async void Mock_sign_test(TestAssembly testAssembly)
        {
            output.WriteLine("Assembly: {0}", testAssembly.ResourceName);
            var keyVaultAgentMock = new Mock<IKeyVaultAgent>(MockBehavior.Strict);

            string keyId = Any.String(4, 10, "uvwxyz");
            byte[] expectedSignature = Any.Sequence(i => Any.Byte(), 256).ToArray();

            keyVaultAgentMock
                .Setup(k => k.SignAsync(
                //It.Is<string>(s => s.Equals(keyId)), It.Is<byte[]>(d => d.SequenceEqual(testAssembly.StrongNameSignatureHash))
                It.IsAny<string>(), It.IsAny<byte[]>()
                ))
                .Returns(Task.FromResult(expectedSignature));
            keyVaultAgentMock
                .Setup(k => k.GetRsaKeyIdAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .Returns(Task.FromResult(keyId));

            using (Stream outputPeImage = testAssembly.GetWritablePEImage())
            {
                StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(keyVaultAgentMock.Object, outputPeImage);
                strongNameSigner.RemoveSignature();
                bool result = await strongNameSigner.TrySignAsync();
                result.Should().BeTrue();
                output.WriteLine("Signature dir size: {0}", strongNameSigner.ExtractStrongNameSignature().Length);
                output.WriteLine("Hash Algorithm: {0}", strongNameSigner.HashAlgorithm);
                byte[] hash = strongNameSigner.ComputeHash();
                byte[] expHash = testAssembly.StrongNameSignatureHash;
                output.WriteLine("Calculated hash size: {0}", hash.Length);
                output.WriteLine("  Expected hash size: {0}", expHash.Length);
                output.WriteLine("Calculated hash: {0}", ByteArrayToString(hash));
                output.WriteLine("  Expected hash: {0}", ByteArrayToString(expHash));
                output.WriteLine("PK: {0}", ByteArrayToString(strongNameSigner.PublicKeyBlob));
                strongNameSigner.ComputeHash().Should().BeEquivalentTo(expHash);
                strongNameSigner.ExtractStrongNameSignature().Should().BeEquivalentTo(expectedSignature);
            }

            keyVaultAgentMock.Verify(k => k.SignAsync(It.IsAny<string>(), It.IsAny<byte[]>()), Times.Once);
            keyVaultAgentMock.Verify(k => k.GetRsaKeyIdAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Once);
        }

        //[Theory, MemberData("AllTestAssemblies")]
        //public async void DesignAssemblies(TestAssembly testAssembly)
        //{
        //    using (Stream outputPeImage = testAssembly.GetWritablePEImage())
        //    {
        //        StrongNameSignerHelper strongNameSigner = new StrongNameSignerHelper(null, outputPeImage);
        //        strongNameSigner.RemoveSignature();
        //        if (strongNameSigner.HasStrongNameSignature())
        //        {
        //            using (FileStream fs = new FileStream(testAssembly.ResourceName + ".unsigned.dll", FileMode.Create, FileAccess.Write))
        //            {
        //                outputPeImage.Seek(0, SeekOrigin.Begin);
        //                outputPeImage.CopyTo(fs);
        //            }
        //        }
        //    }
        //}
    }
}
