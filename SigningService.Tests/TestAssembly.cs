using System.Collections.Generic;
using System.IO;

namespace SigningService.Tests
{
    public struct TestAssembly
    {
        public TestAssembly(string resourceName, byte[] strongNameSignatureHash = null)
        {
            ResourceName = resourceName;
            StrongNameSignatureHash = strongNameSignatureHash;
        }
        public string ResourceName;
        public byte[] StrongNameSignatureHash;
        public Stream GetWritablePEImage()
        {
            MemoryStream writablePEImage = new MemoryStream();
            using (Stream peImage = this.GetType().Assembly.GetManifestResourceStream(ResourceName))
            {
                peImage.CopyTo(writablePEImage);
                writablePEImage.Seek(0, SeekOrigin.Begin);
            }

            return writablePEImage;
        }

        public static IEnumerable<object[]> GetTestAssemblies()
        {
            yield return new object[] {
                new TestAssembly(
                    resourceName: @"TestLib.delay.dll",
                    strongNameSignatureHash : new byte[] {
                        0xA3, 0x15, 0x35, 0xB5, 0x37, 0x6C, 0xC7, 0xE4, 0xCF, 0x16, 0x10, 0x25, 0xB3, 0xDD, 0xA6, 0xA3,
                        0x04, 0xEC, 0x8F, 0x80, 0x43, 0xD3, 0x47, 0xB8, 0xF1, 0x64, 0xD7, 0x2F, 0x9D, 0x42, 0x6D, 0x2E
                    }
                )
            };
        }
    }
}
