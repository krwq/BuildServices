using SigningService.Models;
using System.Reflection;
using SigningService.Extensions;
using System;
using System.Security.Cryptography;

namespace SigningService.Signers.StrongName
{
    // Public Key Blob should looks as following:
    // [Optional] 12 bytes header:
    //      - Signature Algorithm Id (4 bytes)
    //      - Hash Algorithm Id (4 bytes)
    //      - Signature Size (4 bytes)
    // Prefix (4 bytes)
    // Signature Algorithm Id (4 bytes)
    // "RSA1" (4 bytes)
    // Modulus size in bits (4 bytes)
    // Exponent (4 bytes)
    // Modulus bytes (var size)
    internal class PublicKeyBlob
    {
        private static readonly byte[] Prefix = new byte[] { 0x06, 0x02, 0x00, 0x00 };
        private static readonly byte[] RSA1 = new byte[] { (byte)'R', (byte)'S', (byte)'A', (byte)'1' };

        public PublicKeyBlob(byte[] publicKeyBlob)
        {
            Blob = publicKeyBlob;
            _publicKey = new Lazy<PublicKey>(GetPublicKey);
            _publicKeyToken = new Lazy<string>(GetPublicKeyToken);
            _hashAlgorithm = new Lazy<AssemblyHashAlgorithm>(GetHashAlgorithm);
        }

        public PublicKeyBlob(string publicKeyBlobHex)
            : this(ByteArrayExt.FromHex(publicKeyBlobHex)) { }

        private Lazy<PublicKey> _publicKey;
        private Lazy<string> _publicKeyToken;
        private Lazy<AssemblyHashAlgorithm> _hashAlgorithm;

        public byte[] Blob { get; private set; }
        public PublicKey PublicKey { get { return _publicKey.Value; } }
        public string PublicKeyToken { get { return _publicKeyToken.Value; } }
        public AssemblyHashAlgorithm HashAlgorithm { get { return _hashAlgorithm.Value; } }

        private PublicKey GetPublicKey()
        {
            // Searching for prefix
            int offset = 0;
            if (!Blob.ContainsSubarray(offset, Prefix))
            {
                // We probably found optional header
                offset += 12;
                if (!Blob.ContainsSubarray(offset, Prefix))
                {
                    ExceptionsHelper.ThrowBadFormatException();
                    return null;
                }
            }

            // Searching for RSA1 bytes
            offset += 8;
            if (!Blob.ContainsSubarray(offset, RSA1))
            {
                ExceptionsHelper.ThrowBadFormatException();
                return null;
            }

            offset += 4;
            UInt32 modulusSize = ReadUInt32AtOffset(Blob, offset);
            modulusSize /= 8;

            offset += 4;
            byte[] exponent = new byte[4];
            Array.Copy(Blob, offset, exponent, 0, 4);

            offset += 4;
            if (Blob.Length != offset + modulusSize)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return null;
            }

            byte[] modulus = new byte[modulusSize];
            Array.Copy(Blob, offset, modulus, 0, modulusSize);
            modulus.ReverseInplace();

            return new PublicKey(exponent, modulus);
        }


        private unsafe AssemblyHashAlgorithm GetHashAlgorithm()
        {
            if (Blob.Length < 8)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return default(AssemblyHashAlgorithm);
            }
            fixed (byte* pk = Blob)
            {
                int* hashAlg = (int*)(pk + 4);
                return (AssemblyHashAlgorithm)(*hashAlg);
            }
        }

        private string GetPublicKeyToken()
        {
            byte[] ret = new byte[8];
            HashAlgorithm sha1 = SHA1.Create();

            sha1.TransformFinalBlock(Blob, 0, Blob.Length);

            for (int i = 0; i < 8; i++)
            {
                ret[i] = sha1.Hash[sha1.Hash.Length - i - 1];
            }
            
            return ret.ToHex();
        }

        private static UInt32 ReadUInt32AtOffset(byte[] bytes, int offset, int size = 4)
        {
            if (size < 0 || size > 4 || offset < 0)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return 0xFFFFFFFF;
            }

            if (offset + size > bytes.Length)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return 0xFFFFFFFF;
            }

            UInt32 ret = 0;
            for (int i = 0; i < size; i++)
            {
                ret += (UInt32)(bytes[offset + i]) << (i * 8);
            }
            return ret;
        }
    }
}