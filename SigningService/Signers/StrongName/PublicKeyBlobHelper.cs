using SigningService.Extensions;
using SigningService.Models;
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace SigningService.Signers.StrongName
{
    internal static class PublicKeyBlobHelper
    {
        private static readonly byte[] Prefix = new byte[] { 0x06, 0x02, 0x00, 0x00 };
        private static readonly byte[] RSA1 = new byte[] { (byte)'R', (byte)'S', (byte)'A', (byte)'1' };

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
        public static PublicKey GetPublicKey(byte[] publicKeyBlob)
        {
            // Searching for prefix
            int offset = 0;
            if (!publicKeyBlob.ContainsSubarray(offset, Prefix))
            {
                // We probably found optional header
                offset += 12;
                if (!publicKeyBlob.ContainsSubarray(offset, Prefix))
                {
                    ExceptionsHelper.ThrowBadFormatException();
                    return null;
                }
            }

            // Searching for RSA1 bytes
            offset += 8;
            if (!publicKeyBlob.ContainsSubarray(offset, RSA1))
            {
                ExceptionsHelper.ThrowBadFormatException();
                return null;
            }

            offset += 4;
            UInt32 modulusSize = ReadUInt32AtOffset(publicKeyBlob, offset);
            modulusSize /= 8;

            offset += 4;
            byte[] exponent = new byte[4];
            Array.Copy(publicKeyBlob, offset, exponent, 0, 4);

            offset += 4;
            if (publicKeyBlob.Length != offset + modulusSize)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return null;
            }

            byte[] modulus = new byte[modulusSize];
            Array.Copy(publicKeyBlob, offset, modulus, 0, modulusSize);
            modulus.ReverseInplace();

            return new PublicKey(exponent, modulus);
        }


        public unsafe static AssemblyHashAlgorithm GetHashAlgorithm(byte[] publicKeyBlob)
        {
            if (publicKeyBlob.Length < 8)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return default(AssemblyHashAlgorithm);
            }
            fixed (byte* pk = publicKeyBlob)
            {
                int* hashAlg = (int*)(pk + 4);
                return (AssemblyHashAlgorithm)(*hashAlg);
            }
        }

        public static string GetPublicKeyToken(byte[] publicKeyBlob)
        {
            byte[] ret = new byte[8];
            HashAlgorithm sha1 = SHA1.Create();

            sha1.TransformFinalBlock(publicKeyBlob, 0, publicKeyBlob.Length);

            for (int i = 0; i < 8; i++)
            {
                ret[i] = sha1.Hash[sha1.Hash.Length - i - 1];
            }
            
            return ByteArrayToHex(ret);
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

        // Dummy implementation
        // No need for anything faster
        public static byte[] ByteArrayFromHex(string hex)
        {
            byte[] ret = new byte[hex.Length / 2];
            for (int i = 0, j = 0; i < ret.Length; i++, j += 2)
            {
                string hexByte = hex.Substring(j, 2);
                ret[i] = Convert.ToByte(hexByte, 16);
            }
            return ret;
        }

        public static string ByteArrayToHex(byte[] t)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(string.Format("{0:x2}", t[i]));
            }
            return sb.ToString();
        }
    }
}