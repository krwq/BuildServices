using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace SigningService.Signers.StrongName
{
    internal static class HashingHelpers
    {
        public static HashAlgorithm CreateHashAlgorithm(AssemblyHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case AssemblyHashAlgorithm.MD5: return MD5.Create();
                case AssemblyHashAlgorithm.Sha1: return SHA1.Create();
                case AssemblyHashAlgorithm.Sha256: return SHA256.Create();
                case AssemblyHashAlgorithm.Sha384: return SHA384.Create();
                case AssemblyHashAlgorithm.Sha512: return SHA512.Create();
                default: return null;
            }
        }

        public static byte[] CalculateAssemblyHash(Stream s, HashAlgorithm hashAlgorithm, List<HashingBlock> hashingBlocks)
        {
            hashAlgorithm.Initialize();

            for (int i = 0; i < hashingBlocks.Count; i++)
            {
                switch (hashingBlocks[i].Hashing)
                {
                    case HashingBlockHashing.HashZeros:
                    {
                        CalculatePartialHashFromZeros(hashAlgorithm, hashingBlocks[i].Size);
                        break;
                    }
                    case HashingBlockHashing.Hash:
                    {
                        s.Seek(hashingBlocks[i].Offset, SeekOrigin.Begin);
                        CalculatePartialHashFromStream(s, hashAlgorithm,  hashingBlocks[i].Size);
                        break;
                    }
                    case HashingBlockHashing.Skip:
                    {
                        break;
                    }
                    default:
                    {
                        ExceptionsHelper.ThrowArgumentOutOfRange("hashingBlocks");
                        return null;
                    }
                }
            }

            // Finalize hashing
            byte[] buffer = new byte[1];
            hashAlgorithm.TransformFinalBlock(buffer, 0, 0);

            return hashAlgorithm.Hash;
        }

        private static void CalculatePartialHashFromStream(Stream s, HashAlgorithm hashAlgorithm, int bytesToRead)
        {
            byte[] buffer = new byte[bytesToRead];
            int totalBytesRead = 0;
            while (bytesToRead > 0)
            {
                long prevPosition = s.Position;
                int bytesRead = s.Read(buffer, totalBytesRead, bytesToRead);
                totalBytesRead += bytesRead;
                bytesToRead -= bytesRead;

                if (bytesRead <= 0)
                {
                    ExceptionsHelper.ThrowUnexpectedEndOfStream(s.Position);
                    return;
                }
                
                hashAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
            }
        }

        private static void CalculatePartialHashFromZeros(HashAlgorithm hashAlgorithm, int numberOfZeroedBytes)
        {
            // Create 0-initialized array
            byte[] buffer = new byte[numberOfZeroedBytes];
            hashAlgorithm.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
        }
    }
}