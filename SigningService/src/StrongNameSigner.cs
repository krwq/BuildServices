using SigningService.Agents;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SigningService
{
    public class StrongNameSigner
    {
        private Lazy<HashAlgorithm> _hashAlgorithm;
        private readonly IKeyVaultAgent _keyVaultAgent;
        private Stream _peStream;
        private Lazy<StrongNameSignerDataExtractor> _dataExtractor;
        private bool _strongNameSignedBitSet = false;
        public StrongNameSigner(IKeyVaultAgent keyVaultAgent, Stream peStream)
        {
            _keyVaultAgent = keyVaultAgent;
            _peStream = peStream;
            _dataExtractor = new Lazy<StrongNameSignerDataExtractor>(ExtractData);
            _hashAlgorithm = new Lazy<HashAlgorithm>(CreateHashAlgorithm);
        }

        public async Task<bool> TrySignAsync()
        {
            if (CanSign())
            {
                byte[] hash = PrepareForSigningAndComputeHash(_peStream);
                byte[] signature = await _keyVaultAgent.Sign(hash);
                EmbedStrongNameSignature(signature);
                return true;
            }

            return false;
        }

        public bool HasStrongNameSignature()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            bool hasStrongNameSignedBit = _strongNameSignedBitSet | dataExtractor.HasStrongNameSignedFlag;
            return hasStrongNameSignedBit && dataExtractor.HasStrongNameSignatureDirectory;
        }

        public bool CanSign()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            bool ret = _peStream.CanWrite && _peStream.CanSeek && _peStream.CanRead;
            ret &= dataExtractor.IsValidAssembly;
            ret &= !dataExtractor.HasStrongNameSignedFlag;
            ret &= dataExtractor.HasStrongNameSignatureDirectory;
            ret &= _hashAlgorithm != null;
            //int hashSize = _hashAlgorithm.HashSize;
            // TODO: We need a way of predicting expected signature length
            return  ret;
        }

        public bool CanHash()
        {
            return _peStream.CanSeek && _peStream.CanRead && _dataExtractor.Value.IsValidAssembly;
        }

        public void EmbedStrongNameSignature(byte[] signature)
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!dataExtractor.HasStrongNameSignatureDirectory)
            {
                ExceptionsHelper.ThrowNoStrongNameSignatureDirectory();
                return;
            }

            if (dataExtractor.StrongNameSignatureDirectorySize != signature.Length)
            {
                ExceptionsHelper.ThrowStrongNameSignatureDirectorySizeIsDifferentThanProvidedSignature(dataExtractor.StrongNameSignatureDirectorySize, signature.Length);
                return;
            }

            if (!_peStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return;
            }

            _peStream.Seek(dataExtractor.StrongNameSignatureDirectoryOffset, SeekOrigin.Begin);
            _peStream.Write(signature, 0, signature.Length);
        }

        public byte[] ComputeHash()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                _peStream.Seek(0, SeekOrigin.Begin);
                _peStream.CopyTo(ms);
                return PrepareForSigningAndComputeHash(ms);
            }
        }

        public byte[] GetPublicKey()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            return dataExtractor.PublicKey;
        }

        public string GetPublicKeyToken()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            return dataExtractor.PublicKeyToken;
        }

        public AssemblyHashAlgorithm GetHashAlgorithm()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            return dataExtractor.HashAlgorithm;
        }

        private HashAlgorithm CreateHashAlgorithm()
        {
            switch (GetHashAlgorithm())
            {
                case AssemblyHashAlgorithm.MD5: return MD5.Create();
                case AssemblyHashAlgorithm.Sha1: return SHA1.Create();
                case AssemblyHashAlgorithm.Sha256: return SHA256.Create();
                case AssemblyHashAlgorithm.Sha384: return SHA384.Create();
                case AssemblyHashAlgorithm.Sha512: return SHA512.Create();
            }
            return null;
        }

        private byte[] PrepareForSigningAndComputeHash(Stream writablePEStream)
        {
            if (!writablePEStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return null;
            }

            PrepareForSigning(writablePEStream);
            return CalculateAssemblyHash(writablePEStream, _hashAlgorithm.Value, _dataExtractor.Value.SpecialHashingBlocks);
        }

        private void PrepareForSigning(Stream writablePEStream)
        {
            SetStrongNameSignedFlag(writablePEStream);
            EraseChecksum(writablePEStream);
        }

        public byte[] ExtractStrongNameSignature()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            if (!HasStrongNameSignature())
            {
                ExceptionsHelper.ThrowNoStrongNameSignature();
                return null;
            }

            _peStream.Seek(dataExtractor.StrongNameSignatureDirectoryOffset, SeekOrigin.Begin);
            int left = dataExtractor.StrongNameSignatureDirectorySize;
            byte[] signature = new byte[left];
            while (left > 0)
            {
                int bytesRead = _peStream.Read(signature, signature.Length - left, signature.Length);
                if (bytesRead <= 0)
                {
                    ExceptionsHelper.ThrowUnexpectedEndOfStream(_peStream.Position);
                    return null;
                }
                left -= bytesRead;
            }

            return signature;
        }

        private void EraseChecksum(Stream writablePEStream)
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!writablePEStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return;
            }

            // 0-initialized byte array
            byte[] newChecksum = new byte[dataExtractor.ChecksumSize];
            writablePEStream.Seek(dataExtractor.ChecksumOffset, SeekOrigin.Begin);
            writablePEStream.Write(newChecksum, 0, newChecksum.Length);
        }

        public void EraseChecksum()
        {
            EraseChecksum(_peStream);
        }

        public void SetStrongNameSignedFlag(Stream writablePEStream)
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!writablePEStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return;
            }

            using (BinaryWriter bw = new BinaryWriter(writablePEStream, Encoding.ASCII, leaveOpen : true))
            {
                bw.Seek(dataExtractor.CorFlagsOffset, SeekOrigin.Begin);
                bw.Write((UInt32)(dataExtractor.CorFlagsValue | CorFlags.StrongNameSigned));
            }

            if (writablePEStream == _peStream)
            {
                _strongNameSignedBitSet = true;
            }
        }

        public void SetStrongNameSignedFlag()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!_peStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return;
            }

            SetStrongNameSignedFlag(_peStream);
        }

        private StrongNameSignerDataExtractor ExtractData()
        {
            return new StrongNameSignerDataExtractor(_peStream);
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

        private static byte[] CalculateAssemblyHash(Stream s, HashAlgorithm hashAlgorithm, List<DataBlock> skipBlocks)
        {
            hashAlgorithm.Initialize();

            s.Seek(0, SeekOrigin.Begin);
            int previousEnd = 0;
            for (int i = 0; i < skipBlocks.Count; i++)
            {
                int bytesToRead = skipBlocks[i].Offset - previousEnd;
                CalculatePartialHashFromStream(s, hashAlgorithm, bytesToRead);
                if (s.Position != skipBlocks[i].Offset)
                {
                    ExceptionsHelper.ThrowPositionMismatch(skipBlocks[i].Offset, s.Position);
                    return null;
                }
                switch (skipBlocks[i].Hashing)
                {
                    case DataBlockHashing.HashZeros:
                    {
                        CalculatePartialHashFromZeros(hashAlgorithm, skipBlocks[i].Size);
                        s.Seek(skipBlocks[i].Size, SeekOrigin.Current);
                        break;
                    }
                    case DataBlockHashing.Hash:
                    {
                        CalculatePartialHashFromStream(s, hashAlgorithm,  skipBlocks[i].Size);
                        break;
                    }
                    case DataBlockHashing.Skip:
                    {
                        s.Seek(skipBlocks[i].Size, SeekOrigin.Current);
                        break;
                    }
                    default:
                    {
                        ExceptionsHelper.ThrowDataBlockHashingValueIsInvalid(skipBlocks[i].Hashing);
                        return null;
                    }
                }

                previousEnd = skipBlocks[i].Offset + skipBlocks[i].Size;
                if (s.Position != previousEnd)
                {
                    ExceptionsHelper.ThrowPositionMismatch(previousEnd, s.Position);
                }
            }

            long pos = previousEnd;
            long end = s.Seek(0, SeekOrigin.End);
            int bytesLeft = (int)(end - pos);
            s.Seek(previousEnd, SeekOrigin.Begin);

            CalculatePartialHashFromStream(s, hashAlgorithm, bytesLeft);

            byte[] buffer = new byte[1];
            hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
            return hashAlgorithm.Hash;
        }
    }
}
