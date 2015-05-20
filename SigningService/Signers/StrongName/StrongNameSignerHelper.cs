using SigningService.Agents;
using SigningService.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SigningService.Signers.StrongName
{
    internal class StrongNameSignerHelper
    {
        private Lazy<HashAlgorithm> _hashAlgorithm;
        private readonly IKeyVaultAgent _keyVaultAgent;
        private Lazy<Task<string>> _keyVaultKeyId;
        private Stream _peStream;
        private Lazy<StrongNameSignerDataExtractor> _dataExtractor;
        private bool _strongNameSignedBitSet = false;
        private bool _strongNameSignedBitOverwritten = false;

        public StrongNameSignerHelper(IKeyVaultAgent keyVaultAgent, Stream peStream)
        {
            _keyVaultAgent = keyVaultAgent;
            _peStream = peStream;
            _dataExtractor = new Lazy<StrongNameSignerDataExtractor>(ExtractData);
            _hashAlgorithm = new Lazy<HashAlgorithm>(CreateHashAlgorithm);
            _keyVaultKeyId = new Lazy<Task<string>>(GetKeyVaultKeyIdFromKeyVaultAsync);
        }

        public async Task<bool> TrySignAsync()
        {
            if (await CanSignAsync())
            {
                byte[] hash = PrepareForSigningAndComputeHash(_peStream);
                string keyId = await _keyVaultKeyId.Value;
                byte[] signature = await _keyVaultAgent.SignAsync(keyId, hash);
                EmbedStrongNameSignature(signature);
                return true;
            }

            return false;
        }

        // Do not call directly, use _keyVaultKeyId.Value instead
        // This method should be called only during lazy initialization of _keyVaultKeyId
        private async Task<string> GetKeyVaultKeyIdFromKeyVaultAsync()
        {
            return await _keyVaultAgent.GetRsaKeyIdAsync(PublicKey.Exponent, PublicKey.Modulus);
        }

        public async Task<string> GetKeyVaultKeyId()
        {
            return await _keyVaultKeyId.Value;
        }

        public bool HasStrongNameSignature()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!dataExtractor.HasStrongNameSignatureDirectory)
            {
                return false;
            }

            return _strongNameSignedBitOverwritten ? _strongNameSignedBitSet : dataExtractor.HasStrongNameSignedFlag;
        }

        public async Task<bool> CanSignAsync()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            bool ret = _peStream.CanWrite && _peStream.CanSeek && _peStream.CanRead;
            ret &= dataExtractor.IsValidAssembly;
            ret &= !HasStrongNameSignature();
            ret &= _hashAlgorithm != null;
            ret &= SupportsHashAlgorithm(HashAlgorithm);
            //int hashSize = _hashAlgorithm.HashSize;
            // TODO: We need a way of predicting expected signature length

            if (!ret)
            {
                // No need for actual async
                return false;
            }

            string keyId = await _keyVaultKeyId.Value;
            return keyId != null;
        }

        public bool CanHash
        {
            get
            {
                return _peStream.CanSeek && _peStream.CanRead && _dataExtractor.Value.IsValidAssembly;
            }
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

        public void EmbedEmptyStrongNameSignature()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            byte[] signature = new byte[dataExtractor.StrongNameSignatureDirectorySize];
            EmbedStrongNameSignature(signature);
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

        public byte[] PublicKeyBlob
        {
            get
            {
                StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyAttributePublicKeyBlob != null)
                {
                    return dataExtractor.AssemblySignatureKeyAttributePublicKeyBlob;
                }
                else
                {
                    return dataExtractor.PublicKeyBlob;
                }
            }
        }

        public PublicKey PublicKey
        {
            get
            {
                StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyAttributePublicKeyBlob != null)
                {
                    return dataExtractor.AssemblySignatureKeyAttributePublicKey;
                }
                else
                {
                    return dataExtractor.PublicKey;
                }
            }
        }

        public string PublicKeyToken
        {
            get
            {
                StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyAttributePublicKeyBlob != null)
                {
                    return dataExtractor.AssemblySignatureKeyAttributePublicKeyToken;
                }
                else
                {
                    return dataExtractor.PublicKeyToken;
                }
            }
        }

        public AssemblyHashAlgorithm HashAlgorithm
        {
            get
            {
                StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyAttributePublicKeyBlob != null)
                {
                    return dataExtractor.AssemblySignatureKeyAttributeHashAlgorithm;
                }
                else
                {
                    return dataExtractor.HashAlgorithm;
                }
            }
        }

        public static bool SupportsHashAlgorithm(AssemblyHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case AssemblyHashAlgorithm.Sha1:
                case AssemblyHashAlgorithm.Sha256:
                case AssemblyHashAlgorithm.Sha384:
                case AssemblyHashAlgorithm.Sha512:
                    return true;
            }

            return false;
        }

        public void RemoveSignature()
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
            if (!HasStrongNameSignature())
            {
                // nothing to do
                return;
            }

            SetStrongNameSignedFlag(false);
            EmbedEmptyStrongNameSignature();
        }

        private HashAlgorithm CreateHashAlgorithm()
        {
            switch (HashAlgorithm)
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

        public void SetStrongNameSignedFlag(Stream writablePEStream, bool value = true)
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
                CorFlags corFlags = dataExtractor.CorFlagsValue;
                if (value)
                {
                    corFlags |= CorFlags.StrongNameSigned;
                }
                else
                {
                    corFlags &= ~(CorFlags.StrongNameSigned);
                }
                bw.Write((UInt32)(corFlags));
            }

            if (writablePEStream == _peStream)
            {
                _strongNameSignedBitSet = value;
                _strongNameSignedBitOverwritten = true;
            }
        }

        public void SetStrongNameSignedFlag(bool value = true)
        {
            StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;

            if (!_peStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return;
            }

            SetStrongNameSignedFlag(_peStream, value);
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
