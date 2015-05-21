using SigningService.Agents;
using SigningService.Models;
using SigningService.Extensions;
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
        private readonly IKeyVaultAgent _keyVaultAgent;
        private Stream _peStream;

        private bool _strongNameSignedBitSet = false;
        private bool _strongNameSignedBitOverwritten = false;

        // Lazy fields
        private Lazy<Task<string>> _keyVaultKeyId;
        private Lazy<HashAlgorithm> _hashAlgorithm;
        private Lazy<StrongNameSignerDataExtractor> _dataExtractor;

        public StrongNameSignerHelper(IKeyVaultAgent keyVaultAgent, Stream peStream)
        {
            _keyVaultAgent = keyVaultAgent;
            _peStream = peStream;
            _dataExtractor = new Lazy<StrongNameSignerDataExtractor>(InitDataExtractor);
            _hashAlgorithm = new Lazy<HashAlgorithm>(InitHashAlgorithm);
            _keyVaultKeyId = new Lazy<Task<string>>(InitKeyVaultKeyIdFromKeyVaultAsync);
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
            ret &= SupportsHashAlgorithm(PublicKeyBlob.HashAlgorithm);
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

        public PublicKeyBlob PublicKeyBlob
        {
            get
            {
                StrongNameSignerDataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyPublicKey != null)
                {
                    return dataExtractor.AssemblySignatureKeyPublicKey;
                }
                else
                {
                    return dataExtractor.PublicKeyBlob;
                }
            }
        }

        public PublicKeyBlob AssemblyDefinitionPublicKeyBlob { get { return _dataExtractor.Value.PublicKeyBlob; } }

        public PublicKeyBlob AssemblySignatureKeyPublicKeyBlob { get { return _dataExtractor.Value.AssemblySignatureKeyPublicKey; } }

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

#region Lazy fields initializers
        /// <summary>
        /// Initializes lazy private field _dataExtractor
        /// </summary>
        /// <returns>Data extractor for PE file with CLI metadata</returns>
        private StrongNameSignerDataExtractor InitDataExtractor()
        {
            return new StrongNameSignerDataExtractor(_peStream);
        }

        /// <summary>
        /// Initializes lazy private field _keyVaultKeyId
        /// </summary>
        /// <returns>KeyVault KeyId related to signature public key</returns>
        private async Task<string> InitKeyVaultKeyIdFromKeyVaultAsync()
        {
            return await _keyVaultAgent.GetRsaKeyIdAsync(PublicKeyBlob.PublicKey.Exponent, PublicKeyBlob.PublicKey.Modulus);
        }

        /// <summary>
        /// Initializes lazy private field _hashAlgorithm
        /// </summary>
        /// <returns>Instance of the System.Security.Cryptography.HashAlgorithm related to signature public key</returns>
        private HashAlgorithm InitHashAlgorithm()
        {
            return HashingHelpers.CreateHashAlgorithm(PublicKeyBlob.HashAlgorithm);
        }
#endregion

        private byte[] PrepareForSigningAndComputeHash(Stream writablePEStream)
        {
            if (!writablePEStream.CanWrite)
            {
                ExceptionsHelper.ThrowCannotWriteToStream();
                return null;
            }

            PrepareForSigning(writablePEStream);
            return HashingHelpers.CalculateAssemblyHash(writablePEStream, _hashAlgorithm.Value, _dataExtractor.Value.HashingBlocks);
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

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            var dataExtractor = _dataExtractor.Value;

            sb.AppendLine("Signature directory size: {0}", dataExtractor.StrongNameSignatureDirectorySize);
            sb.AppendLine("AssemblyDefinition Hash Algorithm: {0}", AssemblyDefinitionPublicKeyBlob.HashAlgorithm);
            if (AssemblySignatureKeyPublicKeyBlob != null)
            {
                sb.AppendLine("AssemblySignatureKey Hash Algorithm: {0}", AssemblySignatureKeyPublicKeyBlob.HashAlgorithm);
            }
            byte[] hash = ComputeHash();

            sb.AppendLine("Calculated hash size: {0}", hash.Length);
            sb.AppendLine("Calculated hash: {0}", hash.ToHex());

            foreach (var block in dataExtractor.HashingBlocks)
            {
                sb.AppendLine(block.ToString());
            }

            sb.AppendLine("NumberOfSections = {0}", dataExtractor.NumberOfSections);
            sb.AppendLine("SectionsHeadersEndOffset = {0}", dataExtractor.SectionsHeadersEndOffset);
            sb.AppendLine("SectionsStartOffset = {0}", dataExtractor.SectionsStartOffset);
            foreach (SectionInfo section in dataExtractor.SectionsInfo)
            {
                string name = section.Name.RemoveSpecialCharacters();
                sb.AppendLine("SECTION(Name = {0}, Start = {1}, Size = {2})", name, section.Offset, section.Size);
            }

            return sb.ToString();
        }
    }
}
