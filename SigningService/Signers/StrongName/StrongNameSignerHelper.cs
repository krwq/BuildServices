using SigningService.Agents;
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
        private Stream _peStream;

        private bool _strongNameSignedBitSet = false;
        private bool _strongNameSignedBitOverwritten = false;

        // Lazy fields
        private Lazy<HashAlgorithm> _hashAlgorithm;
        private Lazy<AssemblyMetadataExtractor> _dataExtractor;
        private Lazy<List<HashingBlock>> _hashingBlocks;

        public StrongNameSignerHelper(Stream peStream)
        {
            _peStream = peStream;
            _dataExtractor = new Lazy<AssemblyMetadataExtractor>(InitDataExtractor);
            _hashAlgorithm = new Lazy<HashAlgorithm>(InitHashAlgorithm);
            _hashingBlocks = new Lazy<List<HashingBlock>>(InitHashingBlocks);
        }

        public bool HasStrongNameSignature()
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

            if (!dataExtractor.HasStrongNameSignatureDirectory)
            {
                return false;
            }

            return _strongNameSignedBitOverwritten ? _strongNameSignedBitSet : dataExtractor.HasStrongNameSignedFlag;
        }

        public bool CanSign()
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

            bool ret = _peStream.CanWrite && _peStream.CanSeek && _peStream.CanRead;
            ret &= !HasStrongNameSignature();
            ret &= _hashAlgorithm.Value != null;
            ret &= SupportsHashAlgorithm(PublicKeyBlob.HashAlgorithm);
            //int hashSize = _hashAlgorithm.HashSize;
            // TODO: We need a way of predicting expected signature length

            return ret;
        }

        public bool CanHash
        {
            get
            {
                return _peStream.CanSeek && _peStream.CanRead;
            }
        }

        public void EmbedStrongNameSignature(byte[] signature)
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

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

            ExceptionsHelper.ThrowIfStreamNotWritable(_peStream);

            _peStream.Seek(dataExtractor.StrongNameSignatureDirectoryOffset, SeekOrigin.Begin);
            _peStream.Write(signature, 0, signature.Length);
        }

        public void EmbedEmptyStrongNameSignature()
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;
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
                AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;
                if (dataExtractor.AssemblySignatureKeyAttributePublicKey != null)
                {
                    return dataExtractor.AssemblySignatureKeyAttributePublicKey;
                }
                else
                {
                    return dataExtractor.AssemblyDefinitionPublicKeyBlob;
                }
            }
        }

        public PublicKeyBlob AssemblyDefinitionPublicKeyBlob { get { return _dataExtractor.Value.AssemblyDefinitionPublicKeyBlob; } }

        public PublicKeyBlob AssemblySignatureKeyPublicKeyBlob { get { return _dataExtractor.Value.AssemblySignatureKeyAttributePublicKey; } }

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
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;
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
        private AssemblyMetadataExtractor InitDataExtractor()
        {
            return new AssemblyMetadataExtractor(_peStream);
        }

        /// <summary>
        /// Initializes lazy private field _hashAlgorithm
        /// </summary>
        /// <returns>Instance of the System.Security.Cryptography.HashAlgorithm related to signature public key</returns>
        private HashAlgorithm InitHashAlgorithm()
        {
            return HashingHelpers.CreateHashAlgorithm(PublicKeyBlob.HashAlgorithm);
        }

        /// <summary>
        /// Initializes lazy private field _hashingBlocks which decides what parts of PE will be hashed
        /// </summary>
        private List<HashingBlock> InitHashingBlocks()
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

            List<HashingBlock> hashingBlocks = new List<HashingBlock>(16);

            hashingBlocks.Add(new HashingBlock(HashingBlockHashing.Hash, "PE Headers", 0, dataExtractor.PaddingBetweenTheSectionHeadersAndSectionsOffset));
            foreach (var section in dataExtractor.SectionsInfo)
            {
                string name = string.Format("Section {0}", section.Name);
                hashingBlocks.Add(new HashingBlock(HashingBlockHashing.Hash, name, section.Offset, section.Size));
            }

            hashingBlocks.Add(new HashingBlock(HashingBlockHashing.HashZeros, "Checksum", dataExtractor.ChecksumOffset, dataExtractor.ChecksumSize));

            // According to ECMA-335 this block should be zeroed and hashed (HashingBlockHashing.HashZeros)
            // For compat reasons we fully hash it
            //specialHashingBlocks.Add(new HashingBlock(HashingBlockHashing.Hash, "StrongNameSignatureDirectory header", StrongNameSignatureDirectoryHeaderOffset, StrongNameSignatureDirectoryHeaderSize));
            
            hashingBlocks.Add(new HashingBlock(HashingBlockHashing.HashZeros, "CertificateTableDirectory header", dataExtractor.CertificateTableDirectoryHeaderOffset, dataExtractor.CertificateTableDirectoryHeaderSize));

            if (dataExtractor.HasStrongNameSignatureDirectory)
            {
                hashingBlocks.Add(new HashingBlock(HashingBlockHashing.Skip, "StrongNameSignatureDirectory", dataExtractor.StrongNameSignatureDirectoryOffset, dataExtractor.StrongNameSignatureDirectorySize));
            }
            else
            {
                ExceptionsHelper.ThrowNoStrongNameSignatureDirectory();
            }

            // In theory we should be hashing it, in practice in some cases it might be past the last section
            // and for compat reasons we do not.
            //if (HasCertificateTableDirectory)
            //{
            //    specialHashingBlocks.Add(new DataBlock(DataBlockHashing.Hash, "CertificateTableDirectory", CertificateTableDirectoryOffset, CertificateTableDirectorySize));
            //}

            return HashingHelpers.SortAndJoinIntersectingHashingBlocks(hashingBlocks);
        }
#endregion

        private byte[] PrepareForSigningAndComputeHash(Stream writablePEStream)
        {
            ExceptionsHelper.ThrowIfStreamNotWritable(writablePEStream);

            PrepareForSigning(writablePEStream);
            return HashingHelpers.CalculateAssemblyHash(writablePEStream, _hashAlgorithm.Value, _hashingBlocks.Value);
        }

        private void PrepareForSigning(Stream writablePEStream)
        {
            SetStrongNameSignedFlag(writablePEStream);
            EraseChecksum(writablePEStream);
        }

        public byte[] ExtractStrongNameSignature()
        {
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;
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
            ExceptionsHelper.ThrowIfStreamNotWritable(writablePEStream);

            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

            // 0-initialized byte array
            byte[] newChecksum = new byte[dataExtractor.ChecksumSize];
            writablePEStream.Seek(dataExtractor.ChecksumOffset, SeekOrigin.Begin);
            writablePEStream.Write(newChecksum, 0, newChecksum.Length);
        }

        public void EraseChecksum()
        {
            EraseChecksum(_peStream);
        }

        private void SetStrongNameSignedFlag(Stream writablePEStream, bool value = true)
        {
            ExceptionsHelper.ThrowIfStreamNotWritable(writablePEStream);

            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

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
            SetStrongNameSignedFlag(_peStream, value);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            AssemblyMetadataExtractor dataExtractor = _dataExtractor.Value;

            sb.AppendLine("Signature directory size: {0}", dataExtractor.StrongNameSignatureDirectorySize);
            sb.AppendLine("AssemblyDefinition Hash Algorithm: {0}", AssemblyDefinitionPublicKeyBlob.HashAlgorithm);
            if (AssemblySignatureKeyPublicKeyBlob != null)
            {
                sb.AppendLine("AssemblySignatureKey Hash Algorithm: {0}", AssemblySignatureKeyPublicKeyBlob.HashAlgorithm);
            }
            byte[] hash = ComputeHash();

            sb.AppendLine("Calculated hash size: {0}", hash.Length);
            sb.AppendLine("Calculated hash: {0}", hash.ToHex());

            foreach (var block in _hashingBlocks.Value)
            {
                sb.AppendLine(block.ToString());
            }

            sb.AppendLine("NumberOfSections = {0}", dataExtractor.NumberOfSections);
            sb.AppendLine("SectionsHeadersEndOffset = {0}", dataExtractor.SectionsHeadersEndOffset);
            foreach (SectionInfo section in dataExtractor.SectionsInfo)
            {
                sb.AppendLine(section.ToString());
            }

            return sb.ToString();
        }
    }
}
