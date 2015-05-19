using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace SigningService
{
    // Extracts all data needed to calculate hash, verify if assembly is signable and to sign it
    public class StrongNameSignerDataExtractor
    {
        public StrongNameSignerDataExtractor(Stream peStream)
        {
            _peStream = peStream;

            // Assuming peImage begins on offset 0
            peStream.Seek(0, SeekOrigin.Begin);

            IsValidAssembly = true;

            ExtractData();
            SpecialHashingBlocks = SortAndJoinIntersectingDataBlocks(GetSpecialHashingBlocks());
        }

        private unsafe void ExtractData()
        {
            using (PEReader peReader = new PEReader(_peStream, PEStreamOptions.LeaveOpen | PEStreamOptions.PrefetchEntireImage | PEStreamOptions.PrefetchMetadata))
            {
                CorFlagsOffset = peReader.PEHeaders.CorHeader.FlagsOffset;
                ChecksumOffset = peReader.PEHeaders.PEHeader.CheckSumOffset;
                CorFlagsValue = peReader.PEHeaders.CorHeader.Flags;

                StrongNameSignatureDirectoryHeaderOffset = peReader.PEHeaders.CorHeader.StrongNameSignatureDirectory.HeaderOffset;
                int strongNameSignatureDirectoryOffset;
                HasStrongNameSignatureDirectory = peReader.PEHeaders.TryGetDirectoryOffset(peReader.PEHeaders.CorHeader.StrongNameSignatureDirectory, out strongNameSignatureDirectoryOffset);
                if (HasStrongNameSignatureDirectory)
                {
                    StrongNameSignatureDirectoryOffset = strongNameSignatureDirectoryOffset;
                    StrongNameSignatureDirectorySize = peReader.PEHeaders.CorHeader.StrongNameSignatureDirectory.Size;
                }

                CertificateTableDirectoryHeaderOffset = peReader.PEHeaders.PEHeader.CertificateTableDirectory.HeaderOffset;
                int certificateTableDirectoryOffset;
                HasCertificateTableDirectory = peReader.PEHeaders.TryGetDirectoryOffset(peReader.PEHeaders.PEHeader.CertificateTableDirectory, out certificateTableDirectoryOffset);
                if (HasCertificateTableDirectory)
                {
                    // It is not clear what to do with this block. According to ECMA-335 we should skip it which can either mean Skip or HashZeros 
                    // although looking at sn.exe implementation I didn't see they are doing that so leaving it as Hash
                    Console.WriteLine("This may not work as expected. Please verify this signature is correct. If it is please remove the warning.");
                    CertificateTableDirectoryOffset = certificateTableDirectoryOffset;
                    CertificateTableDirectorySize = peReader.PEHeaders.PEHeader.CertificateTableDirectory.Size;
                }

                SectionsHeadersEndOffset = peReader.PEHeaders.SectionsHeadersEndOffset;
                NumberOfSections = peReader.PEHeaders.CoffHeader.NumberOfSections;
                if (NumberOfSections > 0)
                {
                    SectionsStartOffset = peReader.PEHeaders.SectionHeaders[0].PointerToRawData;
                }
                else
                {
                    IsValidAssembly = false;
                    ExceptionsHelper.ThrowPEImageHasNoSections();
                    return;
                }

                MetadataReader mr = peReader.GetMetadataReader();
                AssemblyDefinition assemblyDef = mr.GetAssemblyDefinition();
                PublicKeyBlob = mr.GetBlobBytes(assemblyDef.PublicKey);
                PublicKey = new PublicKey(PublicKeyBlob);
                PublicKeyToken = GetPublicKeyToken(PublicKeyBlob);

                // Public Key consists of following field:
                // - Signature algorithm (4 bytes)
                // - Hash Algorithm (4 bytes)
                // - Public Key size (4 bytes)
                // - public Key (var size)
                if (PublicKeyBlob.Length < 8)
                {
                    IsValidAssembly = false;
                    ExceptionsHelper.ThrowBadFormatException();
                    return;
                }
                fixed (byte* pk = PublicKeyBlob)
                {
                    int* hashAlg = (int*)(pk + 4);
                    HashAlgorithm = (AssemblyHashAlgorithm)(*hashAlg);
                }
            }
        }

        private List<DataBlock> GetSpecialHashingBlocks()
        {
            List<DataBlock> specialHashingBlocks = new List<DataBlock>(16);
            specialHashingBlocks.Add(new DataBlock(DataBlockHashing.HashZeros, "Checksum", ChecksumOffset, ChecksumSize));
            specialHashingBlocks.Add(new DataBlock(DataBlockHashing.Hash, "StrongNameSignatureDirectory header", StrongNameSignatureDirectoryHeaderOffset, StrongNameSignatureDirectoryHeaderSize));
            specialHashingBlocks.Add(new DataBlock(DataBlockHashing.HashZeros, "CertificateTableDirectory header", CertificateTableDirectoryHeaderOffset, CertificateTableDirectoryHeaderSize));
            specialHashingBlocks.Add(new DataBlock(DataBlockHashing.Skip, "Padding between directory headers and sections", PaddingBetweenTheSectionHeadersAndSectionsOffset, PaddingBetweenTheSectionHeadersAndSectionsSize));

            if (HasStrongNameSignatureDirectory)
            {
                specialHashingBlocks.Add(new DataBlock(DataBlockHashing.Skip, "StrongNameSignatureDirectory", StrongNameSignatureDirectoryOffset, StrongNameSignatureDirectorySize));
            }

            if (HasCertificateTableDirectory)
            {
                specialHashingBlocks.Add(new DataBlock(DataBlockHashing.Hash, "CertificateTableDirectory", CertificateTableDirectoryOffset, CertificateTableDirectorySize));
            }

            return specialHashingBlocks;
        }

        // Sorts by offsets and joins adjacent blocks
        // THIS IS SIMPLE IMPLEMENTATION which assumes there is gonna be up to 2 overlapping blocks.
        // This might not work properly for 3 or more overlapping blocks.
        // TODO: Use priority to determine what hashing action we should take.
        //       We should use PriorityQueue implementation and split blocks into (begin, offset, id) (end, offset, id)
        // Intersections of blocks may happen if i.e. StrongNameDirectory persists inside CertificateDirectory
        // We always assume that regular hashing has lower precedence.
        //
        // Example intersection:
        // HASHING
        // ,____________,
        //        ,________,
        //         SKIP
        //
        // Results in:
        // ,______,________,
        // HASH    SKIP
        //
        // HASHING
        // ,____________,
        //        ,___,
        //         SKIP
        //
        // Results in:
        // ,______,___,_,
        // HASH    SKIP HASH
        private static List<DataBlock> SortAndJoinIntersectingDataBlocks(List<DataBlock> blocks)
        {
            blocks.Sort();

            List<DataBlock> ret = new List<DataBlock>(16);

            DataBlock prev = new DataBlock(DataBlockHashing.Hash, "Fake block beginning", 0, 0);
            for (int i = 0; i < blocks.Count; i++)
            {
                // are intersecting? (adjacent is ok)
                if (blocks[i].Offset < prev.Offset + prev.Size)
                {
                    if (prev.Size == 0)
                    {
                        prev = blocks[i];
                    }
                    else
                    {
                        if (prev.Hashing == blocks[i].Hashing)
                        {
                            // If they have the same type of hashing situation is clear, we just add them
                            prev.Name += " + " + blocks[i].Name;
                            // prev offset is always lower or equal to blocks[i] offset as DataBlocks are sorted
                            prev.Size = Math.Max(prev.Offset + prev.Size, blocks[i].Offset + blocks[i].Size) - prev.Offset;
                        }
                        else
                        {
                            // Now it means we have a conflict
                            // We are gonna try resolve DataBlockHashing.Hash vs anything else
                            // In any other case we throw
                            //
                            // We are gonna output 1-3 block:
                            // ,______,_______,_______,
                            //  LEFT   MIDDLE  RIGHT
                            // where MIDDLE = blocks[i]
                            if (prev.Hashing ==  DataBlockHashing.Hash)
                            {
                                int leftBlockSize = blocks[i].Offset - prev.Offset;
                                if (leftBlockSize > 0)
                                {
                                    // we add left block if size is non zero
                                    ret.Add(new DataBlock(DataBlockHashing.Hash, prev.Name, prev.Offset, leftBlockSize));
                                }

                                int rightBlockEndOffset = prev.Offset + prev.Size;
                                int middleBlockEndOffset = blocks[i].Offset + blocks[i].Size;

                                DataBlock rightBlock = new DataBlock(DataBlockHashing.Hash, prev.Name, middleBlockEndOffset, rightBlockEndOffset - middleBlockEndOffset);
                                if (rightBlock.Size > 0)
                                {
                                    // we add middle block and right block if right is non-zero
                                    ret.Add(blocks[i]);
                                    prev = rightBlock;
                                }
                                else
                                {
                                    // if right block is zero then
                                    // we only add middle block
                                    prev = blocks[i];
                                }
                            }
                            else if (blocks[i].Hashing == DataBlockHashing.Hash)
                            {
                                // Let's assume that hashing is always less important as it is default.
                                int leftBlockEndOffset = prev.Offset + prev.Size;
                                int middleBlockEndOffset = blocks[i].Offset + blocks[i].Size;
                                int middleBlockSize = middleBlockEndOffset - leftBlockEndOffset;
                                if (middleBlockSize > 0)
                                {
                                    ret.Add(prev);
                                    prev.Name = blocks[i].Name;
                                    prev.Offset = leftBlockEndOffset;
                                    prev.Size = middleBlockSize;
                                }
                                // else do nothing
                            }
                            else
                            {
                                // here we have to fight HashZeros vs Skip
                                throw new NotImplementedException(string.Format("Incompatible intersecting blocks. {0} and {1}.", prev.Hashing, blocks[i].Hashing));
                            }
                        }
                    }
                } // if (are intersecting?)
                else
                {
                    // are not intersecting
                    if (prev.Size > 0)
                    {
                        ret.Add(prev);
                    }
                    prev = blocks[i];
                }
            } // for

            // add the remaining element
            if (prev.Size > 0)
            {
                ret.Add(prev);
            }

            return ret;
        }

        private static string GetPublicKeyToken(byte[] publicKey)
        {
            byte[] ret = new byte[8];
            HashAlgorithm sha1 = SHA1.Create();

            sha1.TransformFinalBlock(publicKey, 0, publicKey.Length);

            for (int i = 0; i < 8; i++)
            {
                ret[i] = sha1.Hash[sha1.Hash.Length - i - 1];
            }
            
            return ByteArrayToString(ret);
        }

        private static string ByteArrayToString(byte[] t)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(string.Format("{0:x2}", t[i]));
            }
            return sb.ToString();
        }

        private Stream _peStream;

        public bool IsValidAssembly { get; private set; }
        public bool HasStrongNameSignedFlag { get { return CorFlagsValue.HasFlag(CorFlags.StrongNameSigned); } }

        public int CorFlagsOffset { get; private set; }
        public int CorFlagsSize { get { return 4; /*sizeof(UInt32)*/ } }
        public CorFlags CorFlagsValue { get; private set; }

        public int ChecksumOffset { get; private set; }
        public int ChecksumSize { get { return 4; /*sizeof(UInt32)*/ } }

        public int StrongNameSignatureDirectoryHeaderOffset { get; private set; }
        public int StrongNameSignatureDirectoryHeaderSize { get { return 8; /*sizeof(RVA) + sizeof(Size) = sizeof(UInt32) + sizeof(UInt32)*/ } }

        public bool HasStrongNameSignatureDirectory { get; private set; }
        public int StrongNameSignatureDirectoryOffset { get; private set; }
        public int StrongNameSignatureDirectorySize { get; private set; }

        public int CertificateTableDirectoryHeaderOffset { get; private set; }
        public int CertificateTableDirectoryHeaderSize { get { return 8; /*sizeof(RVA) + sizeof(Size) = sizeof(UInt32) + sizeof(UInt32)*/ } }

        public bool HasCertificateTableDirectory { get; private set; }
        public int CertificateTableDirectoryOffset { get; private set; }
        public int CertificateTableDirectorySize { get; private set; }

        public int SectionsHeadersEndOffset { get; private set; }
        public int NumberOfSections { get; private set; }
        public int SectionsStartOffset { get; private set; }
        public int PaddingBetweenTheSectionHeadersAndSectionsOffset { get { return SectionsHeadersEndOffset; } }
        public int PaddingBetweenTheSectionHeadersAndSectionsSize { get { return SectionsStartOffset - SectionsHeadersEndOffset; } }

        public List<DataBlock> SpecialHashingBlocks { get; private set; }

        public byte[] PublicKeyBlob { get; private set; }
        public PublicKey PublicKey { get; private set; }
        public string PublicKeyToken { get; private set; }
        public AssemblyHashAlgorithm HashAlgorithm { get; private set; }
    }
}
