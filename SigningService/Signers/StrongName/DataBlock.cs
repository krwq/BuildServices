using System;

namespace SigningService.Signers.StrongName
{
    internal struct DataBlock : IComparable<DataBlock>
    {
        public DataBlock(DataBlockHashing hashing, string name, int offset, int size)
        {
            Hashing = hashing;
            Name = name;
            Offset = offset;
            Size = size;
        }

        public DataBlockHashing Hashing;
        public string Name;
        public int Offset;
        public int Size;

        public int CompareTo(DataBlock other)
        {
            return Offset.CompareTo(other.Offset);
        }
    }
}
