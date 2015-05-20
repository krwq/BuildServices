using System;

namespace SigningService.Signers.StrongName
{
    internal struct DataBlock : IComparable<DataBlock>
    {
        public DataBlock(DataBlockHashing hashing, string name, int offset, int size) : this()
        {
            Hashing = hashing;
            Name = name;
            Offset = offset;
            Size = size;
        }

        public DataBlockHashing Hashing { get; set; }
        public string Name { get; set; }
        public int Offset { get; set; }
        public int Size { get; set; }

        public int CompareTo(DataBlock other)
        {
            return Offset.CompareTo(other.Offset);
        }
    }
}
