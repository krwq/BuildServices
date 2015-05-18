using System;

namespace SigningService
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
    public class PublicKey : IEquatable<PublicKey>
    {
        private static readonly byte[] Prefix = new byte[] { 0x06, 0x02, 0x00, 0x00 };
        private static readonly byte[] RSA1 = new byte[] { (byte)'R', (byte)'S', (byte)'A', (byte)'1' };

        public PublicKey(UInt32 exponent, byte[] modulus)
        {
            Exponent = exponent;
            Modulus = modulus;
        }

        public PublicKey(byte[] exponent, byte[] modulus)
        {
            Exponent = ByteArrayHelpers.ReadUInt32AtOffset(exponent, 0, exponent.Length);
            Modulus = modulus;
        }

        public PublicKey(byte[] publicKeyBlob)
        {
            // Searching for prefix
            int offset = 0;
            if (!ByteArrayHelpers.IsSubArray(publicKeyBlob, offset, Prefix))
            {
                // We probably found optional header
                offset += 12;
                if (!ByteArrayHelpers.IsSubArray(publicKeyBlob, offset, Prefix))
                {
                    ExceptionsHelper.ThrowBadFormatException();
                    return;
                }
            }

            // Searching for RSA1 bytes
            offset += 8;
            if (!ByteArrayHelpers.IsSubArray(publicKeyBlob, offset, RSA1))
            {
                ExceptionsHelper.ThrowBadFormatException();
                return;
            }

            offset += 4;
            UInt32 modulusSize = ByteArrayHelpers.ReadUInt32AtOffset(publicKeyBlob, offset);
            modulusSize /= 8;

            offset += 4;
            Exponent = ByteArrayHelpers.ReadUInt32AtOffset(publicKeyBlob, offset);

            offset += 4;
            if (publicKeyBlob.Length != offset + modulusSize)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return;
            }

            byte[] modulus = new byte[modulusSize];
            Array.Copy(publicKeyBlob, offset, modulus, 0, modulusSize);
            ByteArrayHelpers.ReverseInplace(modulus);
            Modulus = modulus;
        }

        public UInt32 Exponent { get; private set; }
        public byte[] Modulus { get; private set; }

        public bool Equals(PublicKey other)
        {
            if (other == null)
            {
                return false;
            }

            return Exponent == other.Exponent && ByteArrayHelpers.ArraysEqual(Modulus, other.Modulus);
        }
    }
}