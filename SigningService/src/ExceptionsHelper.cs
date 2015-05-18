namespace SigningService
{
    internal static class ExceptionsHelper
    {
        public static void ThrowPositionMismatch(long expectedPosition, long actualPosition)
        {
            throw new StrongNameSignerException("Position mismatch! Expected position: {0}, Actual position: {1}", expectedPosition, actualPosition);
        }

        public static void ThrowDataBlockHashingValueIsInvalid(DataBlockHashing value)
        {
            throw new StrongNameSignerException("DataBlockHashing value is invalid! (int)Value = {0}", (int)value);
        }

        public static void ThrowBadFormatException()
        {
            throw new StrongNameSignerException("Bad format exception!");
        }

        public static void ThrowPEImageHasNoSections()
        {
            throw new StrongNameSignerException("PE Image has no sections!");
        }

        public static void ThrowAssemblyAlreadySigned()
        {
            throw new StrongNameSignerException("Assembly is already signed!");
        }

        public static void ThrowUnexpectedEndOfStream(long position)
        {
            throw new StrongNameSignerException("Unexpected end of stream on position {0}!");
        }

        public static void ThrowNoStrongNameSignature()
        {
            throw new StrongNameSignerException("Assembly is not strong name signed!");
        }

        public static void ThrowNoStrongNameSignatureDirectory()
        {
            throw new StrongNameSignerException("Assembly does not have strong name signature directory!");
        }

        public static void ThrowStrongNameSignatureDirectorySizeIsDifferentThanProvidedSignature(long strongNameSignatureSize, long signatureSize)
        {
            throw new StrongNameSignerException("Assembly has different strong name signature directory size than provided signature! Strong name signature directory size: {0}. Size of provided signature: {1}", strongNameSignatureSize, signatureSize);
        }

        public static void ThrowCannotWriteToStream()
        {
            throw new StrongNameSignerException("Stream is not writable!");
        }
    }
}
