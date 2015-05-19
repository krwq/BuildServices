namespace SigningService.Extensions
{
    internal static class ByteArrayHelpers
    {
        public static bool ContainsSubarray(this byte[] array, int atOffset, byte[] subArray)
        {
            if (atOffset + subArray.Length > array.Length)
            {
                return false;
            }

            for (int i = 0; i < subArray.Length; i++)
            {
                if (array[atOffset + i] != subArray[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static void ReverseInplace(this byte[] bytes)
        {
            int i = 0, j = bytes.Length - 1;
            while (i < j)
            {
                byte c = bytes[i];
                bytes[i] = bytes[j];
                bytes[j] = c;
                i++;
                j--;
            }
        }

        public static bool IsEquivalentTo(this byte[] a, byte[] b)
        {
            if (a == b)
            {
                return true;
            }

            if (a == null || b == null)
            {
                // since they are not equal
                return false;
            }

            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}