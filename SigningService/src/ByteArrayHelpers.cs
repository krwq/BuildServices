using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SigningService
{
    internal static class ByteArrayHelpers
    {
        public static bool IsSubArray(byte[] array, int arrayOffset, byte[] subArray)
        {
            if (arrayOffset + subArray.Length > array.Length)
            {
                return false;
            }

            for (int i = 0; i < subArray.Length; i++)
            {
                if (array[arrayOffset + i] != subArray[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static void ReverseInplace(byte[] bytes)
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

        public static UInt32 ReadUInt32AtOffset(byte[] bytes, int offset, int size = 4)
        {
            if (size < 0 || size > 4 || offset < 0)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return 0xFFFFFFFF;
            }

            if (offset + size > bytes.Length)
            {
                ExceptionsHelper.ThrowBadFormatException();
                return 0xFFFFFFFF;
            }

            UInt32 ret = 0;
            for (int i = 0; i < size; i++)
            {
                ret += (UInt32)(bytes[offset + i]) << (i * 8);
            }
            return ret;
        }

        public static bool ArraysEqual(byte[] a, byte[] b)
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