/*                                                                           *
 * Copyright © 2016, Raphaël Boissel                                         *
 * Permission is hereby granted, free of charge, to any person obtaining     *
 * a copy of this software and associated documentation files, to deal in    *
 * the Software without restriction, including without limitation the        *
 * rights to use, copy, modify, merge, publish, distribute, sublicense,      *
 * and/or sell copies of the Software, and to permit persons to whom the     *
 * Software is furnished to do so, subject to the following conditions:      *
 *                                                                           *
 * - The above copyright notice and this permission notice shall be          *
 *   included in all copies or substantial portions of the Software.         *
 * - The Software is provided "as is", without warranty of any kind,         *
 *   express or implied, including but not limited to the warranties of      *
 *   merchantability, fitness for a particular purpose and noninfringement.  *
 *   In no event shall the authors or copyright holders. be liable for any   *
 *   claim, damages or other liability, whether in an action of contract,    *
 *   tort or otherwise, arising from, out of or in connection with the       *
 *   software or the use or other dealings in the Software.                  *
 * - Except as contained in this notice, the name of Raphaël Boissel shall   *
 *   not be used in advertising or otherwise to promote the sale, use or     *
 *   other dealings in this Software without prior written authorization     *
 *   from Raphaël Boissel.                                                   *
 *                                                                           */

namespace Ratchet.IO.Format
{
    static class elf_parser
    {
        static internal ulong ReadWord(byte[] AssemblyData, ulong Offset, Elf.Assembly Elf)
        {
            if (Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_32BITS ||
                Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
            {
                return (ulong)AssemblyData[Offset] +
                       (ulong)AssemblyData[Offset + 1] * 0x100;
            }
            else
            {
                return (ulong)AssemblyData[Offset] * 0x100 +
                       (ulong)AssemblyData[Offset + 1];
            }
        }

        static internal ulong ReadDWord(byte[] AssemblyData, ulong Offset, Elf.Assembly Elf)
        {
            if (Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_32BITS ||
                Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
            {
                return (ulong)AssemblyData[Offset] +
                       (ulong)AssemblyData[Offset + 1] * 0x100 +
                       (ulong)AssemblyData[Offset + 2] * 0x10000 +
                       (ulong)AssemblyData[Offset + 3] * 0x1000000;
            }
            else
            {
                return (ulong)AssemblyData[Offset + 3] +
                       (ulong)AssemblyData[Offset + 2] * 0x100 +
                       (ulong)AssemblyData[Offset + 1] * 0x10000 +
                       (ulong)AssemblyData[Offset] * 0x1000000;
            }
        }

        static internal ulong ReadQWord(byte[] AssemblyData, ulong Offset, Elf.Assembly Elf)
        {
            if (Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_32BITS ||
                Elf.Class == Format.Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
            {
                return (ulong)AssemblyData[Offset] +
                       (ulong)AssemblyData[Offset + 1] * 0x100 +
                       (ulong)AssemblyData[Offset + 2] * 0x10000 +
                       (ulong)AssemblyData[Offset + 3] * 0x1000000 +
                       (ulong)AssemblyData[Offset + 4] * 0x100000000 +
                       (ulong)AssemblyData[Offset + 5] * 0x10000000000 +
                       (ulong)AssemblyData[Offset + 6] * 0x1000000000000 +
                       (ulong)AssemblyData[Offset + 7] * 0x100000000000000;
            }
            else
            {
                return (ulong)AssemblyData[Offset + 7] +
                       (ulong)AssemblyData[Offset + 6] * 0x100 +
                       (ulong)AssemblyData[Offset + 5] * 0x10000 +
                       (ulong)AssemblyData[Offset + 4] * 0x1000000 +
                       (ulong)AssemblyData[Offset + 3] * 0x100000000 +
                       (ulong)AssemblyData[Offset + 2] * 0x10000000000 +
                       (ulong)AssemblyData[Offset + 1] * 0x1000000000000 +
                       (ulong)AssemblyData[Offset] * 0x100000000000000;
            }
        }

        static internal string ReadASCIIZ(byte[] AssemblyData, ulong Offset)
        {
            string value = "";
            for (int n = (int)Offset; n < AssemblyData.Length; n++)
            {
                if (AssemblyData[n] == 0) { return value; }
                value += (char)(AssemblyData[n]);
            }
            return value;
        }
    }
}
