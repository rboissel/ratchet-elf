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
    internal static class elf_got
    {
        static internal void ReadGot(byte[] AssemblyData, ulong Offset, ulong Size, Elf.Section Parent, Elf.Assembly Assembly)
        {
            ulong end = Offset + Size;
            while (Offset < end)
            {
                if (Assembly.Class == Elf.AssemblyClass.LITTLE_ENDIAN_64BITS ||
                    Assembly.Class == Elf.AssemblyClass.BIG_ENDIAN_64BITS)
                {
                    ulong gotOffset = Offset - Parent.__sh_offset;
                    ulong absoluteRef = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    Assembly.GlobalOffsetTable.Locations.Add(gotOffset, absoluteRef);
                }
                else
                {
                    ulong gotOffset = Offset - Parent.__sh_offset;
                    ulong absoluteRef = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    Assembly.GlobalOffsetTable.Locations.Add(gotOffset, absoluteRef);
                }
            }
        }
    }
}
