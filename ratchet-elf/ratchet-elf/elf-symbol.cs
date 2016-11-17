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
    internal static class elf_symbol
    {

        static Elf.SymbolType ToSymbolType(ulong Type)
        {
            switch (Type)
            {
                case 0: return Elf.SymbolType.STT_NOTYPE;
                case 1: return Elf.SymbolType.STT_OBJECT;
                case 2: return Elf.SymbolType.STT_FUNC;
                case 3: return Elf.SymbolType.STT_SECTION;
                case 4: return Elf.SymbolType.STT_FILE;
                case 13: return Elf.SymbolType.STT_LOPROC;
                case 15: return Elf.SymbolType.STT_HIPROC;
                default: return Elf.SymbolType.STT_NOTYPE;
            }
        }

        static internal void ReadSymbolsTable(byte[] AssemblyData, ulong Offset, ulong Size, Elf.Section Parent, Elf.Assembly Assembly)
        {
            // Find the symbol string table
            Elf.Section StringTable = null;

            for (int n = 0; n < Assembly.Sections.Count; n++)
            {
                if (Parent._Name == ".symtab" && Assembly.Sections[n]._Name == ".strtab")
                {
                    StringTable = Assembly.Sections[n];
                    break;
                }
                if (Parent._Name == ".dynsym" && Assembly.Sections[n]._Name == ".dynstr")
                {
                    StringTable = Assembly.Sections[n];
                    break;
                }
                /* As specified in the arm documentation */
                if (Parent._Name == ".dynsym" && Assembly.Sections[n]._Name == ".dynstrtab")
                {
                    StringTable = Assembly.Sections[n];
                    break;
                }
            }
            ulong end = Offset + Size;
            while (Offset < end)
            {
                Elf.Symbol Symbol = new Elf.Symbol();
                Symbol._Section_Offset = Offset - Parent.__sh_offset;
                Symbol._Section = Parent;
                if (Assembly.Class == Elf.AssemblyClass.BIG_ENDIAN_64BITS ||
                    Assembly.Class == Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
                {
                    Symbol.__st_name = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    Symbol.__st_info = AssemblyData[(int)Offset]; Offset += 1;
                    Symbol.__st_other = AssemblyData[(int)Offset]; Offset += 1;
                    Symbol.__st_shndx = elf_parser.ReadWord(AssemblyData, Offset, Assembly); Offset += 2;
                    Symbol.__st_value = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    Symbol.__st_size = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;

                    Symbol.__st_info_bind = Symbol.__st_info >> 4;
                    Symbol.__st_info_type = Symbol.__st_info & 0xF;
                    Symbol._Type = ToSymbolType(Symbol.__st_info_type);

                }
                else
                {
                    Symbol.__st_name = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    Symbol.__st_value = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    Symbol.__st_size = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    Symbol.__st_info = AssemblyData[(int)Offset]; Offset += 1;
                    Symbol.__st_other = AssemblyData[(int)Offset]; Offset += 1;
                    Symbol.__st_shndx = elf_parser.ReadWord(AssemblyData, Offset, Assembly); Offset += 2;

                    Symbol.__st_info_bind = Symbol.__st_info >> 4;
                    Symbol.__st_info_type = Symbol.__st_info & 0xF;
                    Symbol._Type = ToSymbolType(Symbol.__st_info_type);
                }
                if (Symbol.__st_name != 0 && StringTable != null)
                {
                    ulong nameoffset = StringTable.__sh_offset + Symbol.__st_name;
                    Symbol._Name = elf_parser.ReadASCIIZ(AssemblyData, nameoffset);
                }
                Assembly.Symbols.Add(Symbol);
                Parent._Symbols.Add(Symbol);
            }
        }
    }
}
