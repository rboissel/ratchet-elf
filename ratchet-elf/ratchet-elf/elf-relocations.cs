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

using System;

namespace Ratchet.IO.Format
{
    class elf_relocation
    {
        static Elf.RelocationType ToRelocationType_32(ulong Value)
        {
            switch (Value)
            {
                case 0: return Elf.RelocationType.R_NONE;
                case 1: return Elf.RelocationType.R_32;
                case 2: return Elf.RelocationType.R_PC32;
                case 3: return Elf.RelocationType.R_GOT32;
                case 4: return Elf.RelocationType.R_PLT32;
                case 5: return Elf.RelocationType.R_COPY;
                case 6: return Elf.RelocationType.R_GLOB_DAT;
                case 7: return Elf.RelocationType.R_JMP_SLOT;
                case 8: return Elf.RelocationType.R_RELATIVE;
                case 9: return Elf.RelocationType.R_GOTOOFF;
                case 10: return Elf.RelocationType.R_GOTPC;
                default: return Elf.RelocationType.R_NONE;
            }
        }

        static Elf.RelocationType ToRelocationType_64(ulong Value)
        {
            switch (Value)
            {
                case 0: return Elf.RelocationType.R_NONE;
                case 1: return Elf.RelocationType.R_64;
                case 2: return Elf.RelocationType.R_PC32;
                case 3: return Elf.RelocationType.R_GOT32;
                case 4: return Elf.RelocationType.R_PLT32;
                case 5: return Elf.RelocationType.R_COPY;
                case 6: return Elf.RelocationType.R_GLOB_DAT;
                case 7: return Elf.RelocationType.R_JMP_SLOT;
                case 8: return Elf.RelocationType.R_RELATIVE;
                case 9: return Elf.RelocationType.R_GOTPCREL;
                case 10: return Elf.RelocationType.R_32;
                case 11: return Elf.RelocationType.R_32S;
                case 12: return Elf.RelocationType.R_16;
                case 13: return Elf.RelocationType.R_PC16;
                case 14: return Elf.RelocationType.R_8;
                case 15: return Elf.RelocationType.R_PC8;
                case 16: return Elf.RelocationType.R_DTPMOD64;
                case 17: return Elf.RelocationType.R_DTPOFF64;
                case 18: return Elf.RelocationType.R_TPOFF64;
                case 19: return Elf.RelocationType.R_TLSGD;
                case 20: return Elf.RelocationType.R_TLSLD;
                case 21: return Elf.RelocationType.R_DTPOFF32;
                case 22: return Elf.RelocationType.R_GOTTPOFF;
                case 23: return Elf.RelocationType.R_TPOFF32;
                case 24: return Elf.RelocationType.R_PC64;
                case 25: return Elf.RelocationType.R_GOTOFF64;
                case 26: return Elf.RelocationType.R_GOTPC32;
                case 32: return Elf.RelocationType.R_SIZE32;
                case 33: return Elf.RelocationType.R_SIZE64;
                case 34: return Elf.RelocationType.R_GOTPC32_TLSDESC;
                case 35: return Elf.RelocationType.R_TLSDESC_ALL;
                case 36: return Elf.RelocationType.R_TLSDESC;
                case 37: return Elf.RelocationType.R_IRELATIVE;
                default: return Elf.RelocationType.R_NONE;
            }
        }

        static internal void ReadRelocations(byte[] AssemblyData, ulong Offset, ulong Size, bool hasAddEnd, Elf.Section Parent, Elf.Assembly Assembly)
        {
            Elf.Section SourceSymbolSection = null;
            Elf.Section DestSection = null;

            if ((ulong)Assembly.Sections.Count > Parent.__sh_link) { SourceSymbolSection = Assembly.Sections[(int)Parent.__sh_link]; }
            if ((ulong)Assembly.Sections.Count > Parent.__sh_info) { DestSection = Assembly.Sections[(int)Parent.__sh_info]; }


            ulong end = Offset + Size;
            while (Offset < end)
            {
                if (Assembly.Class == Elf.AssemblyClass.LITTLE_ENDIAN_64BITS ||
                    Assembly.Class == Elf.AssemblyClass.BIG_ENDIAN_64BITS)
                {
                    ulong r_offset = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    ulong r_info = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    ulong r_sym = r_info >> 32;
                    ulong r_type = r_info & 0xFFFFFFFF;

                    Elf.Symbol symbol = null;
                    if (SourceSymbolSection != null && (ulong)SourceSymbolSection._Symbols.Count > r_sym)
                    { symbol = SourceSymbolSection._Symbols[(int)r_sym]; }
                    Elf.RelocationType type = ToRelocationType_64(r_type);
                    Elf.Section section = DestSection;
                    ulong r_addEnd = 0;

                    if ((DestSection != null && DestSection.__sh_addr == 0) ||
                        r_offset != 0)
                    {
                        // We need to find the true section from the requested mapping
                        section = Assembly.FindSectionFromAddress(new IntPtr((long)r_offset), new IntPtr(0));
                    }

                    if (hasAddEnd)
                    {
                        r_addEnd = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    }
                    Assembly.Relocations.Add(new Elf.Relocation()
                    {
                        _r_AddEnd = (long)r_addEnd,
                        _r_Symbols = r_sym,
                        _r_Offset = r_offset,
                        _Type = type,
                        _Symbol = symbol,
                        _SymbolSection = SourceSymbolSection,
                        _TargetSection = section
                    });
                }
                else
                {
                    ulong r_offset = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    ulong r_info = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    ulong r_sym = r_info >> 8;
                    ulong r_type = r_info & 0xFF;
                    Elf.Symbol symbol = null;
                    if (SourceSymbolSection != null && (ulong)SourceSymbolSection._Symbols.Count > r_sym)
                    { symbol = SourceSymbolSection._Symbols[(int)r_sym]; }
                    Elf.RelocationType type = ToRelocationType_32(r_type);
                    Elf.Section section = DestSection;
                    ulong r_addEnd = 0;

                    if (DestSection != null && DestSection.__sh_addr == 0)
                    {
                        // We need to find the true section from the requested mapping
                        section = Assembly.FindSectionFromAddress(new IntPtr((long)r_offset), new IntPtr(0));
                    }

                    if (hasAddEnd)
                    {
                        r_addEnd = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    }
                    Assembly.Relocations.Add(new Elf.Relocation()
                    {
                        _r_AddEnd = (long)r_addEnd,
                        _r_Symbols = r_sym,
                        _r_Offset = r_offset,
                        _Type = type,
                        _Symbol = symbol,
                        _SymbolSection = SourceSymbolSection,
                        _TargetSection = section
                    });
                }
            }
        }
    }
}
