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
    internal static class elf_sections
    {
        static internal void ReadSections(byte[] AssemblyData, ulong Offset, ulong EntrySize, ulong EntryCount, ulong StringTableIndex, Elf.Assembly Assembly)
        {
            for (ulong n = 0; n < EntryCount; n++)
            {
                ReadSection(AssemblyData, Offset, Assembly);
                Offset += EntrySize;
            }
            if (Assembly.Sections.Count > (int)StringTableIndex)
            {
                Elf.Section StringSection = Assembly.Sections[(int)StringTableIndex];
                for (int n = 0; n < Assembly.Sections.Count; n++)
                {
                    if (n == 0 && Assembly.Sections[0].__sh_name == 0) { continue; }
                    ulong offset = (StringSection.__sh_offset) + (Assembly.Sections[n].__sh_name);
                    Assembly.Sections[n]._Name = elf_parser.ReadASCIIZ(AssemblyData, offset);
                }
            }

            // Find the dynamic sym section
            Elf.Section SymTable = null;
            Elf.Section DynSym = null;
            Elf.Section Dynamic = null;

            Elf.Section GotPlt = null;
            Elf.Section Got = null;
            Elf.Section Plt = null;
            Elf.Section DynamicRelocations_Type0 = null;
            Elf.Section PltRelocations_Type0 = null;
            Elf.Section DynamicRelocations_Type1 = null;
            Elf.Section PltRelocations_Type1 = null;



            for (int n = 0; n < Assembly.Sections.Count; n++)
            {
                if (Assembly.Sections[n]._Name == ".dynsym")
                {
                    DynSym = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".symtab")
                {
                    SymTable = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".got.plt")
                {
                    GotPlt = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".got")
                {
                    Got = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".plt")
                {
                    Plt = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".rel.dyn")
                {
                    DynamicRelocations_Type0 = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".rela.dyn")
                {
                    DynamicRelocations_Type1 = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".rel.plt")
                {
                    PltRelocations_Type0 = Assembly.Sections[n];
                    continue;
                }
                if (Assembly.Sections[n]._Name == ".rela.plt")
                {
                    PltRelocations_Type1 = Assembly.Sections[n];
                }
                if (Assembly.Sections[n]._Name == ".dynamic")
                {
                    Dynamic = Assembly.Sections[n];
                }
            }
            if (SymTable != null)
            {
                elf_symbol.ReadSymbolsTable(AssemblyData, SymTable.__sh_offset, SymTable.__sh_size, SymTable, Assembly);
            }
            if (DynSym != null)
            {
                elf_symbol.ReadSymbolsTable(AssemblyData, DynSym.__sh_offset, DynSym.__sh_size, DynSym, Assembly);
            }
            if (Got != null)
            {
                elf_got.ReadGot(AssemblyData, Got.__sh_offset, Got.__sh_size, Got, Assembly);
            }
            if (DynamicRelocations_Type0 != null)
            {
                elf_relocation.ReadRelocations(AssemblyData, DynamicRelocations_Type0.__sh_offset, DynamicRelocations_Type0.__sh_size, false, DynamicRelocations_Type0, Assembly);
            }
            if (DynamicRelocations_Type1 != null)
            {
                elf_relocation.ReadRelocations(AssemblyData, DynamicRelocations_Type1.__sh_offset, DynamicRelocations_Type1.__sh_size, true, DynamicRelocations_Type1, Assembly);
            }

            if (PltRelocations_Type0 != null)
            {
                elf_relocation.ReadRelocations(AssemblyData, PltRelocations_Type0.__sh_offset, PltRelocations_Type0.__sh_size, false, PltRelocations_Type0, Assembly);
            }
            if (PltRelocations_Type1 != null)
            {
                elf_relocation.ReadRelocations(AssemblyData, PltRelocations_Type1.__sh_offset, PltRelocations_Type1.__sh_size, true, PltRelocations_Type1, Assembly);
            }
            if (Dynamic != null)
            {
                ReadDependencies(AssemblyData, Dynamic.__sh_offset, Dynamic.__sh_size, Dynamic, Assembly);
            }
        }

        static internal void ReadSection(byte[] AssemblyData, ulong Offset, Elf.Assembly Assembly)
        {
            Elf.Section Section = new Elf.Section();
            if (Assembly.Class == Elf.AssemblyClass.BIG_ENDIAN_64BITS || Assembly.Class == Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
            {
                Section.__sh_name = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_type = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_flags = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                Section.__sh_addr = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                Section.__sh_offset = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                Section.__sh_size = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                Section.__sh_link = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_info = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_addralign = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                Section.__sh_entsize = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
            }
            else
            {
                Section.__sh_name = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_type = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_flags = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_addr = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_offset = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_size = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_link = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_info = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_addralign = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                Section.__sh_entsize = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
            }

            if ((Section.__sh_flags & 0x2) != 0x0)
            {
                Section._Protection = Section._Protection | Elf.MemoryProtection.READ;
                if ((Section.__sh_flags & 0x1) != 0x0) { Section._Protection = Section._Protection | Elf.MemoryProtection.WRITE; }
                if ((Section.__sh_flags & 0x4) != 0x0) { Section._Protection = Section._Protection | Elf.MemoryProtection.EXECUTE; }
            }

            Assembly.Sections.Add(Section);
        }

        static void ReadDependencies(byte[] AssemblyData, ulong Offset, ulong Size, Elf.Section Parent, Elf.Assembly Assembly)
        {
            // Find the string table
            Elf.Section StringTable = null;

            for (int n = 0; n < Assembly.Sections.Count; n++)
            {
                if (Assembly.Sections[n]._Name == ".strtab" || Assembly.Sections[n]._Name == ".dynstr" || Assembly.Sections[n]._Name == ".dynstrtab")
                {
                    StringTable = Assembly.Sections[n];
                    break;
                }
            }

            ulong end = Offset + Size;
            while (Offset < end)
            {
                if (Assembly.Class == Elf.AssemblyClass.BIG_ENDIAN_64BITS ||
                    Assembly.Class == Elf.AssemblyClass.LITTLE_ENDIAN_64BITS)
                {
                    ulong d_val = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    ulong d_ptr = elf_parser.ReadQWord(AssemblyData, Offset, Assembly); Offset += 8;
                    if (d_val != 0)
                    {
                        switch (d_val)
                        {
                            case 1:
                                {
                                    if (d_ptr != 0 && StringTable != null)
                                    {
                                        ulong nameoffset = StringTable.__sh_offset + d_ptr;
                                        string dep = elf_parser.ReadASCIIZ(AssemblyData, nameoffset);
                                        Assembly.Dependencies.Add(dep);
                                    }
                                    break;
                                }
                        }
                    }
                }
                else
                {
                    ulong d_val = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    ulong d_ptr = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    ulong d_off = elf_parser.ReadDWord(AssemblyData, Offset, Assembly); Offset += 4;
                    if (d_val != 0)
                    {
                        switch (d_val)
                        {
                            case 1:
                                {
                                    if (d_ptr != 0 && StringTable != null)
                                    {
                                        ulong nameoffset = StringTable.__sh_offset + d_ptr;
                                        string dep = elf_parser.ReadASCIIZ(AssemblyData, nameoffset);
                                        Assembly.Dependencies.Add(dep);
                                    }
                                    break;
                                }
                        }
                    }

                }
            }
        }
    }
}
