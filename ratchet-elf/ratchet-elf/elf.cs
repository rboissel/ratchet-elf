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
using System.Collections.Generic;

namespace Ratchet.IO.Format
{
    /// <summary>
    /// This class provides a set of feature to manipulate elf binary files
    /// </summary>
    public static class Elf
    {
        public abstract class Mapper
        {
            public abstract IntPtr MapMemory(ulong Size, MemoryProtection Protection);
            public abstract void UnmapMemory(IntPtr Pointer, ulong Size);
            public abstract IntPtr ChangeMemoryProtection(IntPtr Pointer, ulong Size, MemoryProtection Protection);
            public virtual void Copy(byte[] Source, ulong Offset, ulong Size, IntPtr Destination) { System.Runtime.InteropServices.Marshal.Copy(Source, (int)Offset, Destination, (int)Size); }
        }

        public class Assembly
        {
            internal byte[] _Data = null;
            List<Section> _Sections = new List<Section>();
            internal IntPtr _MappedAddress = new IntPtr();

            /// <summary>
            /// Return a list of all the section in this executable.
            /// </summary>
            /// <remarks>
            /// If the application want to write to the list as well a lock on the assembly must be held for read and write operation.
            /// Internal method using this list will respect this rule as well and can be use in such scenarios.
            /// </remarks>
            public List<Section> Sections { get { return _Sections; } }

            List<Symbol> _Symbols = new List<Symbol>();

            /// <summary>
            /// Return a list of all the symbols in this executable.
            /// </summary>
            /// <remarks>
            /// If the application want to write to the list as well a lock on the assembly must be held for read and write operation.
            /// Internal method using this list will respect this rule as well and can be use in such scenarios.
            /// </remarks>
            public List<Symbol> Symbols { get { return _Symbols; } }

            List<Relocation> _Relocations = new List<Relocation>();

            /// <summary>
            /// Return a list of all the Relocations in this executable.
            /// </summary>
            /// <remarks>
            /// If the application want to write to the list as well a lock on the assembly must be held for read and write operation.
            /// Internal method using this list will respect this rule as well and can be use in such scenarios.
            /// </remarks>
            public List<Relocation> Relocations { get { return _Relocations; } }


            internal HashSet<string> _Dependencies = new HashSet<string>();

            /// <summary>
            /// Return all the dependencis of this executable.
            /// </summary>
            /// <remarks>
            /// If the application want to write to the set as well a lock on the assembly must be held for read and write operation.
            /// Internal method using this list will respect this rule as well and can be use in such scenarios.
            /// </remarks>
            public HashSet<string> Dependencies { get { return _Dependencies; } }

            GlobalOffsetTable _GOT = new GlobalOffsetTable();
            /// <summary>
            /// Get the global offset table (GOT) of this executable
            /// </summary>
            public GlobalOffsetTable GlobalOffsetTable { get { return _GOT; } }

            internal AssemblyClass _Class;
            /// <summary>
            /// Get the assembly class (big endian, little endian, 32 bits, 64 bits ...)
            /// </summary>
            public AssemblyClass Class { get { return _Class; } }

            /// <summary>
            /// Find the section associated to an address.
            /// </summary>
            /// <param name="Address">The requested address</param>
            /// <param name="BaseAddress">The address where the executable is supposed to have been mapped</param>
            /// <returns>The section containing the address or null</returns>
            public Section FindSectionFromAddress(IntPtr Address, IntPtr BaseAddress)
            {
                if (Address.ToInt64() < BaseAddress.ToInt64()) { throw new Exception("Invalid address"); }
                Address = new IntPtr(Address.ToInt64() - BaseAddress.ToInt64());
                lock (this)
                {
                    foreach (Section section in _Sections)
                    {
                        if (section.__sh_addr == 0) continue;
                        if ((ulong)Address.ToInt64() >= section.__sh_addr &&
                            (ulong)Address.ToInt64() < section.__sh_addr + section.__sh_size)
                        {
                            return section;
                        }
                    }
                }
                return null;
            }

            public void Map(Mapper Mapper) { elf_mapper.MapAssembly(this, Mapper); }
        }

        public class GlobalOffsetTable
        {
            internal Dictionary<ulong, ulong> _Locations = new Dictionary<ulong, ulong>();

            /// <summary>
            /// Return a list of all the locations in the GOT.
            /// </summary>
            /// <remarks>
            /// If the application want to write to the list as well a lock on the got must be held for read and write operation.
            /// Internal method using this list will respect this rule as well and can be use in such scenarios.
            /// </remarks>
            public Dictionary<ulong, ulong> Locations { get { return _Locations; } }
        }

        public class Symbol
        {
            internal ulong __st_name = 0;
            internal ulong __st_value = 0;
            internal ulong __st_size = 0;
            internal ulong __st_info = 0;
            internal ulong __st_info_bind = 0;
            internal ulong __st_info_type = 0;
            internal ulong __st_other = 0;
            internal ulong __st_shndx = 0;

            internal IntPtr _MappedAddress = new IntPtr();
            internal Section _Section = null;

            internal SymbolType _Type = SymbolType.STT_NOTYPE;

            /// <summary>
            /// Get the type associated to this symbol
            /// </summary>
            public SymbolType Type { get { return _Type; } }
            internal ulong _Section_Offset = 0;

            internal string _Name = "";
            /// <summary>
            /// Get the name of this symbol
            /// </summary>
            public string Name { get { return _Name; } }

            internal Assembly _Assembly = null;
            public override string ToString()
            {
                return _Name;
            }

        }

        public class Section
        {
            internal bool __StringTable = false;
            internal ulong __sh_name = 0;
            internal ulong __sh_type = 0;
            internal ulong __sh_flags = 0;
            internal ulong __sh_addr = 0;
            internal ulong __sh_offset = 0;
            internal ulong __sh_size = 0;
            internal ulong __sh_link = 0;
            internal ulong __sh_info = 0;
            internal ulong __sh_addralign = 0;
            internal ulong __sh_entsize = 0;

            internal IntPtr _MappedAddress = new IntPtr();

            internal MemoryProtection _Protection = MemoryProtection.NO_ACCESS;

            /// <summary>
            /// Get the requested memory protection for this section
            /// </summary>
            public MemoryProtection Protection { get { return _Protection; } }

            internal string _Name = "";
            /// <summary>
            /// Get the name of this section
            /// </summary>
            public string Name { get { return _Name; } }

            internal List<Symbol> _Symbols = new List<Symbol>();

            public Section() { }
            public override string ToString()
            {
                return _Name;
            }
        }

        public class Relocation
        {
            internal ulong _r_Offset;
            internal long _r_AddEnd;
            internal ulong _r_Symbols;

            internal Symbol _Symbol;
            internal RelocationType _Type;
            internal Section _SymbolSection;
            internal Section _TargetSection;

        }

        public enum AssemblyClass
        {
            LITTLE_ENDIAN_32BITS,
            LITTLE_ENDIAN_64BITS,
            BIG_ENDIAN_32BITS,
            BIG_ENDIAN_64BITS,
        }

        public enum SymbolType
        {
            STT_NOTYPE,
            STT_OBJECT,
            STT_FUNC,
            STT_SECTION,
            STT_FILE,
            STT_LOPROC,
            STT_HIPROC
        }

        public enum RelocationType
        {
            R_NONE,
            R_32,
            R_PC32,
            R_GOT32,
            R_PLT32,
            R_COPY,
            R_GLOB_DAT,
            R_JMP_SLOT,
            R_RELATIVE,
            R_GOTOOFF,
            R_GOTPC,

            R_64,
            R_GOTPCREL,
            R_32S,
            R_16,
            R_PC16,
            R_8,
            R_PC8,
            R_DTPMOD64,
            R_DTPOFF64,
            R_TPOFF64,
            R_TLSGD,
            R_TLSLD,
            R_DTPOFF32,
            R_GOTTPOFF,
            R_TPOFF32,
            R_PC64,
            R_GOTOFF64,
            R_GOTPC32,
            R_SIZE32,
            R_SIZE64,
            R_GOTPC32_TLSDESC,
            R_TLSDESC_ALL,
            R_TLSDESC,
            R_IRELATIVE
        }

        public enum MemoryProtection
        {
            NO_ACCESS = 0x0,
            READ = 0x1,
            WRITE = 0x2,
            EXECUTE = 0x4
        }

        /// <summary>
        /// Parse an elf assembly and return the parsed result
        /// </summary>
        /// <param name="AssemblyData">A byte array containing the elf file</param>
        /// <returns>the parsed assembly</returns>
        public static Assembly Read(byte[] AssemblyData)
        {
            if (AssemblyData.Length < 0x32) { return null; }
            bool _64bits = false;
            bool littleEndian = true;
            switch (AssemblyData[4])
            {
                case 1: _64bits = false; break;
                case 2: _64bits = true; if (AssemblyData.Length < 0x3E) { return null; }; break;
                default: return null;
            }
            
            switch (AssemblyData[5])
            {
                case 1: littleEndian = true; break;
                case 2: littleEndian = false; break;
                default: return null;
            }

            Assembly assembly = new Assembly();
            assembly._Data = (byte[])AssemblyData.Clone();
            if (_64bits)
            {
                if (littleEndian) { assembly._Class = AssemblyClass.LITTLE_ENDIAN_64BITS; }
                else { assembly._Class = AssemblyClass.BIG_ENDIAN_64BITS; }
            }
            else
            {
                if (littleEndian) { assembly._Class = AssemblyClass.LITTLE_ENDIAN_32BITS; }
                else { assembly._Class = AssemblyClass.BIG_ENDIAN_32BITS; }
            }

            ulong SectionTablePtr = 0;
            ulong SectionTableEntrySize = 0;
            ulong SectionTableEntryCount = 0;
            ulong SectionStringIndex = 0;

            ulong entryPoint = 0;

            if (_64bits) { entryPoint = elf_parser.ReadQWord(AssemblyData, 0x18, assembly); }
            else { entryPoint = elf_parser.ReadDWord(AssemblyData, 0x18, assembly); }

            if (entryPoint > 0)
            {
                Elf.Symbol entryPointSymbol = new Elf.Symbol();
                entryPointSymbol._Assembly = assembly;
                entryPointSymbol._Name = "_start";
                entryPointSymbol.__st_value = entryPoint;
            }

            if (_64bits)
            {
                SectionTablePtr = elf_parser.ReadQWord(AssemblyData, 0x28, assembly);
                SectionTableEntrySize = elf_parser.ReadWord(AssemblyData, 0x3A, assembly);
                SectionTableEntryCount = elf_parser.ReadWord(AssemblyData, 0x3C, assembly);
                SectionStringIndex = elf_parser.ReadWord(AssemblyData, 0x3E, assembly);
            }
            else
            {
                SectionTablePtr = elf_parser.ReadDWord(AssemblyData, 0x20, assembly);
                SectionTableEntrySize = elf_parser.ReadWord(AssemblyData, 0x2E, assembly);
                SectionTableEntryCount = elf_parser.ReadWord(AssemblyData, 0x30, assembly);
                SectionStringIndex = elf_parser.ReadWord(AssemblyData, 0x32, assembly);
            }

            elf_sections.ReadSections(AssemblyData, SectionTablePtr, SectionTableEntrySize, SectionTableEntryCount, SectionStringIndex, assembly);
            return assembly;
        }
    }
}
