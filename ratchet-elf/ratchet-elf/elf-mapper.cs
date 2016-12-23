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
    class elf_mapper
    {
        internal class MapHelper
        {
            IntPtr _Mapping = new IntPtr();
            ulong _PageSize = 4096;


            List<Elf.Section>[] _SectionMap = new List<Elf.Section>[0];

            public IntPtr Mapping { get { return _Mapping; } }

            Elf.Mapper _Mapper;

            public MapHelper(ulong Size, Elf.Mapper Mapper)
            {
                _Mapper = Mapper;
                _Mapping = _Mapper.MapMemory(Size, Elf.MemoryProtection.READ | Elf.MemoryProtection.WRITE);
                if (_Mapping.ToInt64() == 0) { throw new OutOfMemoryException(); }
                _SectionMap = new List<Elf.Section>[(Size + (ulong)_PageSize - 1) / (ulong)_PageSize];
            }

            public IntPtr MapSection(Elf.Section Section)
            {
                IntPtr ptr = new IntPtr((long)Section.__sh_addr + _Mapping.ToInt64());
                ulong page = Section.__sh_addr / _PageSize;
                ulong size = (Section.__sh_size + _PageSize - 1) / _PageSize;
                for (ulong n = page; n < (page + size) && n < (ulong)_SectionMap.Length; n++)
                {
                    if (_SectionMap[n] == null) { _SectionMap[n] = new List<Elf.Section>(); }
                    _SectionMap[n].Add(Section);
                }
                return ptr;
            }

            public void ApplyProtection()
            {
                IntPtr unmapptr = new IntPtr();
                ulong unmapSize = 0;
                for (long n = 0; n < _SectionMap.LongLength; n++)
                {
                    IntPtr ptr = new IntPtr((long)(n * (long)_PageSize) + _Mapping.ToInt64());
                    Elf.MemoryProtection protection = Elf.MemoryProtection.NO_ACCESS;
                    if (_SectionMap[n] != null)
                    {
                        for (int x = 0; x < _SectionMap[n].Count; x++)
                        {
                            protection = protection | _SectionMap[n][x].Protection;
                        }
                    }
                    if (protection == Elf.MemoryProtection.NO_ACCESS)
                    {
                        if (unmapSize == 0)
                        {
                            unmapptr = ptr;
                        }
                        unmapSize += _PageSize;
                    }
                    else
                    {
                        if (unmapSize > 0)
                        {
                            _Mapper.UnmapMemory(unmapptr, unmapSize);
                            unmapSize = 0;
                        }
                        _Mapper.ChangeMemoryProtection(ptr, _PageSize, protection);
                    }
                }
                if (unmapSize > 0)
                {
                    _Mapper.UnmapMemory(unmapptr, unmapSize);

                }
            }
        }

        public static void MapAssembly(Elf.Assembly Assembly, Elf.Mapper Mapper)
        {
            lock (Assembly)
            {

            }
        }

        public static void MapSection(Elf.Assembly Assembly, Elf.Mapper Mapper)
        {
            Elf.Section lastMappedSection = null;


            foreach (Elf.Section section in Assembly.Sections)
            {
                if (section == null) { continue; }
                if (section.__sh_addr != 0 && section._Protection != Elf.MemoryProtection.NO_ACCESS)
                {
                    if (lastMappedSection == null) { lastMappedSection = section; }
                    if (lastMappedSection.__sh_addr + lastMappedSection.__sh_size < section.__sh_addr + section.__sh_size) { lastMappedSection = section; }
                }
            }

            ulong size = lastMappedSection.__sh_size + lastMappedSection.__sh_addr;

            MapHelper mapHelper = new MapHelper(size, Mapper);

            // Now place the section inside the map helper
            foreach (Elf.Section section in Assembly.Sections)
            {
                if (section == null) { continue; }
                if (section.__sh_addr != 0 && section._Protection != Elf.MemoryProtection.NO_ACCESS)
                {
                    section._MappedAddress = mapHelper.MapSection(section);
                    if ((ulong)Assembly._Data.Length < section.__sh_offset + section.__sh_size) { /* Do Nothing */ }
                    else { Mapper.Copy(Assembly._Data, section.__sh_offset, section.__sh_size, section._MappedAddress); }
                }
            }



            mapHelper.ApplyProtection();
            Assembly._MappedAddress = mapHelper.Mapping;
        }
    }
}
