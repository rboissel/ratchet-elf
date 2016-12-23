using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Ratchet.IO.Format;

namespace readelf
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                System.Console.WriteLine("Usage: readelf [file]");
                System.Environment.Exit(1);
            }

            if (!System.IO.File.Exists(args[0]))
            {
                System.Console.WriteLine("File " + args[0] + " not found");
                System.Environment.Exit(1);
            }

            byte[] data = System.IO.File.ReadAllBytes(args[0]);
            Elf.Assembly assembly = Elf.Read(data);
            Console.WriteLine("dependencies:");
            foreach (string dep in assembly.Dependencies) { Console.WriteLine(" * " + dep); }
            Console.WriteLine("sections:");
            foreach (Elf.Section section in assembly.Sections) { Console.WriteLine(" * " + section.Name); }
            Console.WriteLine("symbols:");
            foreach (Elf.Symbol symbol in assembly.Symbols) { Console.WriteLine(" * " + symbol.Name); }

        }
    }
}
