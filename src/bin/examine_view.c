/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2014-2016 Vincent Torri.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#endif

#include <Examine.h>

#include "examine_private.h"
#include "examine_dwarf.h"

#ifdef _WIN32
# define FMT_DWD "%lu"
# define FMT_DWDX "%lx"
# define FMT_DWD8X "%08lx"
# define FMT_LL16X "%016I64x"
#else
# define FMT_DWD "%u"
# define FMT_DWDX "%x"
# define FMT_DWD8X "%08x"
# define FMT_LL16X "%016llx"
#endif

#define EXM_VIEW_DEBUG_SIGNATURE_NB10 0x4e423130 /* NB10 - PDB 2.0 (unsupported since VC6 */
#define EXM_VIEW_DEBUG_SIGNATURE_RSDS 0x53445352 /* RSDS - PDB 7.0 */

#define EXM_VIEW_DLLCHAR_SET(val, str) \
do { \
    if (dllchar & val) \
    { \
        if (is_first) \
        { \
            is_first = 0; \
            *ptr++ = ' '; \
            *ptr++ = '('; \
        } \
        else \
        { \
            *ptr++ = ','; \
            *ptr++ = ' '; \
        } \
        memcpy(ptr, str, strlen(str)); \
        ptr += strlen(str); \
    } \
} while (0)

static char _exm_view_dllcharacteristics[4096];

static const char *
_exm_view_subsystem_get(WORD subsystem)
{
    switch (subsystem)
    {
        case IMAGE_SUBSYSTEM_UNKNOWN:
            return "(Unknown)";
        case IMAGE_SUBSYSTEM_NATIVE:
            return "(Native)";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            return "(Win32 GUI)";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            return "(Win32 CUI)";
        case IMAGE_SUBSYSTEM_OS2_CUI:
            return "(OS/2 CUI)";
        case IMAGE_SUBSYSTEM_POSIX_CUI:
            return "(POSIX CUI)";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
            return "(WinCE CUI)";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:
            return "(EFI Application)";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
            return "(EFI driver - boot service)";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
            return "(EFI driver - runtime service)";
        case IMAGE_SUBSYSTEM_EFI_ROM:
            return "(EFI ROM image)";
        case IMAGE_SUBSYSTEM_XBOX:
            return "(XBOX)";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
            return "(Boot Application)";
        default:
            return "";
    }
}

static const char *
_exm_view_dllcharacteristics_get(WORD dllchar)
{
    char *ptr = _exm_view_dllcharacteristics;
    unsigned char is_first = 1;

    if (!dllchar)
        return "";

#ifdef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "high_entropy_va");
#endif
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "dynamic_base");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "force_integrity");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "nx_compat");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "no_isolation");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_NO_SEH, "no_seh");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_NO_BIND, "no_bind");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "appcontainer");
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "wdm_driver");
#ifdef IMAGE_DLLCHARACTERISTICS_GUARD_CF
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_GUARD_CF, "guard_cf");
#endif
    EXM_VIEW_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "terminal_server_aware");

    if (!is_first)
    {
        *ptr = ')';
        ptr++;
    }

    *ptr = '\0';

    return _exm_view_dllcharacteristics;
}

static void
_exm_view_cmd_dos_header_display(Exm_Pe *pe)
{
    const IMAGE_DOS_HEADER *dos_header;

    dos_header = exm_pe_dos_header_get(pe);
    printf("DOS Header\n");
    printf("  field      type    value\n");
    printf("  e_magic    USHORT  0x%02hx \"%c%c\"\n", dos_header->e_magic, dos_header->e_magic & 0x00ff, (dos_header->e_magic & 0xff00) >> 8);
    printf("  e_cblp     USHORT  0x%02hx\n", dos_header->e_cblp);
    printf("  e_cp       USHORT  0x%hu\n", dos_header->e_cp);
    printf("  e_crlc     USHORT  0x%hu\n", dos_header->e_crlc);
    printf("  e_cparhdr  USHORT  0x%hu\n", dos_header->e_cparhdr);
    printf("  e_minalloc USHORT  0x%02hx\n", dos_header->e_minalloc);
    printf("  e_maxalloc USHORT  0x%02hx\n", dos_header->e_maxalloc);
    printf("  e_ss       USHORT  0x%02hx\n", dos_header->e_ss);
    printf("  e_sp       USHORT  0x%02hx\n", dos_header->e_sp);
    printf("  e_csum     USHORT  0x%02hx\n", dos_header->e_csum);
    printf("  e_ip       USHORT  0x%02hx\n", dos_header->e_ip);
    printf("  e_cs       USHORT  0x%02hx\n", dos_header->e_cs);
    printf("  e_lfarlc   USHORT  0x%02hx\n", dos_header->e_lfarlc);
    printf("  e_ovno     USHORT  0x%02hx\n", dos_header->e_ovno);
    printf("  e_res[4]   USHORT  [0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx]\n",
           dos_header->e_res[0],
           dos_header->e_res[1],
           dos_header->e_res[2],
           dos_header->e_res[3]);
    printf("  e_oemid    USHORT  0x%02hx\n", dos_header->e_oemid);
    printf("  e_oeminfo  USHORT  0x%02hx\n", dos_header->e_oeminfo);
    printf("  e_res2[10] USHORT  [0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx, 0x%02hx]\n",
           dos_header->e_res2[0],
           dos_header->e_res2[1],
           dos_header->e_res2[2],
           dos_header->e_res2[3],
           dos_header->e_res2[4],
           dos_header->e_res2[5],
           dos_header->e_res2[6],
           dos_header->e_res2[7],
           dos_header->e_res2[8],
           dos_header->e_res2[9]);
    printf("  e_lfanew   LONG    0x" FMT_DWD8X "\n", dos_header->e_lfanew);
}

static void
_exm_view_cmd_optional_header_32_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS32 *nt_header;

    nt_header = (const IMAGE_NT_HEADERS32 *)exm_pe_nt_header_get(pe);

    printf("  field                       type    value\n");
    printf("  Magic                       WORD    0x%04hx (PE32)\n", nt_header->OptionalHeader.Magic);
    printf("  MajorLinkerVersion          BYTE    %hu\n", nt_header->OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion          BYTE    %hu\n", nt_header->OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode                  DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData       DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData     DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfUninitializedData);
    printf("  AddressOfEntryPoint         DWORD   0x" FMT_DWD8X "\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode                  DWORD   0x" FMT_DWD8X "\n", nt_header->OptionalHeader.BaseOfCode);
    printf("  BaseOfData                  DWORD   0x" FMT_DWD8X "\n", nt_header->OptionalHeader.BaseOfData);
    printf("  ImageBase                   DWORD   0x" FMT_DWD8X "\n", nt_header->OptionalHeader.ImageBase);
    printf("  SectionAlignment            DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SectionAlignment);
    printf("  FileAlignment               DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion WORD    %u\n", nt_header->OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion WORD    %u\n", nt_header->OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion           WORD    %u\n", nt_header->OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion           WORD    %u\n", nt_header->OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion       WORD    %u\n", nt_header->OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion       WORD    %u\n", nt_header->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue           DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.Win32VersionValue);
    printf("  SizeOfImage                 DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders               DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfHeaders);
    printf("  CheckSum                    DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.CheckSum);
    printf("  Subsystem                   WORD    %u %s\n", nt_header->OptionalHeader.Subsystem, _exm_view_subsystem_get(nt_header->OptionalHeader.Subsystem));
    printf("  DllCharacteristics          WORD    0x%x%s\n", nt_header->OptionalHeader.DllCharacteristics, _exm_view_dllcharacteristics_get(nt_header->OptionalHeader.DllCharacteristics));
    printf("  SizeOfStackReserve          DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackReserve          DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit           DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve           DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit            DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags                 DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes         DWORD   " FMT_DWD "\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);
    printf("  DataDirectory               array\n");
}

static void
_exm_view_cmd_optional_header_64_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS64 *nt_header;

    nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);

    printf("  field                       type      value\n");
    printf("  Magic                       WORD      0x%04hx (PE32+)\n", nt_header->OptionalHeader.Magic);
    printf("  MajorLinkerVersion          BYTE      %hu\n", nt_header->OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion          BYTE      %hu\n", nt_header->OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode                  DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData       DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData     DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SizeOfUninitializedData);
    printf("  AddressOfEntryPoint         DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode                  DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.BaseOfCode);
    printf("  ImageBase                   ULONGLONG 0x" FMT_LL16X "\n", nt_header->OptionalHeader.ImageBase);
    printf("  SectionAlignment            DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SectionAlignment);
    printf("  FileAlignment               DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion WORD      %u\n", nt_header->OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion WORD      %u\n", nt_header->OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion           WORD      %u\n", nt_header->OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion           WORD      %u\n", nt_header->OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion       WORD      %u\n", nt_header->OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion       WORD      %u\n", nt_header->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue           DWORD     " FMT_DWD "\n", nt_header->OptionalHeader.Win32VersionValue);
    printf("  SizeOfImage                 DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders               DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.SizeOfHeaders);
    printf("  CheckSum                    DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.CheckSum);
    printf("  Subsystem                   WORD      %u %s\n", nt_header->OptionalHeader.Subsystem, _exm_view_subsystem_get(nt_header->OptionalHeader.Subsystem));
    printf("  DllCharacteristics          WORD      0x%x%s\n", nt_header->OptionalHeader.DllCharacteristics, _exm_view_dllcharacteristics_get(nt_header->OptionalHeader.DllCharacteristics));
    printf("  SizeOfStackReserve          ULONGLONG 0x" FMT_LL16X "\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit           ULONGLONG 0x" FMT_LL16X "\n", nt_header->OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve           ULONGLONG 0x" FMT_LL16X "\n", nt_header->OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit            ULONGLONG 0x" FMT_LL16X "\n", nt_header->OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags                 DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes         DWORD     0x" FMT_DWD8X "\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);
    printf("  DataDirectory               array\n");
}

static void
_exm_view_cmd_nt_header_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS *nt_header;
    signed char is_64bits;

    nt_header = exm_pe_nt_header_get(pe);

    is_64bits = exm_pe_is_64bits(pe);
    if (is_64bits == -1)
    {
        EXM_LOG_ERR("Can not find a valid PE32 or PE32+ file");
        return;
    }

    printf("NT Header\n");
    printf("  field          type    value\n");
    printf("  Signature      DWORD   0x" FMT_DWD8X " \"%c%c%c%c\"\n",
           nt_header->Signature,
           (unsigned char)(nt_header->Signature & 0x000000ff),
           (unsigned char)((nt_header->Signature & 0x0000ff00) >> 8),
           (unsigned char)((nt_header->Signature & 0x00ff0000) >> 16),
           (unsigned char)((nt_header->Signature & 0xff000000) >> 24));
    printf("  FileHeader     structure\n");
    printf("  OptionalHeader structure\n");

    printf("\n");
    printf("File Header\n");
    printf("  field                type    value\n");
    printf("  Machine              WORD    0x%04hx\n", nt_header->FileHeader.Machine);
    printf("  NumberOfSections     WORD    0x%04hx\n", nt_header->FileHeader.NumberOfSections);
    printf("  TimeDateStamp        DWORD   0x" FMT_DWD8X "\n", nt_header->FileHeader.TimeDateStamp);
    printf("  PointerToSymbolTable DWORD   0x" FMT_DWD8X "\n", nt_header->FileHeader.PointerToSymbolTable);
    printf("  NumberOfSymbols      DWORD   0x" FMT_DWD8X "\n", nt_header->FileHeader.NumberOfSymbols);
    printf("  SizeOfOptionalHeader WORD    0x%x\n", nt_header->FileHeader.SizeOfOptionalHeader);
    printf("  Characteristics      WORD    0x%x\n", nt_header->FileHeader.Characteristics);

    printf("\n");
    printf("Optional Header\n");
    if (is_64bits)
        _exm_view_cmd_optional_header_64_display(pe);
    else
        _exm_view_cmd_optional_header_32_display(pe);
}

static void
_exm_view_cmd_sections_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS *nt_header;
    IMAGE_SECTION_HEADER *iter;
    WORD i;

    nt_header = exm_pe_nt_header_get(pe);
    iter = IMAGE_FIRST_SECTION(nt_header);
    for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, iter++)
    {
        printf("Section header #%u\n", i);
        printf("  field                type    value\n");
        printf("  Name[8]              BYTE    %c%c%c%c%c%c%c%c", iter->Name[0], iter->Name[1], iter->Name[2], iter->Name[3], iter->Name[4], iter->Name[5], iter->Name[6], iter->Name[7]);
        if (iter->Name[0] == '/')
            printf(" (%s)", exm_pe_section_name_get(pe, iter));
        printf("\n");
        printf("  VirtualSize          DWORD   0x" FMT_DWDX "\n", iter->Misc.VirtualSize);
        printf("  VirtualAddress       DWORD   0x" FMT_DWDX "\n", iter->VirtualAddress);
        printf("  SizeOfRawData        DWORD   0x" FMT_DWDX "\n", iter->SizeOfRawData);
        printf("  PointerToRawData     DWORD   0x" FMT_DWDX "\n", iter->PointerToRawData);
        printf("  PointerToRelocations DWORD   0x" FMT_DWDX "\n", iter->PointerToRelocations);
        printf("  PointerToLinenumbers DWORD   0x" FMT_DWDX "\n", iter->PointerToLinenumbers);
        printf("  NumberOfRelocations  WORD    0x%x\n", iter->NumberOfRelocations);
        printf("  NumberOfLinenumbers  WORD    0x%x\n", iter->NumberOfLinenumbers);
        printf("  Characteristics      DWORD   0x" FMT_DWDX " (%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u)\n",
               iter->Characteristics,
               (iter->Characteristics & IMAGE_SCN_SCALE_INDEX) == IMAGE_SCN_SCALE_INDEX,
               (iter->Characteristics & IMAGE_SCN_TYPE_NO_PAD) == IMAGE_SCN_TYPE_NO_PAD,
               (iter->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE,
               (iter->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA,
               (iter->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA,
               (iter->Characteristics & IMAGE_SCN_LNK_OTHER) == IMAGE_SCN_LNK_OTHER,
               (iter->Characteristics & IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO,
               (iter->Characteristics & IMAGE_SCN_LNK_REMOVE) == IMAGE_SCN_LNK_REMOVE,
               (iter->Characteristics & IMAGE_SCN_LNK_COMDAT) == IMAGE_SCN_LNK_COMDAT,
               (iter->Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) == IMAGE_SCN_NO_DEFER_SPEC_EXC,
               (iter->Characteristics & IMAGE_SCN_MEM_FARDATA) == IMAGE_SCN_MEM_FARDATA,
               (iter->Characteristics & IMAGE_SCN_MEM_PURGEABLE) == IMAGE_SCN_MEM_PURGEABLE,
               (iter->Characteristics & IMAGE_SCN_MEM_LOCKED) == IMAGE_SCN_MEM_LOCKED,
               (iter->Characteristics & IMAGE_SCN_MEM_PRELOAD) == IMAGE_SCN_MEM_PRELOAD,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_1BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_2BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_4BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_8BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_16BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_32BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_64BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_128BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_256BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_512BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_1024BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_2048BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_4096BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_8192BYTES,
               (iter->Characteristics & IMAGE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_MASK,
               (iter->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) == IMAGE_SCN_LNK_NRELOC_OVFL,
               (iter->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE,
               (iter->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED,
               (iter->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == IMAGE_SCN_MEM_NOT_PAGED,
               (iter->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED,
               (iter->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE,
               (iter->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ,
               (iter->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE);
        if (i != (nt_header->FileHeader.NumberOfSections - 1))
            printf("\n");
    }
}

static void
_exm_view_cmd_directory_entry_export_display(Exm_Pe *pe)
{
    const IMAGE_EXPORT_DIRECTORY *export_dir;
    const IMAGE_DATA_DIRECTORY *data_dir;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

    printf("Directory entry Export - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x" FMT_DWDX "\n", data_dir->VirtualAddress);
    printf("  Size            DWORD   0x" FMT_DWDX "\n", data_dir->Size);

    export_dir = exm_pe_export_directory_get(pe, NULL);
    if (!export_dir)
        return;

    printf("\n");
    printf("Directory entry Export - Image Export Directory\n");
    printf("  field                 type    value\n");
    printf("  Characteristics       DWORD   0x" FMT_DWDX "\n", export_dir->Characteristics);
    printf("  TimeDateStamp         DWORD   0x" FMT_DWDX "\n", export_dir->TimeDateStamp);
    printf("  MajorVersion          WORD    %u\n", export_dir->MajorVersion);
    printf("  MinorVersion          WORD    %u\n", export_dir->MinorVersion);
    printf("  Name                  DWORD   0x" FMT_DWDX "\n", export_dir->Name);
    printf("  Base                  DWORD   0x" FMT_DWDX "\n", export_dir->Base);
    printf("  NumberOfFunctions     DWORD   0x" FMT_DWDX "\n", export_dir->NumberOfFunctions);
    printf("  NumberOfNames         DWORD   0x" FMT_DWDX "\n", export_dir->NumberOfNames);
    printf("  AddressOfFunctions    DWORD   0x" FMT_DWDX "\n", export_dir->AddressOfFunctions);
    printf("  AddressOfNames        DWORD   0x" FMT_DWDX "\n", export_dir->AddressOfNames);
    printf("  AddressOfNameOrdinals DWORD   0x" FMT_DWDX "\n", export_dir->AddressOfNameOrdinals);
}

static void
_exm_view_cmd_directory_entry_import_display(Exm_Pe *pe)
{
    const IMAGE_IMPORT_DESCRIPTOR *import_desc;
    const IMAGE_DATA_DIRECTORY *data_dir;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

    printf("Directory entry Import - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x" FMT_DWDX "\n", data_dir->VirtualAddress);
    printf("  Size            DWORD   0x" FMT_DWDX "\n", data_dir->Size);

    import_desc = exm_pe_import_descriptor_get(pe, NULL);
    if (!import_desc)
        return;

    printf("\n");
    printf("Directory entry Import - Image Import Descriptor\n");
    printf("  field                 type    value\n");
#ifdef _WIN32
    printf("  Characteristics       DWORD   0x" FMT_DWDX "\n", import_desc->Characteristics);
#else
    printf("  Characteristics       DWORD   0x" FMT_DWDX "\n", import_desc->u.Characteristics);
#endif
    printf("  TimeDateStamp         DWORD   0x" FMT_DWDX "\n", import_desc->TimeDateStamp);
    printf("  ForwarderChain        DWORD   0x" FMT_DWDX "\n", import_desc->ForwarderChain);
    printf("  Name                  DWORD   0x" FMT_DWDX "\n", import_desc->Name);
    printf("  FirstThunk            DWORD   0x" FMT_DWDX "\n", import_desc->FirstThunk);
}

static void
_exm_view_cmd_directory_entry_resource_dump(const Exm_Pe *pe,
                                            const unsigned char *base,
                                            const IMAGE_RESOURCE_DIRECTORY *resource_dir,
                                            const IMAGE_RESOURCE_DIRECTORY_ENTRY *parent,
                                            int spaces);

static void
_exm_view_cmd_directory_entry_resource_name_get(const unsigned char *base,
                                                const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry,
                                                wchar_t *buf)
{
    if (entry->NameIsString)
    {
        IMAGE_RESOURCE_DIR_STRING_U *str;

        str = (IMAGE_RESOURCE_DIR_STRING_U *)(base + entry->NameOffset);
        wmemcpy(buf, str->NameString, str->Length);
        buf[str->Length] = 0;
    }
    else
    {
        switch (entry->Id)
        {
            case 1: /* RT_CURSOR */
                wcscpy(buf, L"cursor");
                break;
            case 2: /* RT_BITMAP */
                wcscpy(buf, L"bitmap");
                break;
            case 3: /* RT_ICON */
                wcscpy(buf, L"icon");
                break;
            case 4: /* RT_MENU */
                wcscpy(buf, L"menu");
                break;
            case 5: /* RT_DIALOG */
                wcscpy(buf, L"dialog");
                break;
            case 6: /* RT_STRING, string table */
                wcscpy(buf, L"string table");
                break;
            case 7: /* RT_FONTDIR */
                wcscpy(buf, L"font directory");
                break;
            case 8: /* RT_FONT */
                wcscpy(buf, L"font");
                break;
            case 9: /* RT_ACCELERATOR */
                wcscpy(buf, L"accelerator");
                break;
            case 10: /* RT_RCDATA */
                wcscpy(buf, L"rc data");
                break;
            case 11: /* RT_MESSAGETABLE */
                wcscpy(buf, L"message table");
                break;
            case 12: /* RT_GROUP_CURSOR */
                wcscpy(buf, L"group cursor");
                break;
            case 14: /* RT_GROUP_ICON */
                wcscpy(buf, L"group icon");
                break;
            case 16: /* RT_VERSION */
                wcscpy(buf, L"version");
                break;
            case 17: /* RT_DLGINCLUDE */
                wcscpy(buf, L"dgl include");
                break;
            case 19: /* RT_PLUGPLAY */
                wcscpy(buf, L"PnP");
                break;
            case 20: /* RT_VXD */
                wcscpy(buf, L"VXD");
                break;
            case 21: /* RT_ANICURSOR */
                wcscpy(buf, L"animated cursor");
                break;
            case 22: /* RT_ANIICON */
                wcscpy(buf, L"animated icon");
                break;
            case 23: /* RT_HTML */
                wcscpy(buf, L"HTML");
                break;
            case 24: /* RT_MANIFEST */
                wcscpy(buf, L"Manifest");
                break;
            default:
                swprintf(buf, 256, L"Unknown (%u)", entry->Id);
                break;
        }
    }
}

static void
_exm_view_cmd_directory_entry_resource_entry_dump(const Exm_Pe *pe,
                                                  const unsigned char *base,
                                                  const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry,
                                                  int level)
{
    char str_spaces[128];
    const IMAGE_RESOURCE_DATA_ENTRY *data;
    int i;

    if (entry->DataIsDirectory)
    {
        _exm_view_cmd_directory_entry_resource_dump(pe, base,
                                                    (const IMAGE_RESOURCE_DIRECTORY *)(base + entry->OffsetToDirectory), entry, level);
        return;
    }

    for (i = 0; i < (2 * level); i++)
        str_spaces[i]=' ';
    str_spaces[i] = '\0';

    data = (const IMAGE_RESOURCE_DATA_ENTRY *)(base + entry->OffsetToData);
    printf("%s  OffsetToData        DWORD   0x" FMT_DWDX "\n", str_spaces, data->OffsetToData);
    printf("%s  Size                DWORD   %lu\n", str_spaces, data->Size);
    printf("%s  CodePage            DWORD   0x" FMT_DWDX "\n", str_spaces, data->CodePage);
}

static void
_exm_view_cmd_directory_entry_resource_dump(const Exm_Pe *pe,
                                            const unsigned char *base,
                                            const IMAGE_RESOURCE_DIRECTORY *resource_dir,
                                            const IMAGE_RESOURCE_DIRECTORY_ENTRY *parent,
                                            int level)
{
    wchar_t buf[256];
    char str_spaces[128];
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    DWORD i;

    for (i = 0; i < (DWORD)(2 * level); i++)
        str_spaces[i] = ' ';
    str_spaces[i] = 0;

    printf("\n");
    printf("%sDirectory entry Resource - Image Resource Directory (level: %d)\n",
           str_spaces, level);
    printf("%s  field                 type    value\n", str_spaces);
    printf("%s  Characteristics       DWORD   0x" FMT_DWDX "\n", str_spaces, resource_dir->Characteristics);
    printf("%s  TimeDateStamp         DWORD   0x" FMT_DWDX "\n", str_spaces, resource_dir->TimeDateStamp);
    printf("%s  MajorVersion          WORD    %u\n", str_spaces, resource_dir->MajorVersion);
    printf("%s  MinorVersion          WORD    %u\n", str_spaces, resource_dir->MinorVersion);
    printf("%s  NumberOfNamedEntries  WORD    %u\n", str_spaces, resource_dir->NumberOfNamedEntries);
    printf("%s  NumberOfIdEntries     WORD    %u\n", str_spaces, resource_dir->NumberOfIdEntries);

    if (parent)
    {
        printf("%s  Id                    WORD    %u (0x%x)", str_spaces, parent->Id, parent->Id);
        _exm_view_cmd_directory_entry_resource_name_get(base, parent, buf);
        wprintf(L"       Name: %s\n", buf);


        printf("%s  OffsetToData          DWORD   0x" FMT_DWDX " (is dir: %s)\n",
               str_spaces, parent->OffsetToData, parent->DataIsDirectory ? "yes" : "no");
    }

    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(resource_dir + 1);
    for (i = 0; i < (resource_dir->NumberOfNamedEntries + resource_dir->NumberOfIdEntries); i++, entry++)
    {
        _exm_view_cmd_directory_entry_resource_entry_dump(pe, base, entry,
                                                          level + 1);
    }
}

static void
_exm_view_cmd_directory_entry_resource_display(Exm_Pe *pe)
{
    const IMAGE_RESOURCE_DIRECTORY *resource_dir;
    const IMAGE_DATA_DIRECTORY *data_dir;
    const unsigned char *base;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);

    printf("Directory entry Resource - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x" FMT_DWDX "\n", data_dir->VirtualAddress);
    printf("  Size            DWORD   0x" FMT_DWDX "\n", data_dir->Size);

    resource_dir = exm_pe_resource_directory_get(pe, NULL);
    if (!resource_dir)
        return;

    base = (const unsigned char *)resource_dir;
    _exm_view_cmd_directory_entry_resource_dump(pe, base, resource_dir, NULL, 0);
}

static void
_exm_view_cmd_directory_entry_debug_display(Exm_Pe *pe)
{
    const IMAGE_DEBUG_DIRECTORY *debug_dir;
    const IMAGE_DATA_DIRECTORY *data_dir;
    const char *debug_type;
    DWORD i;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_DEBUG);

    printf("Directory entry Debug - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x" FMT_DWDX "\n", data_dir->VirtualAddress);
    printf("  Size            DWORD   0x" FMT_DWDX "\n", data_dir->Size);

    debug_dir = exm_pe_debug_directory_get(pe, NULL);
    if (!debug_dir)
    {
        const IMAGE_NT_HEADERS *nt_header;
        IMAGE_SECTION_HEADER *iter;

        nt_header = exm_pe_nt_header_get(pe);
        iter = IMAGE_FIRST_SECTION(nt_header);
        for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, iter++)
        {
            const unsigned char *data;

            unsigned int length;
            unsigned int offset;
            unsigned short version;
            unsigned char size;

            if (strcmp(exm_pe_section_name_get(pe, iter), ".debug_info") != 0)
                continue;

            data = (const unsigned char *)exm_pe_dos_header_get(pe) + iter->PointerToRawData;
            length = exm_dwarf_read_uint32(data);
            data += 4;
            version = exm_dwarf_read_uint16(data);
            data += 2;
            offset = exm_dwarf_read_uint32(data);
            data += 4;
            size = exm_dwarf_read_uint8(data);
            data++;

            printf("\n");
            printf("Directory entry Debug - DWARF CUH\n");
            printf("  data                  type    value\n");
            printf("  Length                DWORD   0x%x\n", length);
            printf("  Version               WORD    %u\n", version);
            printf("  Offset                DWORD   0x%x\n", offset);
            printf("  Size                  UCHAR   %u\n", size);
        }

        return;
    }

    for (i = 0; i < (data_dir->Size / sizeof(IMAGE_DEBUG_DIRECTORY)); i++, debug_dir++)
    {
        switch (debug_dir->Type)
        {
            case IMAGE_DEBUG_TYPE_UNKNOWN:
                debug_type = "Unknown";
                break;
            case IMAGE_DEBUG_TYPE_COFF:
                debug_type = "COFF";
                break;
            case IMAGE_DEBUG_TYPE_CODEVIEW:
                debug_type = "CodeView";
                break;
            case IMAGE_DEBUG_TYPE_FPO:
                debug_type = "FPO";
                break;
            case IMAGE_DEBUG_TYPE_MISC:
                debug_type = "Miscellaneous";
                break;
            case IMAGE_DEBUG_TYPE_EXCEPTION:
                debug_type = "Exception";
                break;
            case IMAGE_DEBUG_TYPE_FIXUP:
                debug_type = "Fix Up";
                break;
            case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
                debug_type = "Omap to Src";
                break;
            case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
                debug_type = "Omap from src";
                break;
            case IMAGE_DEBUG_TYPE_BORLAND:
                debug_type = "Borland";
                break;
            case IMAGE_DEBUG_TYPE_RESERVED10:
                debug_type = "Reserved";
                break;
            case IMAGE_DEBUG_TYPE_CLSID:
                debug_type = "CLSID";
                break;
            default:
                debug_type = "Unsupported (error)";
                break;
        }
        printf("\n");
        printf("Directory entry Debug - Image Debug Directory #" FMT_DWD "\n", i);
        printf("  field                 type    value\n");
        printf("  Characteristics       DWORD   0x" FMT_DWDX "\n", debug_dir->Characteristics);
        printf("  TimeDateStamp         DWORD   0x" FMT_DWDX "\n", debug_dir->TimeDateStamp);
        printf("  MajorVersion          WORD    %u\n", debug_dir->MajorVersion);
        printf("  MinorVersion          WORD    %u\n", debug_dir->MinorVersion);
        printf("  Type                  DWORD   0x" FMT_DWDX " (%s)\n", debug_dir->Type, debug_type);
        printf("  SizeOfData            DWORD   0x" FMT_DWDX "\n", debug_dir->SizeOfData);
        printf("  AddressOfRawData      DWORD   0x" FMT_DWDX "\n", debug_dir->AddressOfRawData);
        printf("  PointerToRawData      DWORD   0x" FMT_DWDX "\n", debug_dir->PointerToRawData);
        if (debug_dir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            unsigned char *raw_data;
            DWORD signature;

            if (debug_dir->SizeOfData < sizeof(DWORD))
            {
                EXM_LOG_WARN("invalid size of CodeView debug information");
                return;
            }

            raw_data = (unsigned char *)exm_pe_dos_header_get(pe) + debug_dir->PointerToRawData;
            signature = *(DWORD *)raw_data;
            printf("  Signature             DWORD   0x" FMT_DWDX " (%c%c%c%c)\n",
                   signature,
                   (char)(signature & 0x000000ff),
                   (char)((signature >> 8) & 0x000000ff),
                   (char)((signature >> 16) & 0x000000ff),
                   (char)((signature >> 24) & 0x000000ff));

            if (signature == EXM_VIEW_DEBUG_SIGNATURE_RSDS)
            {
                unsigned char *file_name;

                /*
                 * PDB 7.0 information header is:
                 *
                 * DWORD  CvSignature
                 * GUID   Signature
                 * DWORD  Age
                 * BYTE * FileName
                 */
                file_name = raw_data + sizeof(DWORD) + sizeof(GUID) + sizeof(DWORD);
                printf("  PDB 7.0 file name             %s\n", file_name);
            }
            else if (signature == EXM_VIEW_DEBUG_SIGNATURE_NB10)
            {
                unsigned char *file_name;

                /*
                 * PDB 2.0 information header is:
                 *
                 * DWORD  CvSignature
                 * LONG   Offset (always 0 for NB10)
                 * DWORD  Seconds (seconds since 01/01/1970)
                 * DWORD  Age
                 * BYTE * FileName
                 *
                 * Obsolete since VC > VC6
                 */
                file_name = raw_data + sizeof(DWORD) + sizeof(LONG) + sizeof(DWORD) + sizeof(DWORD);
                printf("  PDB 20 file name             %s\n", file_name);
            }
            /* other */
        }
        else if (debug_dir->Type == IMAGE_DEBUG_TYPE_MISC)
        {
            char file_name[65536];
            IMAGE_DEBUG_MISC *idm;
            size_t len;

            /*
             * Obsolete since VC >= VC8
             */

            idm = (IMAGE_DEBUG_MISC *)((unsigned char *)exm_pe_dos_header_get(pe) + debug_dir->PointerToRawData);
            len = strlen((const char *)idm->Data) * (idm->Unicode ? 2 : 1);
            memcpy(file_name, idm->Data, len);
            file_name[len] = 0;
            if (idm->Unicode == 2) file_name[len+1] = 0;
            printf("  DBG file name                 %s\n", file_name);
        }
    }
}

static void
_exm_view_cmd_directory_entry_delayload_display(Exm_Pe *pe)
{
    const IMAGE_DELAYLOAD_DESCRIPTOR *delayload_desc;
    const IMAGE_DATA_DIRECTORY *data_dir;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

    printf("Directory entry Delayload - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x" FMT_DWDX "\n", data_dir->VirtualAddress);
    printf("  Size            DWORD   0x" FMT_DWDX "\n", data_dir->Size);

    delayload_desc = exm_pe_delayload_descriptor_get(pe, NULL);
    if (!delayload_desc)
        return;

    printf("\n");
    printf("Directory entry Delayload - Image Delayload Descriptor\n");
    printf("  field                      type    value\n");
    printf("  AllAttributes              DWORD   0x" FMT_DWDX "\n", delayload_desc->Attributes.AllAttributes);
    printf("  DllNameRVA                 DWORD   0x" FMT_DWDX "\n", delayload_desc->DllNameRVA);
    printf("  ModuleHandleRVA            DWORD   0x" FMT_DWDX "\n", delayload_desc->ModuleHandleRVA);
    printf("  ImportAddressTableRVA      DWORD   0x" FMT_DWDX "\n", delayload_desc->ImportAddressTableRVA);
    printf("  ImportNameTableRVA         DWORD   0x" FMT_DWDX "\n", delayload_desc->ImportNameTableRVA);
    printf("  BoundImportAddressTableRVA DWORD   0x" FMT_DWDX "\n", delayload_desc->BoundImportAddressTableRVA);
    printf("  UnloadInformationTableRVA  DWORD   0x" FMT_DWDX "\n", delayload_desc->UnloadInformationTableRVA);
    printf("  TimeDateStamp              DWORD   0x" FMT_DWDX "\n", delayload_desc->TimeDateStamp);
}

static void
_exm_view_cmd_run(Exm_Pe *pe)
{
    _exm_view_cmd_dos_header_display(pe);
    printf("\n");
    _exm_view_cmd_nt_header_display(pe);
    printf("\n");
    _exm_view_cmd_sections_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_export_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_import_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_resource_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_debug_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_delayload_display(pe);
}

#ifdef _WIN32
static void
_exm_view_gui_run(Exm_Pe *pe, Exm_Log_Level log_level)
{
    char args[32768];
    Exm_Process *process;
    Exm_Map_Shared *map;
    char *cmd_gui;

    cmd_gui = exm_file_find("examine_view.exe");
    if (!cmd_gui)
    {
        EXM_LOG_ERR("Can not allocate memory for application name");
        return;
    }

    args[0] = '\0';
    exm_str_append(args, exm_pe_filename_get(pe));

    process = exm_process_new(cmd_gui, args);
    if (!process)
    {
        EXM_LOG_ERR("Creation of process %s %s failed", cmd_gui, args);
        return;
    }
    free(cmd_gui);

    map = exm_map_shared_new("exm_view_gui_shared",
                             &log_level, sizeof(Exm_Log_Level));
    if (!map)
    {
        EXM_LOG_ERR("Can not map shared memory to pass to Examine View GUI");
        exm_process_del(process);
        return;
    }

    exm_process_run(process);
    exm_map_shared_del(map);
    exm_process_del(process);
}
#endif

void
exm_view_run(const char *module, unsigned char gui, Exm_Log_Level log_level)
{
    Exm_Pe *pe;

    pe = exm_pe_new(module);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        return;
    }

#ifdef _WIN32
    if (gui)
        _exm_view_gui_run(pe, log_level);
    else
#endif
        _exm_view_cmd_run(pe);

    exm_pe_free(pe);

    EXM_LOG_DBG("resources freed");
}
