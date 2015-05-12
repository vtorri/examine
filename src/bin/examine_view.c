/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2014-2015 Vincent Torri.
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

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#endif

#include <Examine.h>

#include "examine_private.h"

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
    printf("  e_lfanew   LONG    0x%04lx\n", dos_header->e_lfanew);
}

static void
_exm_view_cmd_optional_header_32_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS32 *nt_header;

    nt_header = (const IMAGE_NT_HEADERS32 *)exm_pe_nt_header_get(pe);

    printf("  field                       type    value\n");
    printf("  Magic                       WORD    0x%04hx\n", nt_header->OptionalHeader.Magic);
    printf("  MajorLinkerVersion          BYTE    %hu\n", nt_header->OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion          BYTE    %hu\n", nt_header->OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode                  DWORD   %lu\n", nt_header->OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData       DWORD   %lu\n", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData     DWORD   %lu\n", nt_header->OptionalHeader.SizeOfUninitializedData);
    printf("  AddressOfEntryPoint         DWORD   0x%08lx\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode                  DWORD   0x%08lx\n", nt_header->OptionalHeader.BaseOfCode);
    printf("  BaseOfData                  DWORD   0x%08lx\n", nt_header->OptionalHeader.BaseOfData);
    printf("  ImageBase                   DWORD   0x%08lx\n", nt_header->OptionalHeader.ImageBase);
    printf("  SectionAlignment            DWORD   %lu\n", nt_header->OptionalHeader.SectionAlignment);
    printf("  FileAlignment               DWORD   %lu\n", nt_header->OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion WORD    %u\n", nt_header->OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion WORD    %u\n", nt_header->OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion           WORD    %u\n", nt_header->OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion           WORD    %u\n", nt_header->OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion       WORD    %u\n", nt_header->OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion       WORD    %u\n", nt_header->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue           DWORD   %lu\n", nt_header->OptionalHeader.Win32VersionValue);
    printf("  SizeOfImage                 DWORD   %lu\n", nt_header->OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders               DWORD   %lu\n", nt_header->OptionalHeader.SizeOfHeaders);
    printf("  CheckSum                    DWORD   %lu\n", nt_header->OptionalHeader.CheckSum);
    printf("  Subsystem                   WORD    %u\n", nt_header->OptionalHeader.Subsystem);
    printf("  DllCharacteristics          WORD    %u\n", nt_header->OptionalHeader.DllCharacteristics);
    printf("  SizeOfStackReserve          DWORD   %lu\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackReserve          DWORD   %lu\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit           DWORD   %lu\n", nt_header->OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve           DWORD   %lu\n", nt_header->OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit            DWORD   %lu\n", nt_header->OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags                 DWORD   %lu\n", nt_header->OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes         DWORD   %lu\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);
    printf("  DataDirectory               array\n");
}

static void
_exm_view_cmd_optional_header_64_display(Exm_Pe *pe)
{
    const IMAGE_NT_HEADERS64 *nt_header;

    nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);

    printf("  field                       type      value\n");
    printf("  Magic                       WORD      0x%04hx\n", nt_header->OptionalHeader.Magic);
    printf("  MajorLinkerVersion          BYTE      %hu\n", nt_header->OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion          BYTE      %hu\n", nt_header->OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode                  DWORD     0x%08lx\n", nt_header->OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData       DWORD     0x%08lx\n", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData     DWORD     0x%08lx\n", nt_header->OptionalHeader.SizeOfUninitializedData);
    printf("  AddressOfEntryPoint         DWORD     0x%08lx\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode                  DWORD     0x%08lx\n", nt_header->OptionalHeader.BaseOfCode);
    printf("  ImageBase                   ULONGLONG 0x%016I64x\n", nt_header->OptionalHeader.ImageBase);
    printf("  SectionAlignment            DWORD     0x%08lx\n", nt_header->OptionalHeader.SectionAlignment);
    printf("  FileAlignment               DWORD     0x%08lx\n", nt_header->OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion WORD      %u\n", nt_header->OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion WORD      %u\n", nt_header->OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion           WORD      %u\n", nt_header->OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion           WORD      %u\n", nt_header->OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion       WORD      %u\n", nt_header->OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion       WORD      %u\n", nt_header->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue           DWORD     %lu\n", nt_header->OptionalHeader.Win32VersionValue);
    printf("  SizeOfImage                 DWORD     0x%08lx\n", nt_header->OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders               DWORD     0x%08lx\n", nt_header->OptionalHeader.SizeOfHeaders);
    printf("  CheckSum                    DWORD     0x%08lx\n", nt_header->OptionalHeader.CheckSum);
    printf("  Subsystem                   WORD      %u\n", nt_header->OptionalHeader.Subsystem);
    printf("  DllCharacteristics          WORD      %u\n", nt_header->OptionalHeader.DllCharacteristics);
    printf("  SizeOfStackReserve          ULONGLONG 0x%016I64x\n", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit           ULONGLONG 0x%016I64x\n", nt_header->OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve           ULONGLONG 0x%016I64x\n", nt_header->OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit            ULONGLONG 0x%016I64x\n", nt_header->OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags                 DWORD     0x%08lx\n", nt_header->OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes         DWORD     0x%08lx\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);
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
    printf("  Signature      DWORD   0x%08lx \"%c%c%c%c\"\n",
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
    printf("  TimeDateStamp        DWORD   0x%08lx\n", nt_header->FileHeader.TimeDateStamp);
    printf("  PointerToSymbolTable DWORD   0x%08lx\n", nt_header->FileHeader.PointerToSymbolTable);
    printf("  NumberOfSymbols      DWORD   0x%08lx\n", nt_header->FileHeader.NumberOfSymbols);
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
        printf("  Name[8]              BYTE    %c%c%c%c%c%c%c%c\n", iter->Name[0], iter->Name[1], iter->Name[2], iter->Name[3], iter->Name[4], iter->Name[5], iter->Name[6], iter->Name[7]);
        printf("  VirtualSize          DWORD   0x%lx\n", iter->Misc.VirtualSize);
        printf("  VirtualAddress       DWORD   0x%lx\n", iter->VirtualAddress);
        printf("  SizeOfRawData        DWORD   0x%lx\n", iter->SizeOfRawData);
        printf("  PointerToRawData     DWORD   0x%lx\n", iter->PointerToRawData);
        printf("  PointerToRelocations DWORD   0x%lx\n", iter->PointerToRelocations);
        printf("  PointerToLinenumbers DWORD   0x%lx\n", iter->PointerToLinenumbers);
        printf("  NumberOfRelocations  WORD    0x%x\n", iter->NumberOfRelocations);
        printf("  NumberOfLinenumbers  WORD    0x%x\n", iter->NumberOfLinenumbers);
        printf("  Characteristics      DWORD   0x%lx (%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u)\n",
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
    IMAGE_DATA_DIRECTORY data_dir;

    if (exm_pe_is_64bits(pe))
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    printf("Directory entry Import - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x%lx\n", data_dir.VirtualAddress);
    printf("  Size            DWORD   0x%lx\n", data_dir.Size);

    export_dir = exm_pe_export_directory_get(pe, NULL);
    if (!export_dir)
        return;

    printf("\n");
    printf("Directory entry Export - Image Export Directory\n");
    printf("  field                 type    value\n");
    printf("  Characteristics       DWORD   0x%lx\n", export_dir->Characteristics);
    printf("  TimeDateStamp         DWORD   0x%lx\n", export_dir->TimeDateStamp);
    printf("  MajorVersion          WORD    %u\n", export_dir->MajorVersion);
    printf("  MinorVersion          WORD    %u\n", export_dir->MinorVersion);
    printf("  Name                  DWORD   0x%lx\n", export_dir->Name);
    printf("  Base                  DWORD   0x%lx\n", export_dir->Base);
    printf("  NumberOfFunctions     DWORD   0x%lx\n", export_dir->NumberOfFunctions);
    printf("  NumberOfNames         DWORD   0x%lx\n", export_dir->NumberOfNames);
    printf("  AddressOfFunctions    DWORD   0x%lx\n", export_dir->AddressOfFunctions);
    printf("  AddressOfNames        DWORD   0x%lx\n", export_dir->AddressOfNames);
    printf("  AddressOfNameOrdinals DWORD   0x%lx\n", export_dir->AddressOfNameOrdinals);
}

static void
_exm_view_cmd_directory_entry_import_display(Exm_Pe *pe)
{
    const IMAGE_IMPORT_DESCRIPTOR *import_desc;
    IMAGE_DATA_DIRECTORY data_dir;

    if (exm_pe_is_64bits(pe))
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    else
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    printf("Directory entry Import - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x%lx\n", data_dir.VirtualAddress);
    printf("  Size            DWORD   0x%lx\n", data_dir.Size);

    import_desc = exm_pe_import_descriptor_get(pe, NULL);
    if (!import_desc)
        return;

    printf("\n");
    printf("Directory entry Import - Image Import Descriptor\n");
    printf("  field                 type    value\n");
    printf("  Characteristics       DWORD   0x%lx\n", import_desc->Characteristics);
    printf("  TimeDateStamp         DWORD   0x%lx\n", import_desc->TimeDateStamp);
    printf("  ForwarderChain        DWORD   0x%lx\n", import_desc->ForwarderChain);
    printf("  Name                  DWORD   0x%lx\n", import_desc->Name);
    printf("  FirstThunk            DWORD   0x%lx\n", import_desc->FirstThunk);
}

static void
_exm_view_cmd_directory_entry_debug_display(Exm_Pe *pe)
{
    const IMAGE_DEBUG_DIRECTORY *debug_dir;
    IMAGE_DATA_DIRECTORY data_dir;

    if (exm_pe_is_64bits(pe))
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }

    printf("Directory entry Import - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x%lx\n", data_dir.VirtualAddress);
    printf("  Size            DWORD   0x%lx\n", data_dir.Size);

    debug_dir = exm_pe_debug_directory_get(pe, NULL);
    if (!debug_dir)
        return;

    printf("\n");
    printf("Directory entry Debug - Image Debug Directory\n");
    printf("  field                 type    value\n");
    printf("  Characteristics       DWORD   0x%lx\n", debug_dir->Characteristics);
    printf("  TimeDateStamp         DWORD   0x%lx\n", debug_dir->TimeDateStamp);
    printf("  MajorVersion          WORD    %u\n", debug_dir->MajorVersion);
    printf("  MinorVersion          WORD    %u\n", debug_dir->MinorVersion);
    printf("  Type                  DWORD   0x%lx\n", debug_dir->Type);
    printf("  SizeOfData            DWORD   0x%lx\n", debug_dir->SizeOfData);
    printf("  AddressOfRawData      DWORD   0x%lx\n", debug_dir->AddressOfRawData);
    printf("  PointerToRawData      DWORD   0x%lx\n", debug_dir->PointerToRawData);
}

static void
_exm_view_cmd_directory_entry_delayload_display(Exm_Pe *pe)
{
    const IMAGE_DELAYLOAD_DESCRIPTOR *delayload_desc;
    IMAGE_DATA_DIRECTORY data_dir;

    if (exm_pe_is_64bits(pe))
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    }
    else
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        data_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    }

    printf("Directory entry Delayload - Image Data Directory\n");
    printf("  field           type    value\n");
    printf("  VirtualAddress  DWORD   0x%lx\n", data_dir.VirtualAddress);
    printf("  Size            DWORD   0x%lx\n", data_dir.Size);

    delayload_desc = exm_pe_delayload_descriptor_get(pe, NULL);
    if (!delayload_desc)
        return;

    printf("\n");
    printf("Directory entry Delayload - Image Delayload Descriptor\n");
    printf("  field                      type    value\n");
    printf("  AllAttributes              DWORD   0x%lx\n", delayload_desc->Attributes.AllAttributes);
    printf("  DllNameRVA                 DWORD   0x%lx\n", delayload_desc->DllNameRVA);
    printf("  ModuleHandleRVA            DWORD   0x%lx\n", delayload_desc->ModuleHandleRVA);
    printf("  ImportAddressTableRVA      DWORD   0x%lx\n", delayload_desc->ImportAddressTableRVA);
    printf("  ImportNameTableRVA         DWORD   0x%lx\n", delayload_desc->ImportNameTableRVA);
    printf("  BoundImportAddressTableRVA DWORD   0x%lx\n", delayload_desc->BoundImportAddressTableRVA);
    printf("  UnloadInformationTableRVA  DWORD   0x%lx\n", delayload_desc->UnloadInformationTableRVA);
    printf("  TimeDateStamp              DWORD   0x%lx\n", delayload_desc->TimeDateStamp);
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
    _exm_view_cmd_directory_entry_debug_display(pe);
    printf("\n");
    _exm_view_cmd_directory_entry_delayload_display(pe);
}

static void
_exm_view_gui_run(Exm_Pe *pe)
{
    char buf[MAX_PATH];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char *cmd_gui;

    cmd_gui = exm_file_find("examine_view.exe");
    if (!cmd_gui)
    {
        EXM_LOG_ERR("Can not allocate memory for application name");
        return;
    }

    snprintf(buf, sizeof(buf), "\"%s\" \"%s\"",
             cmd_gui, exm_pe_filename_get(pe));

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, buf,
                       NULL, NULL, FALSE,
                       NORMAL_PRIORITY_CLASS,
                       NULL, NULL,
                       &si, &pi))
    {
        EXM_LOG_ERR("Can not create process for %s %s %ld",
                    cmd_gui, exm_pe_filename_get(pe),
                    GetLastError());
        free(cmd_gui);
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(cmd_gui);
}

void
exm_view_run(Exm_List *options, char *module, unsigned char gui)
{
    Exm_Pe *pe;
    Exm_List *option;

    EXM_LOG_INFO("Command : %s", module);
    EXM_LOG_INFO("");
    EXM_LOG_INFO("Examine options:");
    option = options;
    while (option)
    {
        EXM_LOG_INFO("   %s", (char *)option->data);
        option = option->next;
    }

    pe = exm_pe_new(module);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        return;
    }

    if (gui)
        _exm_view_gui_run(pe);
    else
        _exm_view_cmd_run(pe);

    exm_pe_free(pe);

    free(module);

    EXM_LOG_DBG("resources freed");
}
