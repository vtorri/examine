/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2012-2016 Vincent Torri.
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

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <inttypes.h>
#endif

#include "Examine.h"
#ifndef _WIN32
# include "examine_pe_unix.h"
#endif

#include "examine_private_map.h"


/**
 * @defgroup PE file functions
 *
 * The main purpose of this file is to list the modules of a PE
 * file. Indeed, the process which is checked is launched as
 * suspended. So the modules can not be retrieved with
 * EnumProcessModule, but they are accessible within the PE file.
 *
 * See http://bbs.pediy.com/upload/bbs/unpackfaq/ARTeam%20PE_appendix1_offsets.htm
 *
 * @{
 */

/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


struct _Exm_Pe
{
    char *filename;
    Exm_Map *map;
    IMAGE_NT_HEADERS *nt_header; /**< The NT header address */
};

static char _exm_pe_section_name[9];

/**
 * @brief Return the absolute address from a relative virtual address.
 *
 * @param[in] file The PE file.
 * @param[in] The relative virtual address.
 * @return The corresponding absolute address.
 *
 * In PE files, all the addresses are given as relative virtual
 * address (RVA). This function returns the absolute address from this
 * RVA. On error, this function returns @c NULL.
 */
static void *
_exm_pe_rva_to_ptr_get2(const Exm_Pe *pe, DWORD rva)
{
    IMAGE_SECTION_HEADER *sh;
    IMAGE_SECTION_HEADER *sh_iter;
    int delta;
    int i;

    sh = NULL;
    sh_iter = IMAGE_FIRST_SECTION(pe->nt_header);
    for (i = 0; i < pe->nt_header->FileHeader.NumberOfSections; i++, sh_iter++)
    {
        if ((rva >= sh_iter->VirtualAddress) &&
            (rva < (sh_iter->VirtualAddress + sh_iter->Misc.VirtualSize)))
        {
            sh = sh_iter;
            break;
        }
    }

    if (!sh)
        return NULL;

    delta = (int)(sh->VirtualAddress - sh->PointerToRawData);

    return (void *)((unsigned char *)exm_map_base_get(pe->map) + rva - delta);
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


/**
 * @brief Return a new #Exm_Pe object.
 *
 * @param[in] filename The filename of the binary file to open.
 * @return A new #Exm_Pe object, or @c NULL on error.
 *
 * This function opens and mmaps the file named @p filename, get the
 * starting address of the NT header from the DOS header. It returns
 * @c NULL on error, or a newly created #Exm_Pe object otherwise. Once
 * not needed anymore, use exm_pe_free() to free resources.
 */
EXM_API Exm_Pe *
exm_pe_new(const char *filename)
{
    IMAGE_DOS_HEADER *dos_header;
    Exm_Pe *pe;

    if (!filename)
        return NULL;

    pe = (Exm_Pe *)malloc(sizeof(Exm_Pe));
    if (!pe)
        return NULL;

    pe->filename = exm_file_find(filename);
    if (!pe->filename)
        goto free_pe;

    pe->map = exm_map_new(pe->filename);
    if (!pe->map)
        goto free_pe_filename;

    if (exm_map_size_get(pe->map) < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)))
    {
        EXM_LOG_ERR("file %s is not sufficiently large to be a PE file", pe->filename);
        goto del_pe_map;
    }

    dos_header = (IMAGE_DOS_HEADER *)exm_map_base_get(pe->map);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        EXM_LOG_ERR("not a valid DOS header");
        goto del_pe_map;
    }

    if ((unsigned long long)dos_header->e_lfanew > exm_map_size_get(pe->map))
    {
        EXM_LOG_ERR("not a valid PE file (probably 16-bit DOS module)");
        goto del_pe_map;
    }

    pe->nt_header = (IMAGE_NT_HEADERS *)((unsigned char *)dos_header + dos_header->e_lfanew);
    if (pe->nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        EXM_LOG_ERR("not a valid NT header");
        goto del_pe_map;
    }

    return pe;

  del_pe_map:
    exm_map_del(pe->map);
  free_pe_filename:
    free(pe->filename);
  free_pe:
    free(pe);

    return NULL;
}

#ifndef _MSC_VER
#warning port exm_pe_new_from_base() to UNIX
#endif
/* FIXME: port exm_pe_new_from_base() to UNIX */
#if 0
/**
 * @brief Return a new #Exm_Pe object from a loaded module.
 *
 * @param[in] filename The filename of the binary file to open.
 * @param[in] base The base address of the loaded module.
 * @param[in] size The size of the loaded module.
 * @return A new #Exm_Pe object, or @c NULL on error.
 *
 * This function creates a newly allocated #Exm_Pe object from @p
 * filename and the base address @p base and size @p size of a loaded
 * module. It returns @c NULL on error, or a newly created #Exm_Pe
 * object otherwise. Once not needed anymore, use exm_pe_free() to
 * free resources.
 */
EXM_API Exm_Pe *
exm_pe_new_from_base(const char *filename, const void *base, DWORD size)
{
    IMAGE_DOS_HEADER *dos_header;
    Exm_Pe *pe;

    if (!filename)
        return NULL;

    pe = (Exm_Pe *)malloc(sizeof(Exm_Pe));
    if (!pe)
        return NULL;

    pe->filename = exm_file_find(filename);
    if (!pe->filename)
        goto free_pe;

    pe->map = exm_map_new_from_base(base, size);
    if (!pe->map)
        goto free_pe_filename;

    if (exm_map_size_get(pe->map) < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)))
    {
        EXM_LOG_ERR("file %s is not sufficiently large to be a PE file", pe->filename);
        goto del_pe_map;
    }

    dos_header = (IMAGE_DOS_HEADER *)exm_map_base_get(pe->map);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        EXM_LOG_ERR("not a valid DOS header");
        goto del_pe_map;
    }

    pe->nt_header = (IMAGE_NT_HEADERS *)((unsigned char *)dos_header + dos_header->e_lfanew);
    if (pe->nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        EXM_LOG_ERR("not a valid NT header");
        goto del_pe_map;
    }

    return pe;

  del_pe_map:
    exm_map_del(pe->map);
  free_pe_filename:
    free(pe->filename);
  free_pe:
    free(pe);

    return NULL;
}
#endif

/**
 * @Brief Free the given PE file.
 *
 * @param[out] The PE file.
 *
 * This function frees the resources of @p pe.
 */
EXM_API void
exm_pe_free(Exm_Pe *pe)
{
    if (!pe)
        return;

    exm_map_del(pe->map);
    free(pe->filename);
    free(pe);
}

/**
 * @Brief Return the file name from the given PE file.
 *
 * @param[in] The PE file.
 * @return The file name.
 *
 * This function returns the file name of the PE file @p pe.
 */
EXM_API const char *
exm_pe_filename_get(const Exm_Pe *pe)
{
    if (!pe)
        return NULL;

    return pe->filename;
}

/**
 * @Brief Check is the given PE file is 64 bits or not.
 *
 * @param[in] The PE file.
 * @return -1 on error, 0 if 32 bits, 1 if 64 bits.
 *
 * This function returns -1 on error, 0 if @p pe is a 32 bits file and
 * 1 if it is a 64 bits file.
 */
EXM_API signed char
exm_pe_is_64bits(const Exm_Pe *pe)
{
    if (!pe)
        return -1;

    if (pe->nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 1;
    else if (pe->nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return 0;
    else
        return -1;
}

/**
 * @Brief Check is the given PE file is a DLL or not.
 *
 * @param[in] The PE file.
 * @return 0 if it is an executable, 1 if it is a DLL.
 *
 * This function returns 0 if @p pe is an executable and 1 if it is a DLL.
 */
EXM_API unsigned char
exm_pe_is_dll(Exm_Pe *pe)
{
    if (!pe)
        return 0;

    return (pe->nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL;
}

/**
 * @Brief Return the address of the DOS header from the given PE file.
 *
 * @param[in] The PE file.
 * @return The DOS header address.
 *
 * This function returns the DOS header of the PE file @p pe.
 */
EXM_API const IMAGE_DOS_HEADER *
exm_pe_dos_header_get(const Exm_Pe *pe)
{
    return exm_map_base_get(pe->map);
}

/**
 * @Brief Return the address of the NT header from the given PE file.
 *
 * @param[in] The PE file.
 * @return The NT header address.
 *
 * This function returns the NT header of the PE file @p pe.
 */
EXM_API const IMAGE_NT_HEADERS *
exm_pe_nt_header_get(const Exm_Pe *pe)

{
    return pe->nt_header;
}

/**
 * @brief Return the entry point of a PE file.
 *
 * @param pe The PE file
 * @return The entry point.
 *
 * This function returns the entry point of the PE file @p pe.
 */
EXM_API const void *
exm_pe_entry_point_get(const Exm_Pe *pe)
{
  return (unsigned char *)(uintptr_t)pe->nt_header->OptionalHeader.ImageBase + pe->nt_header->OptionalHeader.AddressOfEntryPoint;
}

/**
 * @Brief Return the address of the Image Data Directory for the given
 * directory entry.
 *
 * @param[in] The PE file.
 * @param[in] The directory entry.
 * @return The Image Data Directory address.
 *
 * This function returns the address of the Image Data Directory of
 * the PE file @p pe for the directory entry @p entry. The returned
 * value depends if @pe is a PE32 or PE32+ file. No check is done on
 * the parameters.
 */
EXM_API const IMAGE_DATA_DIRECTORY *
exm_pe_data_directory_get(const Exm_Pe *pe, int entry)
{
    if (exm_pe_is_64bits(pe))
    {
        const IMAGE_NT_HEADERS64 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe);
        return &nt_header->OptionalHeader.DataDirectory[entry];
    }
    else
    {
        const IMAGE_NT_HEADERS32 *nt_header;

        nt_header = (const IMAGE_NT_HEADERS32 *)exm_pe_nt_header_get(pe);
        return &nt_header->OptionalHeader.DataDirectory[entry];
    }
}

/**
 * @Brief Return the address of the export directory from the given PE file.
 *
 * @param[in] The PE file.
 * @return The export directory address.
 *
 * This function returns the address of the export directory of the
 * PE file @p pe. If there is no export directory, @c NULL is returned.
 */
EXM_API const IMAGE_EXPORT_DIRECTORY *
exm_pe_export_directory_get(const Exm_Pe *pe, DWORD *count)
{
    const IMAGE_DATA_DIRECTORY *data_dir;
    DWORD rva;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);
    rva = data_dir->VirtualAddress;
    if (rva == 0)
    {
        EXM_LOG_WARN("PE file %s has no export directory", pe->filename);
        if (count)
            *count = 0;
        return NULL;
    }

    if (count)
        *count = data_dir->Size;

    return (IMAGE_EXPORT_DIRECTORY *)_exm_pe_rva_to_ptr_get2(pe, rva);
}

EXM_API unsigned char
exm_pe_export_directory_function_ordinal_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx, DWORD *ordinal)
{
    WORD *ordinals;

    ordinals = (WORD *)_exm_pe_rva_to_ptr_get2(pe, ed->AddressOfNameOrdinals);
    if (!ordinals)
    {
        *ordinal = 0;
        return 0;
    }

    *ordinal = ed->Base + ordinals[idx];
    return 1;
}

EXM_API const char *
exm_pe_export_directory_function_name_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx)
{
    DWORD *names;

    names = (DWORD *)_exm_pe_rva_to_ptr_get2(pe, ed->AddressOfNames);
    if (!names)
        return NULL;

    return (char *)_exm_pe_rva_to_ptr_get2(pe, names[idx]);
}

EXM_API DWORD
exm_pe_export_directory_function_address_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx)
{
    DWORD *addresses;

    addresses = (DWORD *)_exm_pe_rva_to_ptr_get2(pe, ed->AddressOfFunctions);
    if (!addresses)
        return 0;

    return (DWORD)(uintptr_t)_exm_pe_rva_to_ptr_get2(pe, addresses[idx]);
}

/**
 * @Brief Return the address of the import descriptor from the given PE file.
 *
 * @param[in] The PE file.
 * @return The import descriptor address.
 *
 * This function returns the address of the import descriptor of the
 * PE file @p pe. If there is no import section, @c NULL is returned.
 */
EXM_API const IMAGE_IMPORT_DESCRIPTOR *
exm_pe_import_descriptor_get(const Exm_Pe *pe, DWORD *count)
{
    const IMAGE_DATA_DIRECTORY *data_dir;
    DWORD rva;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
    rva = data_dir->VirtualAddress;
    if (rva == 0)
    {
        EXM_LOG_WARN("PE file %s has no import descriptor", pe->filename);
        if (count)
            *count = 0;
        return NULL;
    }

    if (count)
        *count = data_dir->Size;

    return (IMAGE_IMPORT_DESCRIPTOR *)_exm_pe_rva_to_ptr_get2(pe, rva);
}

EXM_API const char *
exm_pe_import_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_IMPORT_DESCRIPTOR *id)
{
    return (char *)_exm_pe_rva_to_ptr_get2(pe, id->Name);
}

/**
 * @Brief Return the address of the resource directory from the given PE file.
 *
 * @param[in] The PE file.
 * @return The resource directory address.
 *
 * This function returns the address of the resource directory of the
 * PE file @p pe. If there is no resource directory, @c NULL is returned.
 */
EXM_API const IMAGE_RESOURCE_DIRECTORY *
exm_pe_resource_directory_get(const Exm_Pe *pe, DWORD *count)
{
    const IMAGE_DATA_DIRECTORY *data_dir;
    DWORD rva;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    rva = data_dir->VirtualAddress;
    if (rva == 0)
    {
        EXM_LOG_WARN("PE file %s has no resource section", pe->filename);
        if (count)
            *count = 0;
        return NULL;
    }

    if (count)
        *count = data_dir->Size;

    return (IMAGE_RESOURCE_DIRECTORY *)_exm_pe_rva_to_ptr_get2(pe, rva);
}

EXM_API const void *
exm_pe_resource_data_get(const Exm_Pe *pe, DWORD id, DWORD *size)
{
    const IMAGE_RESOURCE_DIRECTORY *resource_dir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    const unsigned char *base;
    DWORD i;

    resource_dir = exm_pe_resource_directory_get(pe, NULL);
    if (!resource_dir)
        return NULL;

    base = (const unsigned char *)resource_dir;
    entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(resource_dir + 1);
    for (i = 0; i < resource_dir->NumberOfNamedEntries; i++, entry++) { }
    for (i = 0; i < resource_dir->NumberOfIdEntries; i++, entry++)
    {
        if ((entry->Id == id) && (entry->DataIsDirectory))
        {
            const IMAGE_RESOURCE_DATA_ENTRY *data;
            void *res;

            resource_dir = (const IMAGE_RESOURCE_DIRECTORY *)(base + entry->OffsetToDirectory);
            if (!resource_dir)
                return NULL;
            entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(resource_dir + 1);
            if (!entry)
                return NULL;
            resource_dir = (const IMAGE_RESOURCE_DIRECTORY *)(base + entry->OffsetToDirectory);
            if (!resource_dir)
                return NULL;
            entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(resource_dir + 1);
            if (!entry)
                return NULL;
            data = (const IMAGE_RESOURCE_DATA_ENTRY *)(base + entry->OffsetToData);
            if (!data)
                return NULL;

            res = _exm_pe_rva_to_ptr_get2(pe, data->OffsetToData);
            *size = data->Size;
            return res;
        }
    }

    return NULL;
}

/**
 * @Brief Return the address of the debug directory from the given PE file.
 *
 * @param[in] The PE file.
 * @return The debug directory address.
 *
 * This function returns the address of the debug directory of the
 * PE file @p pe. If there is no debug directory, @c NULL is returned.
 */
EXM_API const IMAGE_DEBUG_DIRECTORY *
exm_pe_debug_directory_get(const Exm_Pe *pe, DWORD *count)
{
    const IMAGE_DATA_DIRECTORY *data_dir;
    DWORD rva;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_DEBUG);
    rva = data_dir->VirtualAddress;
    if (rva == 0)
    {
        EXM_LOG_WARN("PE file %s has no debug section", pe->filename);
        if (count)
            *count = 0;
        return NULL;
    }

    if (count)
        *count = data_dir->Size;

    return (IMAGE_DEBUG_DIRECTORY *)_exm_pe_rva_to_ptr_get2(pe, rva);
}

/**
 * @Brief Return the address of the delayload directory from the given PE file.
 *
 * @param[in] The PE file.
 * @return The delayload directory address.
 *
 * This function returns the address of the delayload directory of the
 * PE file @p pe. If there is no delayload directory, @c NULL is returned.
 */
EXM_API const IMAGE_DELAYLOAD_DESCRIPTOR *
exm_pe_delayload_descriptor_get(const Exm_Pe *pe, DWORD *count)
{
    const IMAGE_DATA_DIRECTORY *data_dir;
    DWORD rva;

    data_dir = exm_pe_data_directory_get(pe, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    rva = data_dir->VirtualAddress;
    if (rva == 0)
    {
        EXM_LOG_WARN("PE file %s has no delayload section", pe->filename);
        if (count)
            *count = 0;
        return NULL;
    }

    if (count)
        *count = data_dir->Size;

    return (IMAGE_DELAYLOAD_DESCRIPTOR *)_exm_pe_rva_to_ptr_get2(pe, rva);
}

EXM_API const char *
exm_pe_delayload_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_DELAYLOAD_DESCRIPTOR *dd)
{
    if (dd->Attributes.AllAttributes & 1)
        return (char *)_exm_pe_rva_to_ptr_get2(pe, dd->DllNameRVA);
    else
        return (char *)((unsigned char *)exm_map_base_get(pe->map) + dd->DllNameRVA);
}

EXM_API const char *
exm_pe_section_string_table_get(const Exm_Pe *pe)
{
    if (!pe ||
        !pe->nt_header->FileHeader.PointerToSymbolTable  ||
        !pe->nt_header->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL))
        return NULL;

    return (const char *)((unsigned char *)exm_map_base_get(pe->map) + pe->nt_header->FileHeader.PointerToSymbolTable + pe->nt_header->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL));
}

EXM_API const char *
exm_pe_section_name_get(const Exm_Pe *pe, const IMAGE_SECTION_HEADER *sh)
{
    if (sh->Name[0] == '/')
        return exm_pe_section_string_table_get(pe) + atoi((const char*)sh->Name + 1);
    else
    {
        memcpy(_exm_pe_section_name, sh->Name, 8);
        _exm_pe_section_name[8] = '\0';
        return _exm_pe_section_name;
    }
}
