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

#ifndef EXM_PE_H
#define EXM_PE_H

#ifndef _WIN32
# include "examine_pe_unix.h"
#endif

typedef struct _Exm_Pe Exm_Pe;

EXM_API Exm_Pe *exm_pe_new(const char *filename);

EXM_API Exm_Pe *exm_pe_new_from_base(const char *filename, const void *base, DWORD size);

EXM_API void exm_pe_free(Exm_Pe *pe);

EXM_API const char *exm_pe_filename_get(const Exm_Pe *pe);

EXM_API signed char exm_pe_is_64bits(const Exm_Pe *pe);

EXM_API unsigned char exm_pe_is_dll(Exm_Pe *pe);

EXM_API const IMAGE_DOS_HEADER *exm_pe_dos_header_get(const Exm_Pe *pe);

EXM_API const IMAGE_NT_HEADERS *exm_pe_nt_header_get(const Exm_Pe *pe);

EXM_API const void *exm_pe_entry_point_get(const Exm_Pe *pe);

EXM_API const IMAGE_DATA_DIRECTORY *exm_pe_data_directory_get(const Exm_Pe *pe, int entry);

/* export directory */

EXM_API const IMAGE_EXPORT_DIRECTORY *exm_pe_export_directory_get(const Exm_Pe *pe, DWORD *count);

EXM_API unsigned char exm_pe_export_directory_function_ordinal_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx, DWORD *ordinal);

EXM_API const char *exm_pe_export_directory_function_name_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx);

EXM_API DWORD exm_pe_export_directory_function_address_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx);

/* import descriptor */

EXM_API const IMAGE_IMPORT_DESCRIPTOR *exm_pe_import_descriptor_get(const Exm_Pe *pe, DWORD *count);

EXM_API const char *exm_pe_import_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_IMPORT_DESCRIPTOR *id);

/* resource directory */

EXM_API const IMAGE_RESOURCE_DIRECTORY *exm_pe_resource_directory_get(const Exm_Pe *pe, DWORD *count);

EXM_API const void *exm_pe_resource_data_get(const Exm_Pe *pe, DWORD id, DWORD *size);

/* debug directory */

EXM_API const IMAGE_DEBUG_DIRECTORY *exm_pe_debug_directory_get(const Exm_Pe *pe, DWORD *count);

/* delayload directory */

EXM_API const IMAGE_DELAYLOAD_DESCRIPTOR *exm_pe_delayload_descriptor_get(const Exm_Pe *pe, DWORD *count);

EXM_API const char *exm_pe_delayload_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_DELAYLOAD_DESCRIPTOR *dd);

EXM_API const char *exm_pe_section_string_table_get(const Exm_Pe *pe);

EXM_API const char *exm_pe_section_name_get(const Exm_Pe *pe, const IMAGE_SECTION_HEADER *sh);

#endif /* EXM_PE_H */
