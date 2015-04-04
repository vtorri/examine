/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2012-2015 Vincent Torri.
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

Exm_Pe *exm_pe_new(const char *filename);

Exm_Pe *exm_pe_new_from_base(const char *filename, const void *base, DWORD size);

void exm_pe_free(Exm_Pe *pe);

const char *exm_pe_filename_get(const Exm_Pe *pe);

signed char exm_pe_is_64bits(const Exm_Pe *pe);

unsigned char exm_pe_is_dll(Exm_Pe *pe);

const IMAGE_DOS_HEADER *exm_pe_dos_header_get(const Exm_Pe *pe);

const IMAGE_NT_HEADERS *exm_pe_nt_header_get(const Exm_Pe *pe);

const void *exm_pe_entry_point_get(const Exm_Pe *pe);

/* export directory */

const IMAGE_EXPORT_DIRECTORY *exm_pe_export_directory_get(const Exm_Pe *pe, DWORD *count);

unsigned char exm_pe_export_directory_function_ordinal_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx, WORD *ordinal);

const char *exm_pe_export_directory_function_name_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx);

DWORD exm_pe_export_directory_function_address_get(const Exm_Pe *pe, const IMAGE_EXPORT_DIRECTORY *ed, DWORD idx);

/* import descriptor */

const IMAGE_IMPORT_DESCRIPTOR *exm_pe_import_descriptor_get(const Exm_Pe *pe, DWORD *count);

const char *exm_pe_import_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_IMPORT_DESCRIPTOR *id);

/* debug directory */

const IMAGE_DEBUG_DIRECTORY *exm_pe_debug_directory_get(const Exm_Pe *pe, DWORD *count);

/* delayload directory */

const IMAGE_DELAYLOAD_DESCRIPTOR *exm_pe_delayload_descriptor_get(const Exm_Pe *pe, DWORD *count);

const char *exm_pe_delayload_descriptor_file_name_get(const Exm_Pe *pe, const IMAGE_DELAYLOAD_DESCRIPTOR *dd);

#endif /* EXM_PE_H */
