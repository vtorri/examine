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

#ifndef EXAMINE_MEMCHECK_HOOK_H
#define EXAMINE_MEMCHECK_HOOK_H

typedef enum
{
    EXM_HOOK_FCT_NTDLL_BEGIN,
    EXM_HOOK_FCT_RTLALLOCATEHEAP = EXM_HOOK_FCT_NTDLL_BEGIN,
    EXM_HOOK_FCT_RTLFREEHEAP,
    EXM_HOOK_FCT_NTDLL_END,
    EXM_HOOK_FCT_KERNEL32_BEGIN = EXM_HOOK_FCT_NTDLL_END,
    EXM_HOOK_FCT_HEAPALLOC = EXM_HOOK_FCT_KERNEL32_BEGIN,
    EXM_HOOK_FCT_HEAPREALLOC,
    EXM_HOOK_FCT_HEAPFREE,
    EXM_HOOK_FCT_GLOBALALLOC,
    EXM_HOOK_FCT_GLOBALREALLOC,
    EXM_HOOK_FCT_GLOBALFREE,
    EXM_HOOK_FCT_LOCALALLOC,
    EXM_HOOK_FCT_LOCALREALLOC,
    EXM_HOOK_FCT_LOCALFREE,
    EXM_HOOK_FCT_KERNEL32_END,
    EXM_HOOK_FCT_GDI32_BEGIN = EXM_HOOK_FCT_KERNEL32_END,
    EXM_HOOK_FCT_CREATEBITMAP = EXM_HOOK_FCT_GDI32_BEGIN,
    EXM_HOOK_FCT_CREATEBITMAPINDIRECT,
    EXM_HOOK_FCT_CREATECOMPATIBLEBITMAP,
    EXM_HOOK_FCT_CREATEDIBITMAP,
    EXM_HOOK_FCT_CREATEDIBSECTION,
    EXM_HOOK_FCT_CREATEBRUSHINDIRECT,
    EXM_HOOK_FCT_CREATEDIBPATTERNBRUSH,
    EXM_HOOK_FCT_CREATEDIBPATTERNBRUSHPT,
    EXM_HOOK_FCT_CREATEHATCHBRUSH,
    EXM_HOOK_FCT_CREATEPATTERNBRUSH,
    EXM_HOOK_FCT_CREATESOLIDBRUSH,
    EXM_HOOK_FCT_CREATEFONT,
    EXM_HOOK_FCT_CREATEFONTINDIRECT,
    EXM_HOOK_FCT_CREATEPEN,
    EXM_HOOK_FCT_CREATEPENINDIRECT,
    EXM_HOOK_FCT_CREATEELLIPTICRGN,
    EXM_HOOK_FCT_CREATEELLIPTICRGNINDIRECT,
    EXM_HOOK_FCT_CREATEPOLYGONRGN,
    EXM_HOOK_FCT_CREATERECTRGN,
    EXM_HOOK_FCT_CREATERECTRGNINDIRECT,
    EXM_HOOK_FCT_CREATEPALETTE,
    EXM_HOOK_FCT_DELETEOBJECT,
    EXM_HOOK_FCT_GDI32_END,
    EXM_HOOK_FCT_LIBC_BEGIN = EXM_HOOK_FCT_GDI32_END,
    EXM_HOOK_FCT_MALLOC = EXM_HOOK_FCT_LIBC_BEGIN,
    EXM_HOOK_FCT__ALIGNED_MALLOC,
    EXM_HOOK_FCT__STRDUP,
    EXM_HOOK_FCT_CALLOC,
    EXM_HOOK_FCT_REALLOC,
    EXM_HOOK_FCT__EXPAND,
    EXM_HOOK_FCT_FREE,
    EXM_HOOK_FCT_MEMCPY,
    EXM_HOOK_FCT_STRCAT,
    EXM_HOOK_FCT__MBSCAT,
    EXM_HOOK_FCT_LIBC_END,
    EXM_HOOK_FCT_COUNT = EXM_HOOK_FCT_LIBC_END
} Exm_Hook_Fct;

typedef struct _Exm_Hook_Error_Data Exm_Hook_Error_Data;

typedef struct
{
    Exm_Hook_Fct fct;
    size_t size;
    void *data;
    unsigned int nbr_frees;
    Exm_List *stack;
    Exm_List *stack_first_free;
    unsigned int gdi32 : 1;
} Exm_Hook_Data_Alloc;

typedef struct
{
    unsigned int total_count_gdi_handles;
    unsigned int total_count_allocs;
    unsigned int total_count_frees;
    size_t total_bytes_allocated;
} Exm_Hook_Summary;

extern Exm_List *exm_hook_allocations;
extern Exm_List *exm_hook_errors;
extern Exm_Hook_Summary exm_hook_summary;

unsigned char exm_hook_init(const Exm_List *crt_names, const Exm_List *dep_names);
void exm_hook_shutdown(const Exm_List *crt_names, const Exm_List *dep_names);

void exm_hook_error_disp(Exm_Hook_Error_Data *data);

#endif /* EXAMINE_HOOK_H */
