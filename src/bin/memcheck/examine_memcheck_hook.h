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

#ifndef EXAMINE_HOOK_H
#define EXAMINE_HOOK_H

typedef enum
{
    EXM_HOOK_FCT_KERNEL32_BEGIN,
    EXM_HOOK_FCT_HEAPALLOC = EXM_HOOK_FCT_KERNEL32_BEGIN,
    EXM_HOOK_FCT_HEAPFREE,
    EXM_HOOK_FCT_KERNEL32_END,
    EXM_HOOK_FCT_LIBC_BEGIN = EXM_HOOK_FCT_KERNEL32_END,
    EXM_HOOK_FCT_MALLOC = EXM_HOOK_FCT_LIBC_BEGIN,
    EXM_HOOK_FCT_FREE,
    EXM_HOOK_FCT_LIBC_END,
    EXM_HOOK_FCT_COUNT = EXM_HOOK_FCT_LIBC_END
} Exm_Hook_Fct;

typedef struct
{
    Exm_Hook_Fct fct;
    size_t size;
    void *data;
    unsigned int nbr_frees;
    Exm_List *stack;
} Exm_Hook_Data_Alloc;

typedef struct
{
    unsigned int total_count_allocs;
    unsigned int total_count_frees;
    unsigned int total_bytes_allocated;
} Exm_Hook_Summary;

extern Exm_List *exm_hook_allocations;
extern Exm_List *exm_hook_errors;
extern Exm_Hook_Summary exm_hook_summary;

unsigned char exm_hook_init(const Exm_List *crt_names, const Exm_List *dep_names);
void exm_hook_shutdown(const Exm_List *crt_names, const Exm_List *dep_names);

#endif /* EXAMINE_HOOK_H */
