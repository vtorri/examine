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

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <imagehlp.h>

#include <Examine.h>

#include "examine_memcheck_hook.h"


typedef struct
{
    Exm_List *crt_names;
    Exm_List *dep_names;
} Exm_Memcheck;

static Exm_Memcheck _exm_mc_instance = { NULL, NULL };

static int
_exm_mc_dll_init(void)
{
    int lens[2];
    int *vals;
    Exm_List *crt_names;
    Exm_List *dep_names;
    char *names;
    size_t idx;
    int i;
    int j;

    if (!exm_map_shared_read("exm_memcheck_shared_lens",
                             sizeof(lens), lens))
    {
        EXM_LOG_ERR("Can not retrieve shared lengths data");
        return 0;
    }

    vals = (int *)malloc(lens[0]);
    if (!vals)
    {
        EXM_LOG_ERR("Can not allocate memory");
        return 0;
    }

    names = (char *)malloc(lens[1]);
    if (!names)
    {
        EXM_LOG_ERR("Can not allocate memory");
        free(vals);
        return 0;
    }

    if (!exm_map_shared_read("exm_memcheck_shared_vals",
                             lens[0], vals))
    {
        EXM_LOG_ERR("Can not retrieve shared values data");
        free(names);
        free(vals);
        return 0;
    }

    if (!exm_map_shared_read("exm_memcheck_shared_names",
                             lens[1], names))
    {
        EXM_LOG_ERR("Can not retrieve shared names data");
        free(names);
        free(vals);
        return 0;
    }

    exm_log_level_set(vals[0]);

    idx = 0;
    i = 3;
    crt_names = NULL;
    for (j = 0; j < vals[1]; j++)
    {
        char *name;

        name = (char *)malloc(vals[i]);
        if (!name)
        {
            EXM_LOG_ERR("Can not allocate memory for CRT file name");
            free(names);
            free(vals);
            goto free_crt_names;
        }

        memcpy(name, names + idx, vals[i]);
        idx += vals[i];
        i++;
        crt_names = exm_list_append(crt_names, name);
    }

    dep_names = NULL;
    for (j = 0; j < vals[2]; j++)
    {
        char *name;

        name = (char *)malloc(vals[i]);
        if (!name)
        {
            EXM_LOG_ERR("Can not allocate memory for CRT file name");
            free(names);
            free(vals);
            goto free_dep_names;
        }

        memcpy(name, names + idx, vals[i]);
        idx += vals[i];
        i++;
        dep_names = exm_list_append(dep_names, name);
    }

    free(names);
    free(vals);

    _exm_mc_instance.crt_names =  crt_names;
    _exm_mc_instance.dep_names =  dep_names;

    if (!exm_hook_init(crt_names, dep_names))
    {
        EXM_LOG_ERR("Can not initialize hook system");
        goto free_dep_names;
    }

    return 1;

  free_dep_names:
    exm_list_free(dep_names, free);
  free_crt_names:
    exm_list_free(crt_names, free);

    return 0;
}

static void
_exm_mc_dll_shutdown(void)
{
    exm_hook_shutdown(_exm_mc_instance.crt_names, _exm_mc_instance.dep_names);
    exm_list_free(_exm_mc_instance.dep_names, free);
    exm_list_free(_exm_mc_instance.crt_names, free);
}

static int
_exm_mc_leaks_cmp(const void *d1, const void *d2)
{
    const Exm_Hook_Data_Alloc *da1 = d1;
    const Exm_Hook_Data_Alloc *da2 = d2;

    if (da1->size < da2->size)
        return -1;
    else if (da1->size > da2->size)
        return 1;
    else
        return 0;
}

static void
_exm_mc_output(void)
{
    Exm_List *leaks = NULL;
    Exm_List *iter;
    size_t bytes_at_exit = 0;
    size_t blocks_at_exit = 0;
    int alloc_records;
    int error_records;
    int record;

    iter = exm_hook_allocations;
    while (iter)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter->data;
        if (da->nbr_frees > 0)
        {
        }
        else
        {
            bytes_at_exit += da->size;
            blocks_at_exit++;
            leaks = exm_list_insert(leaks, da, _exm_mc_leaks_cmp);
        }

        iter = iter->next;
    }

    EXM_LOG_INFO("");
    EXM_LOG_INFO("HEAP SUMMARY:");
    EXM_LOG_INFO("    in use at exit: %Iu bytes in %Iu blocks",
                 bytes_at_exit, blocks_at_exit);
    EXM_LOG_INFO("  total heap usage: %u allocs, %u frees, %Iu bytes allocated",
                 exm_hook_summary.total_count_allocs,
                 exm_hook_summary.total_count_frees,
                 exm_hook_summary.total_bytes_allocated);
    EXM_LOG_INFO("                    %u GDI handles created",
                 exm_hook_summary.total_count_gdi_handles);
    EXM_LOG_INFO("");

    alloc_records = exm_list_count(leaks);
    if (blocks_at_exit > 0)
    {
        EXM_LOG_INFO("Searching for pointer to %Iu not-freed blocks", blocks_at_exit);

        record = 1;
        iter = leaks;
        while (iter)
        {
            Exm_Hook_Data_Alloc *da;

            da = (Exm_Hook_Data_Alloc *)iter->data;
            EXM_LOG_INFO("%Iu bytes in 1 block(s) are definitely lost [%d/%d]",
                         da->size, record, alloc_records);
            exm_stack_disp(da->stack);
            EXM_LOG_INFO("");
            record++;
            iter = iter->next;
        }

        EXM_LOG_INFO("");
        EXM_LOG_INFO("LEAK SUMMARY:");
        EXM_LOG_INFO("   definitely lost: %Iu bytes in %d blocks",
                     bytes_at_exit, blocks_at_exit);
    }
    else
    {
        EXM_LOG_INFO("All heap blocks were freed -- no leaks are possible");
    }

    EXM_LOG_INFO("");

    error_records = exm_list_count(exm_hook_errors);
    if (error_records > 0)
    {
        EXM_LOG_INFO("ERROR SUMMARY: %d errors from %d contexts",
                     error_records, error_records + alloc_records);
        EXM_LOG_INFO("");

        iter = exm_hook_errors;
        record = 1;
        while (iter)
        {
            EXM_LOG_INFO("1 error in context %d of %d",
                         record, error_records + alloc_records);
            exm_hook_error_disp(iter->data);
            record++;
            iter = iter->next;
        }
    }
    else
    {
        EXM_LOG_INFO("ERROR SUMMARY: 0 errors from %d contexts",
            error_records + alloc_records);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule EXM_UNUSED, DWORD ulReason, LPVOID lpReserved EXM_UNUSED);

BOOL APIENTRY DllMain(HMODULE hModule EXM_UNUSED, DWORD ulReason, LPVOID lpReserved)
{
    switch (ulReason)
    {
     case DLL_PROCESS_ATTACH:
         if (!_exm_mc_dll_init())
         {
             EXM_LOG_ERR("Can not initialize DLL");
             return FALSE;
         }

         EXM_LOG_DBG("process attach");

         break;
     case DLL_THREAD_ATTACH:
         EXM_LOG_DBG("thread attach");
         break;
     case DLL_THREAD_DETACH:
         EXM_LOG_DBG("thread detach");
         break;
     case DLL_PROCESS_DETACH:
     {
         EXM_LOG_DBG("process detach [%p]", lpReserved);

         _exm_mc_output();

         _exm_mc_dll_shutdown();

         break;
     }
    }

    return TRUE;
}
