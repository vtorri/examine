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

#include "examine_log.h"
#include "examine_list.h"
#include "examine_file.h"
#include "examine_map.h"
#include "examine_pe.h"
#include "examine_stacktrace.h"
#include "examine_overloads.h"


typedef struct
{
    Exm_List *crt_names;
    Exm_List *dep_names;
} Exm_Memcheck;

static Exm_Memcheck _exm_memcheck_instance = { NULL, NULL };

static int
_exm_memcheck_dll_init(void)
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

    _exm_memcheck_instance.crt_names =  crt_names;
    _exm_memcheck_instance.dep_names =  dep_names;

    if (!exm_overload_init())
    {
        EXM_LOG_ERR("Can not initialize overload system");
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
_exm_memcheck_dll_shutdown(void)
{
    exm_overload_shutdown();
    exm_list_free(_exm_memcheck_instance.dep_names, free);
    exm_list_free(_exm_memcheck_instance.crt_names, free);
}

static void
_exm_memcheck_module_hook_set(HMODULE module, const char *lib_name, PROC old_function_proc, PROC new_function_proc)
{
    PIMAGE_IMPORT_DESCRIPTOR iid;
    PIMAGE_THUNK_DATA        thunk;
    ULONG                    size;

    iid = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    if (!iid)
        return;

    while (iid->Name)
    {
        PSTR module_name;

        module_name = (PSTR)((PBYTE) module + iid->Name);
        if (_stricmp(module_name, lib_name) == 0)
            break;
        iid++;
    }

    if (!iid->Name)
        return;

    thunk = (PIMAGE_THUNK_DATA)((PBYTE)module + iid->FirstThunk );
    while (thunk->u1.Function)
    {
        PROC *func;

        func = (PROC *)&thunk->u1.Function;
        if (*func == old_function_proc)
        {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD dwOldProtect;

            VirtualQuery(func, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
                return;

            *func = *new_function_proc;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);
            break;
        }
        thunk++;
    }
}

static void
_exm_memcheck_modules_hook(const char *lib_name, int crt)
{
    HMODULE lib_module;
    Exm_List *iter;
    unsigned int i;
    unsigned int start;
    unsigned int end;

    if (!crt)
    {
        start = 0;
        end = EXM_OVERLOAD_COUNT;
    }
    else
    {
        start = EXM_OVERLOAD_COUNT;
        end = EXM_OVERLOAD_COUNT_CRT;
    }

    lib_module = LoadLibrary(lib_name);

    for (i = start; i < end; i++)
    {
        exm_overload_func_proc_old_set(i, lib_module);
        if (!exm_overload_func_proc_old_get(i))
        {
            char buf[MAX_PATH];

            GetModuleFileName(lib_module, buf, sizeof(buf));
            EXM_LOG_ERR("Can not take address of %s in module %s %p [%s]",
                        exm_overload_func_proc_old_get(i),
                        lib_name,
                        lib_module,
                        buf);
        }
    }

    FreeLibrary(lib_module);

    iter = _exm_memcheck_instance.dep_names;
    while (iter)
    {
        HMODULE mod;

        mod = GetModuleHandle((char *)iter->data);
        if (mod)
        {
            for (i = start; i < end; i++)
                _exm_memcheck_module_hook_set(mod, lib_name,
                                              exm_overload_func_proc_old_get(i),
                                              exm_overload_func_proc_new_get(i));
        }
        iter = iter->next;
    }
}

static void
_exm_memcheck_dll_hook(void)
{
    Exm_List *iter;

    EXM_LOG_DBG("Hooking kernel32.dll");
    _exm_memcheck_modules_hook("kernel32.dll", 0);

    iter = _exm_memcheck_instance.crt_names;
    while (iter)
    {
        char *crt_basename;

        crt_basename = strrchr(iter->data, '\\');
        if (crt_basename)
        {
            crt_basename++;
            EXM_LOG_DBG("Hooking %s", crt_basename);
            _exm_memcheck_modules_hook(crt_basename, 1);
        }
        iter = iter->next;
    }
}

static void
_exm_memcheck_modules_unhook(const char *lib_name, int crt)
{
    Exm_List *iter;
    unsigned int i;
    unsigned int start;
    unsigned int end;

    if (!crt)
    {
        start = 0;
        end = EXM_OVERLOAD_COUNT;
    }
    else
    {
        start = EXM_OVERLOAD_COUNT;
        end = EXM_OVERLOAD_COUNT_CRT;
    }

    iter = _exm_memcheck_instance.dep_names;
    while (iter)
    {
        HMODULE mod;

        mod = GetModuleHandle((char *)iter->data);
        if (mod)
        {
            for (i = start; i < end; i++)
                _exm_memcheck_module_hook_set(mod, lib_name,
                                              exm_overload_func_proc_new_get(i),
                                              exm_overload_func_proc_old_get(i));
        }
        iter = iter->next;
    }
}

static void
_exm_memcheck_dll_unhook(void)
{
    Exm_List *iter;

    EXM_LOG_DBG("Unhooking kernel32.dll");
    _exm_memcheck_modules_unhook("kernel32.dll", 0);

    iter = _exm_memcheck_instance.crt_names;
    while (iter)
    {
        char *crt_basename;

        crt_basename = strrchr(iter->data, '\\');
        if (crt_basename)
        {
            crt_basename++;
            EXM_LOG_DBG("Unhooking %s", crt_basename);
            _exm_memcheck_modules_unhook(crt_basename, 1);
        }
        iter = iter->next;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule EXM_UNUSED, DWORD ulReason, LPVOID lpReserved EXM_UNUSED);

BOOL APIENTRY DllMain(HMODULE hModule EXM_UNUSED, DWORD ulReason, LPVOID lpReserved)
{
    switch (ulReason)
    {
     case DLL_PROCESS_ATTACH:
         if (!_exm_memcheck_dll_init())
         {
             EXM_LOG_ERR("Can not initialize DLL");
             return FALSE;
         }

         EXM_LOG_DBG("process attach");

         _exm_memcheck_dll_hook();

         break;
     case DLL_THREAD_ATTACH:
         EXM_LOG_DBG("thread attach");
         break;
     case DLL_THREAD_DETACH:
         EXM_LOG_DBG("thread detach");
         break;
     case DLL_PROCESS_DETACH:
     {
         Exm_List *iter;
         int nbr_alloc;
         int nbr_free;
         size_t bytes_allocated;
         size_t bytes_freed;

         EXM_LOG_DBG("process detach [%p]", lpReserved);
         nbr_alloc = exm_overload_data_alloc_list_count();
         nbr_free = exm_overload_data_free_list_count();
         bytes_allocated = 0;
         iter = exm_overload_data_alloc_list();
         while (iter)
         {
             bytes_allocated += exm_overload_data_alloc_size_get((Exm_Overload_Data_Alloc *)iter->data);
             iter = iter->next;
         }
         bytes_freed = 0;
         iter = exm_overload_data_free_list();
         while (iter)
         {
           bytes_freed += exm_overload_data_free_size_get((Exm_Overload_Data_Free *)iter->data);
             iter = iter->next;
         }

         if (nbr_alloc != nbr_free)
         {
             int records;
             int record;

             records = nbr_alloc - nbr_free;
             record = 1;
             iter = exm_overload_data_alloc_list();
             while (iter)
             {
                 Exm_Overload_Data_Alloc * da;
                 Exm_List *iter_stack;

                 da = (Exm_Overload_Data_Alloc *)iter->data;
                 if (exm_overload_data_alloc_nbr_free_get(da) != 0)
                 {
                     int at = 1;
                     EXM_LOG_INFO("%Iu bytes in 1 block(s) are definitely lost [%d/%d]",
                                  exm_overload_data_alloc_size_get(da), record, records);
                     iter_stack = exm_overload_data_alloc_stack_get(da);
                     while (iter_stack)
                     {
                         Exm_Sw_Data *frame;

                         frame = (Exm_Sw_Data *)iter_stack->data;
                         if (at)
                         {
                             EXM_LOG_INFO("   at 0x00000000: %s (%s:%u)",
                                          exm_sw_data_function_get(frame),
                                          exm_sw_data_filename_get(frame),
                                          exm_sw_data_line_get(frame));
                             at = 0;
                         }
                         else
                             EXM_LOG_INFO("   by 0x00000000: %s (%s:%u)",
                                          exm_sw_data_function_get(frame),
                                          exm_sw_data_filename_get(frame),
                                          exm_sw_data_line_get(frame));
                         iter_stack = iter_stack->next;
                     }
                     EXM_LOG_INFO("");
                     record++;
                 }
                 iter = iter->next;
             }
         }

         EXM_LOG_INFO("HEAP SUMMARY:");
         EXM_LOG_INFO("    in use at exit: %Iu bytes in %d blocks",
                      bytes_allocated - bytes_freed,
                      nbr_alloc - nbr_free);
         EXM_LOG_INFO("  total heap usage: %d allocs, %d frees, %Iu bytes allocated",
                      nbr_alloc, nbr_free, bytes_allocated);
         EXM_LOG_INFO("");
         EXM_LOG_INFO("LEAK SUMMARY:");
         EXM_LOG_INFO("   definitely lost: %Iu bytes in %d blocks",
                      bytes_allocated - bytes_freed,
                      nbr_alloc - nbr_free);

         _exm_memcheck_dll_unhook();
         _exm_memcheck_dll_shutdown();
         break;
     }
    }

    return TRUE;
}
