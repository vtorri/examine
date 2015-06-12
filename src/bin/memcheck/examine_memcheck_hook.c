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

#include <Examine.h>

#include "examine_memcheck_hook.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

typedef enum
{
    EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC,
    EXM_HOOK_ERROR_MULTIPLE_FREES,
    EXM_HOOK_ERROR_MISMATCHED_FREE
} Exm_Hook_Error;

struct _Exm_Hook_Error_Data
{
    Exm_Hook_Error error_type;
    union
    {
        struct
        {
            Exm_List *stack_free;
        } free_without_alloc;
        struct
        {
            Exm_List *stack_free;
            Exm_List *stack_alloc;
            Exm_List *stack_first_free;
            void *address_alloc;
            size_t size_alloc;
        } multiple_frees;
        struct
        {
            Exm_List *stack_free;
            Exm_List *stack_alloc;
            void *address_alloc;
            size_t size_alloc;
        } mismatched_free;

    } error;
};

static Exm_Hook_Error_Data*
_exm_hook_error_data_free_without_alloc_new(Exm_List *stack_free)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC;
    data->error.free_without_alloc.stack_free = stack_free;

    return data;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_multiple_frees_new(Exm_List *stack_free, Exm_Hook_Data_Alloc *da)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_MULTIPLE_FREES;
    data->error.multiple_frees.stack_free = stack_free;
    data->error.multiple_frees.stack_alloc = da->stack;
    data->error.multiple_frees.stack_first_free = da->stack_first_free;
    data->error.multiple_frees.address_alloc = da->data;
    data->error.multiple_frees.size_alloc = da->size;

    return data;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_mismatched_free_new(Exm_List *stack_free, Exm_Hook_Data_Alloc *da)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_MISMATCHED_FREE;
    data->error.mismatched_free.stack_free = stack_free;
    data->error.mismatched_free.stack_alloc = da->stack;
    data->error.mismatched_free.address_alloc = da->data;
    data->error.mismatched_free.size_alloc = da->size;

    return data;
}

static void
_exm_hook_error_data_del(void *ptr)
{
    Exm_Hook_Error_Data *data;

    if (!ptr)
        return;

    data = (Exm_Hook_Error_Data *)ptr;
    switch(data->error_type)
    {
        case EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC:
            exm_list_free(data->error.free_without_alloc.stack_free, exm_stack_data_free);
            break;
        case EXM_HOOK_ERROR_MULTIPLE_FREES:
            exm_list_free(data->error.multiple_frees.stack_free, exm_stack_data_free);
            break;
        case EXM_HOOK_ERROR_MISMATCHED_FREE:
            exm_list_free(data->error.mismatched_free.stack_free, exm_stack_data_free);
            break;
        default:
            break;
    }
}

typedef struct _Exm_Hook Exm_Hook;

struct _Exm_Hook
{
    Exm_Hook_Fct fct;
    FARPROC fct_proc_old;
    FARPROC fct_proc_new;
};

static Exm_Hook _exm_hook_instance[EXM_HOOK_FCT_COUNT];

static Exm_Hook_Data_Alloc *
_exm_hook_data_alloc_new(Exm_Hook_Fct fct, size_t size, void *data, Exm_List *stack)
{
    Exm_Hook_Data_Alloc *da;

    if (!stack)
        return NULL;

    da = (Exm_Hook_Data_Alloc *)calloc(1, sizeof(Exm_Hook_Data_Alloc));
    if (!da)
      return NULL;

    da->fct = fct;
    da->size = size;
    da->data = data;
    da->nbr_frees = 0;
    da->stack = stack;
    da->stack_first_free = NULL;

    return da;
}

static void
_exm_hook_data_alloc_del(void *ptr)
{
    Exm_Hook_Data_Alloc *da = ptr;

    if (!da)
        return;

    exm_list_free(da->stack, free);
    free(da);
}

static void
_exm_hook_allocations_sanitize(void *data)
{
    Exm_List *iter;

    iter = exm_hook_allocations;
    while (iter)
    {
        Exm_Hook_Data_Alloc *d;

        d = (Exm_Hook_Data_Alloc *)iter->data;
        if (data == d->data)
        {
            if (d->nbr_frees == 0)
            {
                /* we should never go there */
                EXM_LOG_ERR("CRITICAL ERROR: The OS allocated memory twice on the same address (0x%p)",
                            data);
            }

            exm_hook_allocations = exm_list_remove(exm_hook_allocations, data, _exm_hook_data_alloc_del);
        }

        iter = iter->next;
    }
}


static LPVOID WINAPI
_exm_hook_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    typedef LPVOID (WINAPI *exm_heap_alloc_t)(HANDLE hHeap,
                                              DWORD dwFlags,
                                              SIZE_T dwBytes);
    exm_heap_alloc_t ha;
    Exm_Hook_Data_Alloc *da;
    LPVOID data;

    EXM_LOG_WARN("HeapAlloc !!!");

    ha = (exm_heap_alloc_t)_exm_hook_instance[EXM_HOOK_FCT_HEAPALLOC].fct_proc_old;
    data = ha(hHeap, dwFlags, dwBytes);

    _exm_hook_allocations_sanitize(data);

    da = _exm_hook_data_alloc_new(EXM_HOOK_FCT_HEAPALLOC,
                                  dwBytes, data, exm_stack_frames_get());
    if (da)
    {
        exm_hook_allocations = exm_list_append(exm_hook_allocations, da);
    }

    exm_hook_summary.total_count_allocs++;
    exm_hook_summary.total_bytes_allocated += dwBytes;

    return data;
}

static BOOL WINAPI
_exm_hook_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    typedef BOOL (WINAPI *exm_heap_free_t)(HANDLE hHeap,
                                           DWORD dwFlags,
                                           LPVOID lpMem);
    exm_heap_free_t hf;
    Exm_Hook_Error_Data *data = NULL;
    Exm_List *iter_alloc;
    unsigned char alloc_not_found = 1;
    unsigned char no_free_error = 1;
    BOOL res = FALSE;

    EXM_LOG_WARN("HeapFree !!!");

    iter_alloc = exm_hook_allocations;
    while (iter_alloc)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter_alloc->data;
        if (da->data == lpMem)
        {
            alloc_not_found = 0;
            da->nbr_frees++;

            /* multiple frees */
            if (da->nbr_frees > 1)
            {
                data = _exm_hook_error_data_multiple_frees_new(exm_stack_frames_get(),
                                                               da);
                exm_hook_error_disp(data);
                exm_hook_errors = exm_list_append(exm_hook_errors, data);
                no_free_error = 0;
            }
            else
                da->stack_first_free = exm_stack_frames_get();

            /* mismatched alloc / free */
            if (da->fct != EXM_HOOK_FCT_HEAPALLOC)
            {
                data = _exm_hook_error_data_mismatched_free_new(exm_stack_frames_get(),
                                                                da);
                exm_hook_error_disp(data);
                exm_hook_errors = exm_list_append(exm_hook_errors, data);
            }

            break;
        }
        iter_alloc = iter_alloc->next;
    }

    if (alloc_not_found)
    {
        data = _exm_hook_error_data_free_without_alloc_new(exm_stack_frames_get());
        no_free_error = 0;
    }

    if (no_free_error)
    {
        hf = (exm_heap_free_t)_exm_hook_instance[EXM_HOOK_FCT_HEAPFREE].fct_proc_old;
        res = hf(hHeap, dwFlags, lpMem);
    }

    exm_hook_summary.total_count_frees++;

    return res;
}

static void *
_exm_hook_malloc(size_t size)
{
    typedef void *(*exm_malloc_t)(size_t size);
    exm_malloc_t ma;
    Exm_Hook_Data_Alloc *da;
    void *data;

    EXM_LOG_WARN("malloc !!!");

    ma = (exm_malloc_t)_exm_hook_instance[EXM_HOOK_FCT_MALLOC].fct_proc_old;
    data = ma(size);

    _exm_hook_allocations_sanitize(data);

    da = _exm_hook_data_alloc_new(EXM_HOOK_FCT_MALLOC,
                                  size, data, exm_stack_frames_get());
    if (da)
    {
        exm_hook_allocations = exm_list_append(exm_hook_allocations, da);
    }

    exm_hook_summary.total_count_allocs++;
    exm_hook_summary.total_bytes_allocated += size;

    return data;
}

static void *
_exm_hook_calloc(size_t nmemb, size_t size)
{
    typedef void *(*exm_calloc_t)(size_t nmemb, size_t size);
    exm_calloc_t ca;
    Exm_Hook_Data_Alloc *da;
    void *data;

    EXM_LOG_WARN("calloc !!!");

    ca = (exm_calloc_t)_exm_hook_instance[EXM_HOOK_FCT_CALLOC].fct_proc_old;
    data = ca(nmemb, size);

    _exm_hook_allocations_sanitize(data);

    da = _exm_hook_data_alloc_new(EXM_HOOK_FCT_CALLOC,
                                  size, data, exm_stack_frames_get());
    if (da)
    {
        exm_hook_allocations = exm_list_append(exm_hook_allocations, da);
    }

    exm_hook_summary.total_count_allocs++;
    exm_hook_summary.total_bytes_allocated += size;

    return data;
}

static void *
_exm_hook_realloc(void *ptr, size_t size)
{
    typedef void *(*exm_realloc_t)(void *ptr, size_t size);
    exm_realloc_t rea;
    Exm_Hook_Data_Alloc *da;
    void *data;

    EXM_LOG_WARN("realloc !!!");

    rea = (exm_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_REALLOC].fct_proc_old;
    data = rea(ptr, size);

    _exm_hook_allocations_sanitize(data);

    da = _exm_hook_data_alloc_new(EXM_HOOK_FCT_REALLOC,
                                  size, data, exm_stack_frames_get());
    if (da)
    {
        exm_hook_allocations = exm_list_append(exm_hook_allocations, da);
    }

    exm_hook_summary.total_count_allocs++;
    exm_hook_summary.total_bytes_allocated += size;

    return data;
}

static void
_exm_hook_free(void *memblock)
{
    typedef void (*exm_free_t)(void *memblock);
    exm_free_t f;
    Exm_Hook_Error_Data *data = NULL;
    Exm_List *iter_alloc;
    unsigned char alloc_not_found = 1;
    unsigned char no_free_error = 1;

    EXM_LOG_WARN("free !!!");

    iter_alloc = exm_hook_allocations;
    while (iter_alloc)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter_alloc->data;
        if (da->data == memblock)
        {
            alloc_not_found = 0;
            da->nbr_frees++;

            /* multiple frees */
            if (da->nbr_frees > 1)
            {
                data = _exm_hook_error_data_multiple_frees_new(exm_stack_frames_get(),
                                                               da);
                exm_hook_error_disp(data);
                exm_hook_errors = exm_list_append(exm_hook_errors, data);
                no_free_error = 0;
            }
            else
                da->stack_first_free = exm_stack_frames_get();

            /* mismatched alloc / free */
            if ((da->fct != EXM_HOOK_FCT_MALLOC) &&
                (da->fct != EXM_HOOK_FCT_CALLOC) &&
                (da->fct != EXM_HOOK_FCT_REALLOC))
            {
                data = _exm_hook_error_data_mismatched_free_new(exm_stack_frames_get(),
                                                                da);
                exm_hook_error_disp(data);
                exm_hook_errors = exm_list_append(exm_hook_errors, data);
            }

            break;
        }
        iter_alloc = iter_alloc->next;
    }

    if (alloc_not_found)
    {
        data = _exm_hook_error_data_free_without_alloc_new(exm_stack_frames_get());
        no_free_error = 0;
    }

    if (no_free_error)
    {
        f = (exm_free_t)_exm_hook_instance[EXM_HOOK_FCT_FREE].fct_proc_old;
        f(memblock);
    }

    exm_hook_summary.total_count_frees++;
}

static void
_exm_hook_fct_set(HMODULE module, const char *lib_name, PROC fct_proc_old, PROC fct_proc_new)
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
        if (*func == fct_proc_old)
        {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD dwOldProtect;

            VirtualQuery(func, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
                return;

            *func = *fct_proc_new;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);
            break;
        }
        thunk++;
    }
}

static void
_exm_hook_set(const char *mod_name, const Exm_List *dep_names, int idx_begin, int idx_end)
{
    const Exm_List *iter_dep;

    iter_dep = dep_names;
    while (iter_dep)
    {
        HMODULE mod_dep;

        mod_dep = GetModuleHandle((char *)iter_dep->data);
        if (mod_dep)
        {
            int i;

            for (i = idx_begin; i < idx_end; i++)
            {
                _exm_hook_fct_set(mod_dep, mod_name,
                                  _exm_hook_instance[i].fct_proc_old,
                                  _exm_hook_instance[i].fct_proc_new);
            }
        }

        iter_dep = iter_dep->next;
    }
}

static void
_exm_unhook_set(const char *mod_name, const Exm_List *dep_names, int idx_begin, int idx_end)
{
    const Exm_List *iter_dep;

    iter_dep = dep_names;
    while (iter_dep)
    {
        HMODULE mod_dep;

        mod_dep = GetModuleHandle((char *)iter_dep->data);
        if (mod_dep)
        {
            int i;

            for (i = idx_begin; i < idx_end; i++)
            {
                _exm_hook_fct_set(mod_dep, mod_name,
                                  _exm_hook_instance[i].fct_proc_new,
                                  _exm_hook_instance[i].fct_proc_old);
            }
        }

        iter_dep = iter_dep->next;
    }
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


#define EXM_HOOK_FCT_SET(type, mod, sym) \
    do \
    { \
        _exm_hook_instance[type].fct = type; \
        _exm_hook_instance[type].fct_proc_old = GetProcAddress(mod, #sym); \
        if (!_exm_hook_instance[type].fct_proc_old) \
        { \
            EXM_LOG_WARN("REDIR: redirection of %s failed", #sym);   \
            _exm_hook_instance[type].fct_proc_new = NULL; \
        } \
        else \
        { \
            char buf[MAX_PATH]; \
            _exm_hook_instance[type].fct_proc_new = (FARPROC)_exm_hook_ ## sym; \
            if (GetModuleFileName(mod, buf, sizeof(buf))) \
                EXM_LOG_INFO("REDIR: 0x%p (%s:%s) redirected to 0x%p (%s%s)", \
                             _exm_hook_instance[type].fct_proc_old, strrchr(buf, '\\') + 1, #sym, \
                             _exm_hook_instance[type].fct_proc_new, "_exm_hook_", #sym); \
            else \
                EXM_LOG_INFO("REDIR: 0x%p (%s) redirected to 0x%p (%s)", \
                             _exm_hook_instance[type].fct_proc_old, #sym, \
                             _exm_hook_instance[type].fct_proc_new, "_exm_hook_", #sym); \
        } \
    } while (0)


Exm_List *exm_hook_allocations;
Exm_List *exm_hook_errors;
Exm_Hook_Summary exm_hook_summary;

unsigned char
exm_hook_init(const Exm_List *crt_names, const Exm_List *dep_names)
{
    const Exm_List *iter_crt;
    char *mod_name;
    HMODULE mod;

    mod_name = "kernel32.dll";

    mod = LoadLibrary(mod_name);
    if (mod)
    {
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_HEAPALLOC, mod, HeapAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_HEAPFREE, mod, HeapFree);

        EXM_LOG_DBG("Hooking %s", mod_name);
        _exm_hook_set(mod_name, dep_names,
                      EXM_HOOK_FCT_KERNEL32_BEGIN, EXM_HOOK_FCT_KERNEL32_END);

        FreeLibrary(mod);
    }

    iter_crt = crt_names;
    while (iter_crt)
    {
        mod_name = (char *)iter_crt->data;

        mod = LoadLibrary(mod_name);
        if (mod)
        {
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_MALLOC, mod, malloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CALLOC, mod, calloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_REALLOC, mod, realloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_FREE, mod, free);

            EXM_LOG_DBG("Hooking %s", strrchr(mod_name, '\\') + 1);
            mod_name = strrchr(mod_name, '\\') + 1;
            _exm_hook_set(mod_name, dep_names,
                          EXM_HOOK_FCT_LIBC_BEGIN, EXM_HOOK_FCT_LIBC_END);

            FreeLibrary(mod);
        }
        iter_crt = iter_crt->next;
    }

    exm_stack_init();

    exm_hook_allocations = NULL;
    exm_hook_errors = NULL;
    memset(&exm_hook_summary, 0, sizeof(Exm_Hook_Summary));

    return 1;
}

void
exm_hook_shutdown(const Exm_List *crt_names, const Exm_List *dep_names)
{
    const Exm_List *iter_crt;
    char *mod_name;

    exm_list_free(exm_hook_errors, _exm_hook_error_data_del);
    exm_list_free(exm_hook_allocations, _exm_hook_data_alloc_del);

    exm_stack_shutdown();

    mod_name = "kernel32.dll";

    EXM_LOG_DBG("Unhooking %s", mod_name);
    _exm_unhook_set(mod_name, dep_names,
                    EXM_HOOK_FCT_KERNEL32_BEGIN, EXM_HOOK_FCT_KERNEL32_END);

    iter_crt = crt_names;
    while (iter_crt)
    {
        mod_name = (char *)iter_crt->data;

        EXM_LOG_DBG("Unhooking %s", strrchr(mod_name, '\\') + 1);
        mod_name = strrchr(mod_name, '\\') + 1;
        _exm_unhook_set(mod_name, dep_names,
                        EXM_HOOK_FCT_LIBC_BEGIN, EXM_HOOK_FCT_LIBC_END);

        iter_crt = iter_crt->next;
    }
}

void
exm_hook_error_disp(Exm_Hook_Error_Data *data)
{
    if (!data)
        return;

    switch (data->error_type)
    {
        case EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC:
            EXM_LOG_INFO("Invalid memory free without allocation");
            exm_stack_disp(data->error.multiple_frees.stack_free);
            break;
        case EXM_HOOK_ERROR_MULTIPLE_FREES:
            EXM_LOG_INFO("Multiple frees");
            exm_stack_disp(data->error.multiple_frees.stack_free);
            EXM_LOG_INFO("Address 0x%p is 0 bytes inside a block of size %zu free'd",
                         data->error.multiple_frees.address_alloc,
                         data->error.multiple_frees.size_alloc);
            exm_stack_disp(data->error.multiple_frees.stack_alloc);
            EXM_LOG_INFO("First free");
            exm_stack_disp(data->error.multiple_frees.stack_first_free);
            break;
        case EXM_HOOK_ERROR_MISMATCHED_FREE:
            EXM_LOG_INFO("Mismatched free / allocation");
            exm_stack_disp(data->error.multiple_frees.stack_free);
            EXM_LOG_INFO("Address 0x%p is 0 bytes inside a block of size %zu free'd",
                         data->error.multiple_frees.address_alloc,
                         data->error.multiple_frees.size_alloc);
            exm_stack_disp(data->error.multiple_frees.stack_alloc);
            break;
        default:
            break;
    }

    EXM_LOG_INFO("");
}
