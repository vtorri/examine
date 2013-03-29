/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2012-2013 Vincent Torri.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <winnt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <imagehlp.h>

#include "examine_log.h"
#include "examine_list.h"
#include "examine_stacktrace.h"


typedef struct
{
    char *func_name_old;
    PROC  func_proc_old;
    PROC  func_proc_new;
} Exm_Hook_Overload;

typedef enum
{
    EXM_HOOK_FCT_HEAPALLOC,
    EXM_HOOK_FCT_HEAPFREE,
    EXM_HOOK_FCT_MALLOC,
    EXM_HOOK_FCT_FREE
} Exm_Hook_Fct;

typedef struct
{
    Exm_Hook_Fct fct;
    size_t size;
    void *data;  /* data returned by the allocator */
    int nbr_free_to_do; /* number of free to do, < 0 means double-free */
    Exm_List *stack;
    Exm_List *stack_free; /* the stack of the double free */
} Exm_Hook_Data_Alloc;

typedef struct
{
    Exm_Hook_Fct fct;
    size_t size;
    Exm_List *stack;
} Exm_Hook_Data_Free;

typedef struct
{
    Exm_List *alloc;
    Exm_List *free;
} Exm_Hook_Data;

Exm_Hook_Data_Alloc *
exm_hook_data_alloc_new(Exm_Hook_Fct fct, size_t size, void *data, Exm_List *stack)
{
    Exm_Hook_Data_Alloc *da;

    da = (Exm_Hook_Data_Alloc *)malloc(sizeof(Exm_Hook_Data_Alloc));
    if (!da)
      return NULL;

    da->fct = fct;
    da->size = size;
    da->data = data;
    da->nbr_free_to_do = 1;
    da->stack = stack;
    da->stack_free = NULL;

    return da;
}

void
exm_hook_data_alloc_free(void *ptr)
{
    Exm_Hook_Data_Alloc *da = ptr;

    if (!da)
        return;

    exm_list_free(da->stack_free, free);
    exm_list_free(da->stack, free);
    free(da);
}

Exm_Hook_Data_Free *
exm_hook_data_free_new(Exm_Hook_Fct fct, size_t size, Exm_List *stack)
{
    Exm_Hook_Data_Free *df;

    df = (Exm_Hook_Data_Free *)malloc(sizeof(Exm_Hook_Data_Free));
    if (!df)
      return NULL;

    df->fct = fct;
    df->size = size;
    df->stack = stack;

    return df;
}

void
exm_hook_data_free_free(void *ptr)
{
    Exm_Hook_Data_Free *df = ptr;

    if (!df)
        return;

    exm_list_free(df->stack, free);
    free(df);
}


/*
 * WARNING
 *
 * Mofidy the value of EXM_HOOK_OVERLOAD_COUNT and
 * EXM_HOOK_OVERLOAD_COUNT when adding other overloaded
 * functions in overloads_instance
 */
#define EXM_HOOK_OVERLOAD_COUNT 2
#define EXM_HOOK_OVERLOAD_COUNT_CRT 4

LPVOID WINAPI EXM_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL WINAPI EXM_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
void *EXM_malloc(size_t size);
void EXM_free(void *memblock);

Exm_Hook_Overload overloads_instance[EXM_HOOK_OVERLOAD_COUNT_CRT] =
{
    {
        "HeapAlloc",
        NULL,
        (PROC)EXM_HeapAlloc
    },
    {
        "HeapFree",
        NULL,
        (PROC)EXM_HeapFree
    },
    {
        "malloc",
        NULL,
        (PROC)EXM_malloc
    },
    {
        "free",
        NULL,
        (PROC)EXM_free
    }
};

typedef struct
{
    char             *filename;
    Exm_List         *modules;
    Exm_Hook_Overload overloads[EXM_HOOK_OVERLOAD_COUNT_CRT];
    char             *crt_name;
    Exm_Sw           *stacktrace;
} Exm_Hook;

typedef LPVOID (WINAPI *exm_heap_alloc_t) (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef BOOL   (WINAPI *exm_heap_free_t)  (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef void  *(*exm_malloc_t)            (size_t size);
typedef void   (*exm_free_t)              (void *memblock);

Exm_Hook exm_hook_instance;

static Exm_Hook_Data _exm_hook_data = { NULL, NULL };

LPVOID WINAPI EXM_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    exm_heap_alloc_t ha;
    Exm_Hook_Data_Alloc *da;
    LPVOID data;
    Exm_List *stack;

    ha = (exm_heap_alloc_t)exm_hook_instance.overloads[0].func_proc_old;
    data = ha(hHeap, dwFlags, dwBytes);

    printf("HeapAlloc !!! %p\n", data);

    stack = exm_sw_frames_get(exm_hook_instance.stacktrace);
    da = exm_hook_data_alloc_new(EXM_HOOK_FCT_HEAPALLOC, dwBytes, data, stack);
    if (da)
    {
        _exm_hook_data.alloc = exm_list_append(_exm_hook_data.alloc, da);
    }

    return data;
}

BOOL WINAPI EXM_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    exm_heap_free_t hf;
    Exm_Hook_Data_Free *df;
    BOOL res;
    Exm_List *stack;
    Exm_List *iter;
    size_t size = 0;

    printf("HeapFree !!! %p\n", lpMem);

    stack = exm_sw_frames_get(exm_hook_instance.stacktrace);

    iter = _exm_hook_data.alloc;
    while (iter)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter->data;
        if (lpMem == da->data)
        {
            da->nbr_free_to_do--;
            size = da->size;
            if (da->nbr_free_to_do < 0)
                da->stack_free = stack;
        }
        iter = iter->next;
    }

    /* TODO : size == 0 : free sans malloc */

    df = exm_hook_data_free_new(EXM_HOOK_FCT_HEAPFREE, size, stack);
    if (df)
    {
        _exm_hook_data.free = exm_list_append(_exm_hook_data.free, df);
    }

    hf = (exm_heap_free_t)exm_hook_instance.overloads[1].func_proc_old;
    res = hf(hHeap, dwFlags, lpMem);

    return res;
}

void *EXM_malloc(size_t size)
{
    exm_malloc_t ma;
    Exm_Hook_Data_Alloc *da;
    void *data;
    Exm_List *stack;

    ma = (exm_malloc_t)exm_hook_instance.overloads[2].func_proc_old;
    data = ma(size);

    printf("malloc !!! %p\n", data);
    stack = exm_sw_frames_get(exm_hook_instance.stacktrace);
    da = exm_hook_data_alloc_new(EXM_HOOK_FCT_MALLOC, size, data, stack);
    if (da)
    {
        _exm_hook_data.alloc = exm_list_append(_exm_hook_data.alloc, da);
    }

    return data;
}

void EXM_free(void *memblock)
{
    exm_free_t f;
    Exm_Hook_Data_Free *df;
    Exm_List *stack;
    Exm_List *iter;
    size_t size = 0;

    printf("free !!! %p\n", memblock);

    stack = exm_sw_frames_get(exm_hook_instance.stacktrace);

    iter = _exm_hook_data.alloc;
    while (iter)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter->data;
        if (memblock == da->data)
        {
            da->nbr_free_to_do--;
            size = da->size;
            if (da->nbr_free_to_do < 0)
                da->stack_free = stack;
        }
        iter = iter->next;
    }

    /* TODO : size == 0 : free sans malloc */

    df = exm_hook_data_free_new(EXM_HOOK_FCT_FREE, size, stack);
    if (df)
    {
        _exm_hook_data.free = exm_list_append(_exm_hook_data.free, df);
    }

    f = (exm_free_t)exm_hook_instance.overloads[3].func_proc_old;
    f(memblock);
}

static char *
_exm_hook_crt_name_get(void)
{
    HANDLE                   hf;
    HANDLE                   hmap;
    BYTE                    *base;
    IMAGE_DOS_HEADER        *dos_headers;
    IMAGE_NT_HEADERS        *nt_headers;
    IMAGE_IMPORT_DESCRIPTOR *import_desc;
    char                    *res = NULL;

    hf = CreateFile(exm_hook_instance.filename, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return NULL;

    hmap = CreateFileMapping(hf, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hmap)
        goto close_file;

    base = (BYTE *)MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
    if (!base)
        goto unmap;

    dos_headers = (IMAGE_DOS_HEADER *)base;
    nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)dos_headers + dos_headers->e_lfanew);
    import_desc = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)dos_headers + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import_desc->Characteristics)
    {
        if(IsBadReadPtr((BYTE *)dos_headers + import_desc->Name,1) == 0)
        {
            char *module_name;

            module_name = (char *)((BYTE *)dos_headers + import_desc->Name);
            EXM_LOG_DBG("Imports from %s\r",(BYTE *)dos_headers + import_desc->Name);
            if (lstrcmpi("msvcrt.dll", module_name) == 0)
            {
                EXM_LOG_DBG("msvcrt.dll !!");
                res = _strdup(module_name);
                break;
            }
            if (lstrcmpi("msvcr90.dll", module_name) == 0)
            {
                EXM_LOG_DBG("msvcr90.dll !!");
                res = _strdup(module_name);
                break;
            }
            if (lstrcmpi("msvcr90d.dll", module_name) == 0)
            {
                EXM_LOG_DBG("msvcr90d.dll !!");
                res = _strdup(module_name);
                break;
            }
            import_desc = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)import_desc + sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }
        else
            break;
    }

    UnmapViewOfFile(base);
    CloseHandle(hf);

    return res;

  unmap:
    UnmapViewOfFile(base);
  close_file:
    CloseHandle(hf);

    return NULL;
}

int
exm_modules_get(void)
{
    HMODULE      modules[1024];
    DWORD        modules_nbr;
    unsigned int i;

    /* FIXME: use EnumProcessModulesEx for windows >= Vista */
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &modules_nbr))
        return 0;

    for (i = 0; i < (modules_nbr / sizeof(HMODULE)); i++)
    {
        char   name[MAX_PATH] = "";
        char  *tmp;
        size_t l;
        DWORD  res;

        res = GetModuleFileName(modules[i], name, sizeof(name));
        if (!res)
          return 0;

        /* we skip the filename of the process */
        if (_stricmp(name, exm_hook_instance.filename) == 0)
            continue;

        /* we exit the loop if we find the injected DLL */
        tmp = strstr(name, "examine_dll.dll");
        if (tmp && (*(tmp + strlen("examine_dll.dll")) == '\0'))
            break;

        /* what remains is the list of the needed modules */
        l = strlen(name) + 1;
        tmp = malloc(sizeof(char) * l);
        if (!tmp)
            continue;
        memcpy(tmp, name, l);
        exm_hook_instance.modules = exm_list_append(exm_hook_instance.modules, tmp);
    }
    /* exm_list_print(exm_hook_instance.modules); */
    return 1;
}

int
exm_hook_init(void)
{
    HANDLE handle;
    void  *base;
    int    length;

    handle = OpenFileMapping(PAGE_READWRITE, FALSE, "shared_size");
    if (!handle)
        return 0;

    base = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, sizeof(int));
    if (!base)
    {
        CloseHandle(handle);
        return 0;
    }

    CopyMemory(&length, base, sizeof(int));
    UnmapViewOfFile(base);
    CloseHandle(handle);

    handle = OpenFileMapping(PAGE_READWRITE, FALSE, "shared_filename");
    if (!handle)
        return 0;

    base = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, length);
    if (!base)
    {
        CloseHandle(handle);
        return 0;
    }

    exm_hook_instance.filename = malloc(length * sizeof(char));
    if (!exm_hook_instance.filename)
    {
        UnmapViewOfFile(base);
        CloseHandle(handle);
        return 0;
    }

    CopyMemory(exm_hook_instance.filename, base, length);
    UnmapViewOfFile(base);
    CloseHandle(handle);

    printf(" ** filename : %s\n", exm_hook_instance.filename);

    exm_modules_get();

    memcpy(exm_hook_instance.overloads, overloads_instance, sizeof(exm_hook_instance.overloads));

    exm_hook_instance.crt_name = _exm_hook_crt_name_get();

    exm_hook_instance.stacktrace = exm_sw_init();

    return 1;
}

void
exm_hook_shutdown(void)
{
    if (exm_hook_instance.stacktrace)
        free(exm_hook_instance.stacktrace);
    if (exm_hook_instance.filename)
        free(exm_hook_instance.filename);
}

void
_exm_modules_hook_set(HMODULE module, const char *lib_name, PROC old_function_proc, PROC new_function_proc)
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

void
_exm_hook_modules_hook(const char *lib_name, int crt)
{
    HMODULE      mods[1024];
    HMODULE      lib_module;
    HMODULE      hook_module = NULL;
    DWORD        res;
    DWORD        mods_nbr;
    unsigned int i;
    unsigned int start;
    unsigned int end;

    if (!crt)
    {
        start = 0;
        end = EXM_HOOK_OVERLOAD_COUNT;
    }
    else
    {
        start = EXM_HOOK_OVERLOAD_COUNT;
        end = EXM_HOOK_OVERLOAD_COUNT_CRT;
    }

    lib_module = LoadLibrary(lib_name);

    for (i = start; i < end; i++)
        exm_hook_instance.overloads[i].func_proc_old = GetProcAddress(lib_module, exm_hook_instance.overloads[i].func_name_old);

    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &mods_nbr))
        return;

    for (i = 0; i < (mods_nbr / sizeof(HMODULE)); i++)
    {
        char name[256] = "";
        char *windir = getenv("WINDIR");
        char buf[256];

        res = GetModuleFileNameEx(GetCurrentProcess(), mods[i], name, sizeof(name));
        if (!res)
            continue;

        snprintf(buf, 255, "%s\\system32\\", windir);

        /* if (strcmp(buf, name) > 0) */
            /* printf(" $$$$ %s\n", name); */

        if (lstrcmp(name, exm_hook_instance.filename) != 0)
            continue;

        /* printf(" $$$$ %s\n", name); */
        hook_module = mods[i];
    }

    if (hook_module)
    {
        for (i = start; i < end; i++)
            _exm_modules_hook_set(hook_module, lib_name,
                                  exm_hook_instance.overloads[i].func_proc_old,
                                  exm_hook_instance.overloads[i].func_proc_new);
    }

    FreeLibrary(lib_module);
}

void
_exm_hook_modules_unhook(const char *lib_name, int crt)
{
    HMODULE      mods[1024];
    HMODULE      hook_module = NULL;
    DWORD        mods_nbr;
    DWORD        res;
    unsigned int i;
    unsigned int start;
    unsigned int end;

    if (!crt)
    {
        start = 0;
        end = EXM_HOOK_OVERLOAD_COUNT;
    }
    else
    {
        start = EXM_HOOK_OVERLOAD_COUNT;
        end = EXM_HOOK_OVERLOAD_COUNT_CRT;
    }

    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &mods_nbr))
        return;

    for (i = 0; i < (mods_nbr / sizeof(HMODULE)); i++)
    {
        char name[256] = "";

        res = GetModuleFileNameEx(GetCurrentProcess(), mods[i], name, sizeof(name));
        if (!res)
            continue;

        if (lstrcmp(name, exm_hook_instance.filename) != 0)
            continue;

        hook_module = mods[i];
    }

    if (hook_module)
    {
        for (i = start; i < end; i++)
            _exm_modules_hook_set(hook_module, lib_name,
                                  exm_hook_instance.overloads[i].func_proc_new,
                                  exm_hook_instance.overloads[i].func_proc_old);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule EXM_UNUSED, DWORD ulReason, LPVOID lpReserved EXM_UNUSED)
{
    switch (ulReason)
    {
     case DLL_PROCESS_ATTACH:
         EXM_LOG_DBG("process attach");
         if (!exm_hook_init())
             return FALSE;
         break;
     case DLL_THREAD_ATTACH:
         EXM_LOG_DBG("thread attach begin");
         _exm_hook_modules_hook("kernel32.dll", 0);
         if (exm_hook_instance.crt_name)
             _exm_hook_modules_hook(exm_hook_instance.crt_name, 1);
         EXM_LOG_DBG("thread attach end");
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

         EXM_LOG_DBG("process detach");
         nbr_alloc = exm_list_count(_exm_hook_data.alloc);
         nbr_free = exm_list_count(_exm_hook_data.free);
         bytes_allocated = 0;
         iter = _exm_hook_data.alloc;
         while (iter)
         {
             bytes_allocated += ((Exm_Hook_Data_Alloc *)iter->data)->size;
             iter = iter->next;
         }
         bytes_freed = 0;
         iter = _exm_hook_data.free;
         while (iter)
         {
             bytes_freed += ((Exm_Hook_Data_Free *)iter->data)->size;
             iter = iter->next;
         }

         if (nbr_alloc != nbr_free)
         {
             int records;
             int record;

             records = nbr_alloc - nbr_free;
             record = 1;
             iter = _exm_hook_data.alloc;
             while (iter)
             {
                 Exm_Hook_Data_Alloc * da;
                 Exm_List *iter_stack;

                 da = (Exm_Hook_Data_Alloc *)iter->data;
                 if (da->nbr_free_to_do != 0)
                 {
                     int at = 1;
                     EXM_LOG_INFO("%Iu bytes in 1 block(s) are definitely lost [%d/%d]",
                                  da->size, record, records);
                     iter_stack = da->stack;
                     while (iter_stack)
                     {
                         Exm_Sw_Data *frame;

                         frame = (Exm_Sw_Data *)iter_stack->data;
                         if (at)
                         {
                             EXM_LOG_INFO("   at 0x00000000: %s (%s:%d)",
                                          exm_sw_data_function_get(frame),
                                          exm_sw_data_filename_get(frame),
                                          exm_sw_data_line_get(frame));
                             at = 0;
                         }
                         else
                             EXM_LOG_INFO("   by 0x00000000: %s (%s:%d)",
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
         _exm_hook_modules_unhook("kernel32.dll", 0);
         if (exm_hook_instance.crt_name)
             _exm_hook_modules_unhook(exm_hook_instance.crt_name, 1);
         exm_hook_shutdown();
         break;
     }
    }

    return TRUE;
}
