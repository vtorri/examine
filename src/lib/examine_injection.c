/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2015 Vincent Torri.
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
#endif

#include "Examine.h"

#include "examine_private_process.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


typedef HMODULE (*_load_library)(const char *);
typedef BOOL    (*_free_library)(HMODULE);

typedef struct _Exm_Injection_Map Exm_Injection_Map;

struct _Exm_Injection_Map
{
    HANDLE handle;
    void *base;
};

struct _Exm_Injection
{
    _load_library  load_library;
    _free_library  free_library;

    DWORD exit_code;

    char *filename;
    Exm_Injection_Map map_file_size;
    Exm_Injection_Map map_file_name;
    Exm_Injection_Map map_process;
};

static FARPROC
_exm_injection_symbol_get(const char *module, const char *symbol)
{
    HMODULE  mod;
    FARPROC  proc;

    EXM_LOG_DBG("loading library %s",
                module);
    mod = LoadLibrary(module);
    if (!mod)
    {
        EXM_LOG_ERR("loading library %s failed",
                    module);
        return NULL;
    }

    EXM_LOG_DBG("retrieving symbol %s", symbol);
    proc = GetProcAddress(mod, symbol);
    if (!proc)
    {
        EXM_LOG_ERR("retrieving symbol %s failed",
                    symbol);
        goto free_library;
    }

    FreeLibrary(mod);

    return proc;

  free_library:
    FreeLibrary(mod);

    return NULL;
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


/**
 * @brief Create a newly allocated #Exm_Injection object.
 *
 * @param[in] filename The filename of the PE file in which the DLL will
 * be injected.
 * @return The newly allocated #Exm_Injection object.
 *
 * This function creates a newly allocated #Exm_Injection object. Its
 * members will be set accordingly to @p filename. It checks if
 * CreateRemoteThread(), LoadLibraryA() and FreeLibrary() are
 * available. On failure, @c NULL is returned.
 */
EXM_API Exm_Injection *
exm_injection_new(const char *filename)
{
    Exm_Injection *inj;

    /* Check if CreateRemoteThread() is available. */
    /* MSDN suggests to check the availability of a */
    /* function instead of checking the Windows version. */
    if (!_exm_injection_symbol_get("kernel32.dll", "CreateRemoteThread"))
    {
        EXM_LOG_ERR("CreateRemoteThread() not found");
        return NULL;
    }

    EXM_LOG_DBG("CreateRemoteThread() found");

    inj = (Exm_Injection *)calloc(1, sizeof(Exm_Injection));
    if (!inj)
        return NULL;

    inj->load_library = (_load_library)_exm_injection_symbol_get("kernel32.dll",
                                                                 "LoadLibraryA");
    if (!inj->load_library)
        goto free_inj;

    inj->free_library = (_free_library)_exm_injection_symbol_get("kernel32.dll",
                                                                 "FreeLibrary");
    if (!inj->free_library)
        goto free_inj;

    inj->filename = _strdup(filename);
    if (!inj->filename)
    {
        EXM_LOG_ERR("Can not allocate memory for file name %s", inj->filename);
        goto free_inj;
    }

    return inj;

  free_inj:
    free(inj);

    return NULL;
}

EXM_API void
exm_injection_del(Exm_Injection *inj)
{
    if (!inj)
        return;

    free(inj->filename);
    free(inj);
}

/**
 * @brief Inject the given DLL in the given loaded module.
 *
 * @param[in] inj The injection object.
 * @param[in] proc The process to be patched.
 * @param[in] The name of the DLL to be injected.
 * @return 1 on success, 0 otherwise.
 *
 * This function injects the DLL of name @p dll_file_name in the
 * process @p proc, with the injection object @p inj. It returns 1 on
 * success, 0 otherwise.
 */
EXM_API int
exm_injection_dll_inject(Exm_Injection *inj, const Exm_Process *proc, const char *dll_file_name)
{
    char buf[MAX_PATH];
    char *tmp;
    char *dll_full_file_name;
    Exm_Pe *pe;
    LPVOID remote_string;
    HANDLE remote_thread;
    HANDLE process;
    SIZE_T size;
    size_t l1;
    size_t l2;
    size_t dll_full_file_name_length;

    /*
     * We get the full file name of the injected DLL. It must be in
     * the directory of the calling process.
     */

    if (!GetModuleFileName(GetModuleHandle(NULL), buf, sizeof(buf)))
    {
        EXM_LOG_ERR("Can not retrieve the path of the calling process");
        return 0;
    }

    /* GetModuleFileName() returns path with \ as separator */
    tmp = strrchr(buf, '\\');
    /* tmp should never be NULL, but in case... */
    if (!tmp)
    {
        EXM_LOG_ERR("Can not retrieve the path of the calling process");
        return 0;
    }

    l1 = (tmp - buf);
    l2 = strlen(dll_file_name) + 1;

    dll_full_file_name = (char *)malloc((l1 + l2 + 1) * sizeof(char));
    if (!dll_full_file_name)
    {
        EXM_LOG_ERR("Can not allocate memory");
        return 0;
    }

    memcpy(dll_full_file_name, buf, l1);
    dll_full_file_name[l1] = '\\';
    memcpy(dll_full_file_name + l1 + 1, dll_file_name, l2);

    /* extra check: if the injected DLL is malformed */
    pe = exm_pe_new(dll_full_file_name);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", dll_full_file_name);
        goto free_dll_full_file_name;
    }

    if (!exm_pe_is_dll(pe))
    {
        EXM_LOG_ERR("%s is not a DLL, but must be a DLL.",
                    dll_full_file_name);
        exm_pe_free(pe);
        goto free_dll_full_file_name;
    }

    exm_pe_free(pe);

    dll_full_file_name_length = l1 + l2 + 1;

    EXM_LOG_DBG("DLL to inject: %s", dll_full_file_name);

    /*
     * Now the we have the DLL full file name and length, we allocate
     * a new memory region inside the process' address space
     */

    process = exm_process_get(proc);

    EXM_LOG_DBG("allocating virtual memory of process 0x%p (%d bytes)",
                process, dll_full_file_name_length);
    remote_string = VirtualAllocEx(process, NULL, dll_full_file_name_length,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_string)
    {
        EXM_LOG_ERR("allocating virtual memory of process 0x%p (%d bytes) failed",
                    process, dll_full_file_name_length);
        goto free_dll_full_file_name;
    }

    EXM_LOG_DBG("writing the argument to LoadLibraryA() to the process' newly allocated region 0x%p",
                remote_string);
    if (!WriteProcessMemory(process, remote_string,
                            dll_full_file_name, dll_full_file_name_length, &size))
    {
        EXM_LOG_ERR("writing process 0x%p in virtual memory failed",
                    process);
        goto virtual_free;
    }

    if (size != dll_full_file_name_length)
    {
        EXM_LOG_ERR("writing process 0x%p in virtual memory failed (wanted: %d, written: %d",
                    process,
                    dll_full_file_name_length,
                    size);
        goto virtual_free;
    }

    EXM_LOG_DBG("Injecting the DLL into the process' address space");
    remote_thread = CreateRemoteThread(process, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)inj->load_library,
                                       remote_string, 0, NULL);
    if (!remote_thread)
    {
        EXM_LOG_ERR("Injection of the DLL failed");
        goto virtual_free;
    }

    WaitForSingleObject(remote_thread, INFINITE);

    EXM_LOG_DBG("getting exit code of thread 0x%p", remote_thread);
    if (!GetExitCodeThread(remote_thread, &inj->exit_code))
    {
        EXM_LOG_ERR("getting exit code of thread 0x%p failed", remote_thread);
        goto close_thread;
    }

    CloseHandle(remote_thread);
    VirtualFreeEx(process, remote_string, 0, MEM_RELEASE);
    free(dll_full_file_name);

    return 1;

  close_thread:
    CloseHandle(remote_thread);
  virtual_free:
    VirtualFreeEx(process, remote_string, 0, MEM_RELEASE);
  free_dll_full_file_name:
    free(dll_full_file_name);

    return 0;
}

EXM_API void
exm_injection_dll_eject(Exm_Injection *inj, const Exm_Process *proc)
{
    HANDLE thread;

    thread = CreateRemoteThread(exm_process_get(proc), NULL, 0,
                                (LPTHREAD_START_ROUTINE)inj->free_library,
                                (void*)(uintptr_t)inj->exit_code, 0, NULL );
    WaitForSingleObject(thread, INFINITE );
    CloseHandle(thread);
}
