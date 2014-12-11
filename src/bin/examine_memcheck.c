/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2014 Vincent Torri.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef _WIN32

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#ifdef _MSC_VER
# include <direct.h>
#endif

#include <examine_log.h>
#include <examine_list.h>
#include <examine_pe.h>

#include "examine_private.h"

#define PATCH 0


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

typedef HMODULE (*_load_library)(const char *);
typedef BOOL    (*_free_library)(HMODULE);

struct Exm_Map
{
    HANDLE handle;
    void *base;
};

typedef struct _Exm Exm;

struct _Exm
{
    _load_library  load_library;
    _free_library  free_library;

    char          *filename;
    char          *args;
    char          *dll_fullname;
    int            dll_length;

    struct
    {
        HANDLE        process1;
        HANDLE        thread;
        DWORD         process_id;
        HANDLE        process2;
        void         *entry_point;
        DWORD         old_protect;
        unsigned char oep[2];
    } child;

    struct Exm_Map map_size;
    struct Exm_Map map_file;
    struct Exm_Map map_process;

    DWORD          exit_code; /* actually the base address of the mapped DLL */
};

static int _exm_process_entry_point_unpatch(Exm *exm);

static FARPROC
_exm_symbol_get(const char *module, const char *symbol)
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

static Exm *
_exm_new(char *filename, char *args)
{
#ifdef _MSC_VER
    char buf[MAX_PATH];
#endif
    Exm *exm;
    Exm_Pe *pe;
    HMODULE kernel32;
    size_t l1;
    size_t l2;

    /* Check if CreateRemoteThread() is available. */
    /* MSDN suggests to check the availability of a */
    /* function instead of checking the Windows version. */

    kernel32 = LoadLibrary("kernel32.dll");
    if (!kernel32)
    {
        EXM_LOG_ERR("no kernel32.dll found");
        return NULL;
    }

    if (!GetProcAddress(kernel32, "CreateRemoteThread"))
    {
        EXM_LOG_ERR("no CreateRemoteThread() found");
        goto free_kernel32;
    }

    exm = (Exm *)calloc(1, sizeof(Exm));
    if (!exm)
        goto free_kernel32;

    exm->filename = filename;
    exm->args = args;

    pe = exm_pe_new(exm->filename);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.",
                    exm->filename);
        goto free_args;
    }

    if (exm_pe_is_dll(pe))
    {
        EXM_LOG_ERR("%s is a DLL, but must be an executable.",
                    exm->filename);
        exm_pe_free(pe);
        goto free_args;
    }

    exm->child.entry_point = exm_pe_entry_point_get(pe);

    exm_pe_free(pe);

    exm->load_library = (_load_library)_exm_symbol_get("kernel32.dll",
                                                       "LoadLibraryA");
    if (!exm->load_library)
        goto free_args;

    exm->free_library = (_free_library)_exm_symbol_get("kernel32.dll",
                                                       "FreeLibrary");
    if (!exm->free_library)
        goto free_args;

#ifdef _MSC_VER
    _getcwd(buf, MAX_PATH);
    l1 = strlen(buf);
#else
    l1 = strlen(PACKAGE_BIN_DIR);
#endif
    l2 = strlen("/examine_dll.dll");
    exm->dll_fullname = malloc(sizeof(char) * (l1 + l2 + 1));
    if (!exm->dll_fullname)
        goto free_args;
#ifdef _MSC_VER
    _getcwd(buf, MAX_PATH);
    memcpy(exm->dll_fullname, buf, l1);
#else
    memcpy(exm->dll_fullname, PACKAGE_BIN_DIR, l1);
#endif
    memcpy(exm->dll_fullname + l1, "/examine_dll.dll", l2);
    exm->dll_fullname[l1 + l2] = '\0';

    pe = exm_pe_new(exm->dll_fullname);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.",
                    exm->dll_fullname);
        goto free_dll_fullname;
    }

    if (!exm_pe_is_dll(pe))
    {
        EXM_LOG_ERR("%s is not a DLL, but must be a DLL.",
                    exm->dll_fullname);
        exm_pe_free(pe);
        goto free_dll_fullname;
    }

    exm_pe_free(pe);

    exm->dll_length = l1 + l2 + 1;

    EXM_LOG_DBG("DLL to inject: %s",
                exm->dll_fullname);

    FreeLibrary(kernel32);

    return exm;

    free_dll_fullname:
    free(exm->dll_fullname);
  free_args:
    free(exm->args);
    free(exm->filename);
    free(exm);
  free_kernel32:
    FreeLibrary(kernel32);

    return NULL;
}

static void
_exm_del(Exm *exm)
{
    if (exm->child.process2)
        CloseHandle(exm->child.process2);
    if (exm->child.thread)
        CloseHandle(exm->child.thread);
    if (exm->child.process1)
        CloseHandle(exm->child.process1);
    free(exm->dll_fullname);
    free(exm->args);
    free(exm->filename);
    free(exm);
}

static int
_exm_file_map(Exm *exm)
{
    int length;

    length = strlen(exm->filename) + 1;

    exm->map_size.handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                             NULL, PAGE_READWRITE, 0, sizeof(int),
                                             "shared_size");
    if (!exm->map_size.handle)
        return 0;

    exm->map_size.base = MapViewOfFile(exm->map_size.handle, FILE_MAP_WRITE,
                                       0, 0, sizeof(int));
    if (!exm->map_size.base)
        goto close_size_mapping;

    CopyMemory(exm->map_size.base, &length, sizeof(int));

    exm->map_file.handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                             NULL, PAGE_READWRITE, 0, length,
                                             "shared_filename");
    if (!exm->map_file.handle)
        goto unmap_size_base;
    exm->map_file.base = MapViewOfFile(exm->map_file.handle, FILE_MAP_WRITE,
                                       0, 0, length);
    if (!exm->map_file.base)
        goto close_file_mapping;
    CopyMemory(exm->map_file.base, exm->filename, length);

    return 1;

  close_file_mapping:
    CloseHandle(exm->map_file.handle);
  unmap_size_base:
    UnmapViewOfFile(exm->map_size.base);
  close_size_mapping:
    CloseHandle(exm->map_size.handle);

    return 0;
}

static void
_exm_file_unmap(Exm *exm)
{
    UnmapViewOfFile(exm->map_file.base);
    CloseHandle(exm->map_file.handle);
    UnmapViewOfFile(exm->map_size.base);
    CloseHandle(exm->map_size.handle);
}

static int
_exm_process_create(Exm *exm)
{
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    EXM_LOG_DBG("creating child process %s", exm->filename);

    if (!CreateProcess(NULL, exm->filename, NULL, NULL, TRUE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        EXM_LOG_ERR("creation of child process %s failed", exm->filename);
        return 0;
    }

    exm->child.process1 = pi.hProcess;
    exm->child.thread = pi.hThread;
    exm->child.process_id = pi.dwProcessId;

    return 1;
}

static void
_exm_process_close(Exm *exm)
{
    CloseHandle(exm->child.thread);
    CloseHandle(exm->child.process1);
}

static void
_exm_process_run(Exm *exm)
{
    EXM_LOG_DBG("resume child process thread 0x%p",
                exm->child.thread);

    ResumeThread(exm->child.thread);
    WaitForSingleObject(exm->child.process1, INFINITE);
}

static int
_exm_process_entry_point_patch(Exm *exm)
{
    CONTEXT context;
    unsigned char nep[2];

    EXM_LOG_DBG("patch entry point of the process handle 0x%p",
                exm->child.process1);

    if (!VirtualProtectEx(exm->child.process1, exm->child.entry_point,
                          2, PAGE_EXECUTE_READWRITE, &exm->child.old_protect))
    {
        EXM_LOG_ERR("can not protect page 0x%p in process handle 0x%p failed",
                    exm->child.entry_point,
                    exm->child.process1);
        return 0;
    }

    if (!ReadProcessMemory(exm->child.process1, exm->child.entry_point,
                           exm->child.oep, 2, NULL))
    {
        EXM_LOG_ERR("read memory 0x%p of process handle 0x%p failed",
                    exm->child.entry_point,
                    exm->child.process1);
        return 0;
    }

    /* patch with an infinite loop : JMP -2 */
    nep[0] = 0xEB;
    nep[1] = 0xFE;

    EXM_LOG_DBG("patching process 0x%p at entry point 0x%p",
                exm->child.process1,
                exm->child.entry_point);
    if (!WriteProcessMemory(exm->child.process1, exm->child.entry_point,
                            nep, 2, NULL))
    {
        EXM_LOG_ERR("write memory 0x%p of process handle 0x%p failed",
                    exm->child.entry_point,
                    exm->child.process1);
        return 0;
    }

    ResumeThread(exm->child.thread);

    while (1)
    {
        Sleep(100);
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(exm->child.thread, &context))
        {
            EXM_LOG_ERR("can not retrieve the context of thread 0x%p, unpatch entry point",
                        exm->child.thread);

            if (!_exm_process_entry_point_unpatch(exm))
            {
                EXM_LOG_ERR("can not unpatch entry point");
            }

            ResumeThread(exm->child.thread);

            return 0;
        }

#if defined (_AMD64_)
        if ((uintptr_t)context.Rip == (uintptr_t)exm->child.entry_point)
            break;
#elif defined (_X86_)
        if ((uintptr_t)context.Eip == (uintptr_t)exm->child.entry_point)
            break;
#else
# error "system not supported"
#endif
    }

    /* SetThreadContext(exm->child.thread, &context); */

    return 1;
}

static int
_exm_process_entry_point_unpatch(Exm *exm)
{
    DWORD new_protect;

    EXM_LOG_DBG("unpatch entry point of the process handle 0x%p",
                exm->child.process2);

    SuspendThread(exm->child.thread);

    if (!WriteProcessMemory(exm->child.process1, exm->child.entry_point,
                            exm->child.oep, 2, NULL))
    {
        EXM_LOG_ERR("write memory 0x%p of process handle 0x%p failed",
                    exm->child.entry_point,
                    exm->child.process1);
        return 0;
    }

    if (!VirtualProtectEx(exm->child.process1, exm->child.entry_point,
                          2, exm->child.old_protect, &new_protect))
    {
        EXM_LOG_ERR("can not protect page 0x%p in process handle 0x%p failed",
                    exm->child.entry_point, exm->child.process1);
        return 0;
    }

    return 1;
}

static int
_exm_dll_inject(Exm *exm)
{
    HANDLE              process;
    HANDLE              remote_thread;
    LPVOID              remote_string;
    SIZE_T              size;
    DWORD               exit_code; /* actually the base address of the mapped DLL */

    EXM_LOG_DBG("opening child process %s", exm->filename);
    process = OpenProcess(CREATE_THREAD_ACCESS, FALSE, exm->child.process_id);
    if (!process)
    {
        EXM_LOG_ERR("opening child process %s failed", exm->filename);
        return 0;
    }

    exm->child.process2 = process;

    EXM_LOG_DBG("mapping process handle 0x%p", exm->child.process2);
    exm->map_process.handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                                NULL, PAGE_READWRITE,
                                                0, sizeof(HANDLE),
                                                "shared_process_handle");
    if (!exm->map_process.handle)
    {
        EXM_LOG_ERR("mapping process handle 0x%p failed", exm->child.process2);
        goto close_process;
    }

    exm->map_process.base = MapViewOfFile(exm->map_process.handle, FILE_MAP_WRITE,
                                          0, 0, sizeof(HANDLE));
    if (!exm->map_process.base)
    {
        EXM_LOG_ERR("viewing map file handle 0x%p failed",
                    exm->map_process.handle);
        goto close_process_handle;
    }

    CopyMemory(exm->map_process.base, &exm->child.process2, sizeof(HANDLE));

    EXM_LOG_DBG("allocating virtual memory of process 0x%p (%d bytes)",
                exm->child.process2, exm->dll_length);
    remote_string = VirtualAllocEx(exm->child.process2, NULL, exm->dll_length,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_string)
    {
        EXM_LOG_ERR("allocating virtual memory of process 0x%p (%d bytes) failed",
                    exm->child.process2, exm->dll_length);
        goto unmap_process_handle;
    }

    EXM_LOG_DBG("writing process 0x%p in virtual memory at address 0x%p",
                exm->child.process2,
                remote_string);
    if (!WriteProcessMemory(exm->child.process2, remote_string,
                            exm->dll_fullname, exm->dll_length, &size))
    {
        EXM_LOG_ERR("writing process 0x%p in virtual memory failed",
                    exm->child.process2);
        goto virtual_free;
    }

    if ((int)size != exm->dll_length)
    {
        EXM_LOG_ERR("writing process 0x%p in virtual memory failed (wanted: %d, written: %d",
                    exm->child.process2,
                    exm->dll_length,
                    (int)size);
        goto virtual_free;
    }

    EXM_LOG_DBG("execute thread of process 0x%p",
                exm->child.process2);
    remote_thread = CreateRemoteThread(exm->child.process2, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)exm->load_library,
                                       remote_string, 0, NULL);
    if (!remote_thread)
    {
        EXM_LOG_ERR("execute thread for process 0x%p failed",
                    exm->child.process2);
        goto virtual_free;
    }

    WaitForSingleObject(remote_thread, INFINITE);

    EXM_LOG_DBG("getting exit code of thread 0x%p",
                remote_thread);
    if (!GetExitCodeThread(remote_thread, &exit_code))
    {
        EXM_LOG_ERR("getting exit code of thread 0x%p failed",
                    remote_thread);
        goto close_thread;
    }

    exm->exit_code = exit_code;
    CloseHandle(remote_thread);
    VirtualFreeEx(exm->child.process2, remote_string, 0, MEM_RELEASE);

    return 1;

  close_thread:
    CloseHandle(remote_thread);
  virtual_free:
    VirtualFreeEx(exm->child.process2, remote_string, 0, MEM_RELEASE);
  unmap_process_handle:
    UnmapViewOfFile(exm->map_process.base);
  close_process_handle:
    CloseHandle(exm->map_process.handle);
  close_process:
    CloseHandle(exm->child.process2);

    return 0;
}

static void
_exm_dll_eject(Exm *exm)
{
    HANDLE thread;

    thread = CreateRemoteThread(exm->child.process2, NULL, 0,
                                (LPTHREAD_START_ROUTINE)exm->free_library,
                                (void*)(uintptr_t)exm->exit_code, 0, NULL );
    WaitForSingleObject(thread, INFINITE );
    CloseHandle(thread);
    UnmapViewOfFile(exm->map_process.base);
    CloseHandle(exm->map_process.handle);
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


void
examine_memcheck_run(char *filename, char *args)
{
    Exm *exm;

    EXM_LOG_INFO("Examine, a memory leak detector");
    EXM_LOG_INFO("Copyright (c) 2013-2014, and GNU GPL2'd, by Vincent Torri");
    EXM_LOG_INFO("Options: --tool=memcheck");

    exm = _exm_new(filename, args);
    if (!exm)
        return;

    EXM_LOG_INFO("Command: %s %s",
                 filename, args);

    if (!_exm_file_map(exm))
    {
        EXM_LOG_ERR("impossible to map filename %s",
                    filename);
        goto del_exm;
    }

    if (!_exm_process_create(exm))
    {
        EXM_LOG_ERR("injection failed");
        goto unmap_exm;
    }

#if PATCH
    if (!_exm_process_entry_point_patch(exm))
    {
        EXM_LOG_ERR("can not patch entry point of the process handle 0x%p",
                    exm->child.process1);
        goto close_process;
    }
#endif

    if (!_exm_dll_inject(exm))
    {
        EXM_LOG_ERR("injection failed");
        goto unpatch_process;
    }

#if PATCH

    if (!_exm_process_entry_point_unpatch(exm))
    {
        EXM_LOG_ERR("can not patch entry point of the process handle 0x%p",
                    exm->child.process2);
        goto dll_eject;
    }
#endif

    _exm_process_run(exm);

    EXM_LOG_DBG("end of process");

    _exm_dll_eject(exm);

    _exm_file_unmap(exm);
    _exm_del(exm);
    EXM_LOG_DBG("resources freed");

    return;

  dll_eject:
    _exm_dll_eject(exm);
  unpatch_process:
    _exm_process_entry_point_unpatch(exm);
  close_process:
    _exm_process_close(exm);
  unmap_exm:
    _exm_file_unmap(exm);
  del_exm:
    _exm_del(exm);
}

#else

#include <examine_log.h>

#include "examine_private.h"

void
examine_memcheck_run(char *filename, char *args)
{
    EXM_LOG_ERR("memcheck tool not available on UNIX");
    (void)filename;
    (void)args;
}

#endif
