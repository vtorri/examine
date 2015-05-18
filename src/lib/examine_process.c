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
#include <stdio.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#endif

#include <psapi.h>
#include <tlhelp32.h>

#include "Examine.h"

#include "examine_private_str.h"
#include "examine_private_process.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

#define EXM_PROCESS_CREATE_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

struct _Exm_Process
{
    char *filename;
    HANDLE process;
    HANDLE thread;
    void *entry_point;
    DWORD id;
    DWORD old_protection;
    unsigned char old_entry_point[2];
    Exm_List *crt_names;
    Exm_List *dep_names;
};

static const char *_exm_process_dep_names_supp[] =
{
    "API-MS-WIN-CORE-CONSOLE-L1-1-0.DLL",
    "API-MS-WIN-CORE-DATETIME-L1-1-0.DLL",
    "API-MS-WIN-CORE-DEBUG-L1-1-0.DLL",
    "API-MS-WIN-CORE-ERRORHANDLING-L1-1-0.DLL",
    "API-MS-WIN-CORE-FIBERS-L1-1-0.DLL",
    "API-MS-WIN-CORE-FILE-L1-1-0.DLL",
    "API-MS-WIN-CORE-HANDLE-L1-1-0.DLL",
    "API-MS-WIN-CORE-HEAP-L1-1-0.DLL",
    "API-MS-WIN-CORE-IO-L1-1-0.DLL",
    "API-MS-WIN-CORE-LIBRARYLOADER-L1-1-0.DLL",
    "API-MS-WIN-CORE-LOCALIZATION-L1-1-0.DLL",
    "API-MS-WIN-CORE-MEMORY-L1-1-0.DLL",
    "API-MS-WIN-CORE-MISC-L1-1-0.DLL",
    "API-MS-WIN-CORE-NAMEDPIPE-L1-1-0.DLL",
    "API-MS-WIN-CORE-PROCESSENVIRONMENT-L1-1-0.DLL",
    "API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL",
    "API-MS-WIN-CORE-PROFILE-L1-1-0.DLL",
    "API-MS-WIN-CORE-RTLSUPPORT-L1-1-0.DLL",
    "API-MS-WIN-CORE-STRING-L1-1-0.DLL",
    "API-MS-WIN-CORE-SYNCH-L1-1-0.DLL",
    "API-MS-WIN-CORE-SYSINFO-L1-1-0.DLL",
    "API-MS-WIN-CORE-THREADPOOL-L1-1-0.DLL",
    "API-MS-WIN-CORE-UTIL-L1-1-0.DLL",
    "API-MS-WIN-SECURITY-BASE-L1-1-0.DLL",
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "user32.dll",

    "msvcrt.dll",
    "msvcr80.dll",
    "msvcr80d.dll",
    "msvcr90.dll",
    "msvcr90d.dll",
    "msvcr100.dll",
    "msvcr100d.dll",
    "msvcr110.dll",
    "msvcr110d.dll",
    "msvcr120.dll",
    "msvcr120d.dll"
};

static const char *_exm_process_crt_names[] =
{
    "msvcrt.dll",
    "msvcr80.dll",
    "msvcr80d.dll",
    "msvcr90.dll",
    "msvcr90d.dll",
    "msvcr100.dll",
    "msvcr100d.dll",
    "msvcr110.dll",
    "msvcr110d.dll",
    "msvcr120.dll",
    "msvcr120d.dll"
};

static int
_exm_process_dep_cmp(const void *d1, const void *d2)
{
    return _stricmp(d1, d2);
}

#if 0

static Exm_Process *
_exm_process_new_from_module(MODULEENTRY32 *me32)
{
    Exm_Process *process;
    Exm_Pe *pe;

    process = (Exm_Process *)calloc(1, sizeof(Exm_Process));
    if (!process)
    {
        EXM_LOG_ERR("Can not allocate memory.");
        return NULL;
    }

    process->filename = _strdup(me32->szExePath);
    if (!process->filename)
    {
        EXM_LOG_ERR("Can not allocate memory.");
        goto free_process;
    }

    process->id = me32->th32ProcessID;
    process->process = OpenProcess(EXM_PROCESS_CREATE_ACCESS, FALSE, process->id);
    if (!process)
    {
        EXM_LOG_ERR("opening process from Id %ld failed", process->id);
        goto free_filename;
    }

    pe = exm_pe_new(process->filename);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", process->filename);
        goto close_process;
    }

    if (!exm_pe_is_dll(pe))
    {
        EXM_LOG_ERR("%s is an EXE, but must be a DLL.", process->filename);
        exm_pe_free(pe);
        goto close_process;
    }

    process->entry_point = (void *)exm_pe_entry_point_get(pe);
    exm_pe_free(pe);

    return process;

  close_process:
    CloseHandle(process->process);
  free_filename:
    free(process->filename);
  free_process:
    free(process);

    return NULL;
}

#endif


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


HANDLE
exm_process_get(const Exm_Process *process)
{
    return process->process;
}

const char *
exm_process_filename_get(const Exm_Process *process)
{
    return process->filename;
}

DWORD
exm_process_id_get(const Exm_Process *process)
{
    return process->id;
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API Exm_Process *
exm_process_new(const char *filename, const char *args)
{
    char buf[32768];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    Exm_Pe *pe;
    Exm_Process *process;

    process = (Exm_Process *)calloc(1, sizeof(Exm_Process));
    if (!process)
    {
        EXM_LOG_ERR("Can not allocate memory.");
        return NULL;
    }

    /* verify that filename is an executable */

    pe = exm_pe_new(filename);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", filename);
        goto free_process;
    }

    if (exm_pe_is_dll(pe))
    {
        EXM_LOG_ERR("%s is a DLL, but must be an executable.", filename);
        exm_pe_free(pe);
        goto free_process;
    }

    process->entry_point = (void *)exm_pe_entry_point_get(pe);
    exm_pe_free(pe);


    process->filename = _strdup(filename);
    if (!process->filename)
    {
        EXM_LOG_ERR("Can not allocate memory.");
        goto free_process;
    }

    /* and create the process */

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    buf[0] = '\0';
    exm_str_append_with_quotes(buf, filename);
    exm_str_append_with_quotes(buf, args);

    EXM_LOG_DBG("Creating child process %s", buf);

    if (!CreateProcess(NULL, buf, NULL, NULL, TRUE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        EXM_LOG_ERR("Creation of child process %s failed", filename);
        goto free_filename;
    }

    process->process = pi.hProcess;
    process->thread = pi.hThread;
    process->id = pi.dwProcessId;

    EXM_LOG_DBG("Process 0x%p created (thread: 0x%p thread ID: %ld)",
                process->process, process->thread, process->id);

    return process;

  free_filename:
    free(process->filename);
  free_process:
    free(process);

    return NULL;
}

EXM_API void
exm_process_del(Exm_Process *process)
{
    exm_list_free(process->dep_names, free);
    exm_list_free(process->crt_names, free);
    if (process->thread)
        CloseHandle(process->thread);
    CloseHandle(process->process);
    free(process->filename);
    free(process);
}

EXM_API const Exm_List *
exm_process_dep_names_get(const Exm_Process *process)
{
    return process->dep_names;
}

EXM_API const Exm_List *
exm_process_crt_names_get(const Exm_Process *process)
{
    return process->crt_names;
}

EXM_API void
exm_process_run(const Exm_Process *process)
{
    EXM_LOG_DBG("resume child process thread 0x%p",
                process->thread);

    ResumeThread(process->thread);
    WaitForSingleObject(process->process, INFINITE);
}

EXM_API void
exm_process_pause(const Exm_Process *process)
{
    EXM_LOG_DBG("pause child process thread 0x%p",
                process->thread);

    SuspendThread(process->thread);
    WaitForSingleObject(process->process, INFINITE);
}

EXM_API int
exm_process_entry_point_patch(Exm_Process *process)
{
    CONTEXT context;
    unsigned char nep[2];

    EXM_LOG_DBG("patch entry point of the process handle 0x%p",
                process->process);

    if (!VirtualProtectEx(process->process, process->entry_point,
                          2, PAGE_EXECUTE_READWRITE, &process->old_protection))
    {
        char *disp = NULL;
        char *msg;
        DWORD err;

        err = GetLastError();
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL,
                           err,
                           0, /* Default language */
                           (LPSTR)&msg,
                           0,
                           NULL))
        {
            disp = (char *)malloc((strlen(msg) + strlen("(00000) ") + 1) * sizeof(char));
            if (disp)
            {
                _snprintf(disp, strlen(msg) + strlen("(00000) ") + 1,
                          "(%5ld) %s", err, msg);
            }

            LocalFree(msg);
        }

        if (disp)
        {
            EXM_LOG_ERR("can not protect page 0x%p in process handle 0x%p failed: %s",
                        process->entry_point,
                        process->process,
                        disp);
            free(disp);
        }
        else
            EXM_LOG_ERR("can not protect page 0x%p in process handle 0x%p failed",
                        process->entry_point,
                        process->process);

        return 0;
    }

    if (!ReadProcessMemory(process->process, process->entry_point,
                           process->old_entry_point, 2, NULL))
    {
        EXM_LOG_ERR("read memory 0x%p of process handle 0x%p failed",
                    process->entry_point,
                    process->process);
        return 0;
    }

    /* patch with an infinite loop : JMP -2 */
    nep[0] = 0xEB;
    nep[1] = 0xFE;

    EXM_LOG_DBG("patching process 0x%p at entry point 0x%p",
                process->process,
                process->entry_point);
    if (!WriteProcessMemory(process->process, process->entry_point, nep, 2, NULL))
    {
        EXM_LOG_ERR("write memory 0x%p of process handle 0x%p failed",
                    process->entry_point,
                    process->process);
        return 0;
    }

    ResumeThread(process->thread);

    while (1)
    {
        Sleep(100);
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(process->thread, &context))
        {
            EXM_LOG_ERR("can not retrieve the context of thread 0x%p, unpatch entry point",
                        process->thread);

            if (!exm_process_entry_point_unpatch(process))
            {
                EXM_LOG_ERR("can not unpatch entry point");
            }

            ResumeThread(process->thread);

            return 0;
        }

#if defined (_AMD64_)
        if ((uintptr_t)context.Rip == (uintptr_t)process->entry_point)
            break;
#elif defined (_X86_)
        if ((uintptr_t)context.Eip == (uintptr_t)process->entry_point)
            break;
#else
# error "system not supported"
#endif
    }

    return 1;
}

EXM_API int
exm_process_entry_point_unpatch(const Exm_Process *process)
{
    DWORD new_protect;

    EXM_LOG_DBG("unpatch entry point of the process handle 0x%p",
                process->process);

    SuspendThread(process->thread);

    if (!WriteProcessMemory(process->process, process->entry_point,
                            process->old_entry_point, 2, NULL))
    {
        EXM_LOG_ERR("write memory 0x%p of process handle 0x%p failed",
                    process->entry_point,
                    process->process);
        return 0;
    }

    if (!VirtualProtectEx(process->process, process->entry_point,
                          2, process->old_protection, &new_protect))
    {
        EXM_LOG_ERR("can not protect page 0x%p in process handle 0x%p failed",
                    process->entry_point, process->process);
        return 0;
    }

    return 1;
}

EXM_API int
exm_process_dependencies_set(Exm_Process *process)
{
    MODULEENTRY32 me32;
    HANDLE h;

    EXM_LOG_DBG("Finding dependencies");
    h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                 process->id);
    if (h == INVALID_HANDLE_VALUE)
    {
        EXM_LOG_ERR("Can not retrieve the modules the process %s",
                    process->filename);
        return 0;
    }

    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(h, &me32))
    {
        EXM_LOG_ERR("Can not retrieve the first module the process %s",
                    process->filename);
        goto close_h;
    }

    do
    {
        size_t i;
        unsigned char is_found;

        EXM_LOG_DBG("Finding process %s in %s", me32.szExePath, process->filename);

        for (i = 0; i < (sizeof(_exm_process_crt_names) / sizeof(const char *)); i++)
        {
            if (_stricmp(me32.szModule, _exm_process_crt_names[i]) != 0)
                continue;

            /* FIXME: this following test should be useless as the list of modules has no duplicata */
            if (exm_list_data_is_found(process->crt_names,
                                       me32.szExePath,
                                       _exm_process_dep_cmp))
                continue;

            process->crt_names = exm_list_append(process->crt_names,
                                                 _strdup(me32.szExePath));
        }

        is_found = 0;
        for (i = 0; i < (sizeof(_exm_process_dep_names_supp) / sizeof(const char *)); i++)
        {
            if (_stricmp(me32.szModule, _exm_process_dep_names_supp[i]) == 0)
            {
                is_found = 1;
                break;
            }
        }

        if (!is_found &&
            /* FIXME: this following test should be useless as the list of modules has no duplicata */
            !exm_list_data_is_found(process->dep_names,
                                    me32.szExePath,
                                    _exm_process_dep_cmp))
            process->dep_names = exm_list_append(process->dep_names,
                                                 _strdup(me32.szExePath));
    } while(Module32Next(h, &me32));

    CloseHandle(h);

    return 1;

  close_h:
    CloseHandle(h);

    return 0;
}
