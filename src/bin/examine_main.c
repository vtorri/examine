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
    _load_library  ll;
    _free_library  fl;

    char          *filename;
    char          *dll_fullname;
    int            dll_length;

    struct
    {
        HANDLE     process1;
        HANDLE     thread;
        HANDLE     process2;
    } child;

    struct Exm_Map map_size;
    struct Exm_Map map_file;
    struct Exm_Map map_process;

    DWORD          exit_code; /* actually the base address of the mapped DLL */
};

/****** Declaration *****/

static FARPROC _exm_symbol_get(const char *module, const char *symbol);

static Exm *exm_new(void);
static void exm_del(Exm *exm);
static int  exm_file_check(Exm *exm, const char *filename);
static int  exm_file_map(Exm *exm);
static void exm_file_unmap(Exm *exm);
static int  exm_dll_inject(Exm *exm);
static void exm_dll_eject(Exm *exm);

/****** Definition *****/

static FARPROC
_exm_symbol_get(const char *module, const char *symbol)
{
    HMODULE  mod;
    FARPROC  proc;

    EXM_PRINT_PUSH("loading library %s... ", module);
    mod = LoadLibrary(module);
    if (!mod)
    {
        EXM_PRINT_POP_ERROR("failed");
        return NULL;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("retrieving symbol %s... ", symbol);
    proc = GetProcAddress(mod, symbol);
    if (!proc)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto free_library;
    }
    EXM_PRINT_POP("done");

    FreeLibrary(mod);

    return proc;

  free_library:
    FreeLibrary(mod);

    return NULL;
}

static Exm *
exm_new(void)
{
#ifdef _MSC_VER
    char buf[MAX_PATH];
#endif
    Exm     *exm;
    HMODULE kernel32;
    size_t  l1;
    size_t  l2;
    DWORD   type;

    /* Check if CreateRemoteThread() is available. */
    /* MSDN suggests to check the availability of a */
    /* function instead of checking the Windows version. */

    kernel32 = LoadLibrary("kernel32.dll");
    if (!kernel32)
    {
        EXM_PRINT_ERROR("no kernel32.dll found");
        return 0;
    }

    if (!GetProcAddress(kernel32, "CreateRemoteThread"))
    {
        EXM_PRINT_ERROR("no CreateRemoteThread() found");
        goto free_kernel32;
    }

    exm = (Exm *)calloc(1, sizeof(Exm));
    if (!exm)
        goto free_kernel32;

    exm->ll = (_load_library)_exm_symbol_get("kernel32.dll", "LoadLibraryA");
    if (!exm->ll)
        goto free_exm;

    exm->fl = (_free_library)_exm_symbol_get("kernel32.dll", "FreeLibrary");
    if (!exm->fl)
        goto free_exm;

#ifdef _MSC_VER
    _getcwd(buf, MAX_PATH);
    l1 = strlen(buf);
#else
    l1 = strlen(PACKAGE_BIN_DIR);
#endif
    l2 = strlen("/examine_dll.dll");
    exm->dll_fullname = malloc(sizeof(char) * (l1 + l2 + 1));
    if (!exm->dll_fullname)
        goto free_exm;
#ifdef _MSC_VER
    _getcwd(buf, MAX_PATH);
    memcpy(exm->dll_fullname, buf, l1);
#else
    memcpy(exm->dll_fullname, PACKAGE_BIN_DIR, l1);
#endif
    memcpy(exm->dll_fullname + l1, "/examine_dll.dll", l2);
    exm->dll_fullname[l1 + l2] = '\0';

    if (GetBinaryType(exm->dll_fullname, &type))
    {
        EXM_PRINT_ERROR("%s is not a valid DLL", exm->dll_fullname);
        goto free_exm;
    }
    else
    {
        if (GetLastError() != ERROR_BAD_EXE_FORMAT)
        {
            EXM_PRINT_ERROR("%s is not a valid DLL", exm->dll_fullname);
            goto free_exm;
        }
    }

    exm->dll_length = l1 + l2 + 1;

    EXM_PRINT("DLL to inject: %s", exm->dll_fullname);

    FreeLibrary(kernel32);

    return exm;

  free_exm:
    free(exm);
  free_kernel32:
    FreeLibrary(kernel32);

    return 0;
}

static void
exm_del(Exm *exm)
{
    if (!exm)
        return;

    if (exm->child.process2)
        CloseHandle(exm->child.process2);
    if (exm->child.thread)
        CloseHandle(exm->child.thread);
    if (exm->child.process1)
        CloseHandle(exm->child.process1);
    free(exm->filename);
    free(exm->dll_fullname);
    free(exm);
}

static int
exm_file_check(Exm *exm, const char *filename)
{
    char *iter;
    size_t length;
    DWORD ret = -1;

    if (!filename || !*filename)
        return 0;

    if (!GetBinaryType(filename, &ret) ||
        ((ret != SCS_32BIT_BINARY) &&
         (ret != SCS_64BIT_BINARY)))
    {
        EXM_PRINT_ERROR("file %s is not an executable program or its path is wrong (%ld)", filename, ret);
        return 0;
    }

    length = strlen(filename);
    exm->filename = malloc(sizeof(char) * (length + 1));
    if (!exm->filename)
        return 0;
    memcpy(exm->filename, filename, length + 1);

    /* '/' replaced by '\' */
    iter = exm->filename;
    while (*iter)
    {
        if (*iter == '/') *iter = '\\';
        iter++;
    }

    return 1;
}

static int
exm_file_map(Exm *exm)
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
exm_file_unmap(Exm *exm)
{
    UnmapViewOfFile(exm->map_file.base);
    CloseHandle(exm->map_file.handle);
    UnmapViewOfFile(exm->map_size.base);
    CloseHandle(exm->map_size.handle);
}

static int
exm_dll_inject(Exm *exm)
{
    STARTUPINFO         si;
    PROCESS_INFORMATION pi;
    HANDLE              process;
    HANDLE              remote_thread;
    LPVOID              remote_string;
    DWORD               exit_code; /* actually the base address of the mapped DLL */

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    EXM_PRINT_PUSH("creating child process %s... ", exm->filename);
    if (!CreateProcess(NULL, exm->filename, NULL, NULL, TRUE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        EXM_PRINT_POP_ERROR("failed");
        return 0;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("waiting for the child process to initialize... ");
    if (!WaitForInputIdle(pi.hProcess, INFINITE))
    {
        EXM_PRINT_POP_ERROR("failed");
        goto close_handles;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("opening child process... ");
    process = OpenProcess(CREATE_THREAD_ACCESS, FALSE, pi.dwProcessId);
    if (!process)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto close_handles;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("mapping process handle 0x%p... ", pi.hProcess);
    exm->map_process.handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                                NULL, PAGE_READWRITE, 0, sizeof(HANDLE),
                                                "shared_process_handle");
    if (!exm->map_process.handle)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto close_process;
    }

    exm->map_process.base = MapViewOfFile(exm->map_process.handle, FILE_MAP_WRITE,
                                          0, 0, sizeof(HANDLE));
    if (!exm->map_process.base)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto close_process_handle;
    }

    CopyMemory(exm->map_process.base, &pi.hProcess, sizeof(HANDLE));
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("allocating virtual memory... ");
    remote_string = VirtualAllocEx(process, NULL, exm->dll_length, MEM_COMMIT, PAGE_READWRITE);
    if (!remote_string)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto unmap_process_handle;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("writing process in virtual memory... ");
    if (!WriteProcessMemory(process, remote_string, exm->dll_fullname, exm->dll_length, NULL))
    {
        EXM_PRINT_POP_ERROR("failed");
        goto virtual_free;
    }
    EXM_PRINT_POP("done");

    EXM_PRINT_PUSH("execute thread... ");
    remote_thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)exm->ll, remote_string, 0, NULL);
    if (!remote_thread)
    {
        EXM_PRINT_POP_ERROR("failed");
        goto virtual_free;
    }
    EXM_PRINT_POP("done");

    WaitForSingleObject(remote_thread, INFINITE);

    EXM_PRINT_PUSH("getting exit code... ");
    if (!GetExitCodeThread(remote_thread, &exit_code))
    {
        EXM_PRINT_POP_ERROR("failed");
        goto close_thread;
    }
    EXM_PRINT_POP("done");

    CloseHandle(remote_thread);
    VirtualFreeEx(process, remote_string, 0, MEM_RELEASE);

    EXM_PRINT("resume child process");
    ResumeThread(pi.hThread);

    exm->child.process1 = pi.hProcess;
    exm->child.thread = pi.hThread;
    exm->child.process2 = process;
    exm->exit_code = exit_code;

    return 1;

  close_thread:
    CloseHandle(remote_thread);
  virtual_free:
    VirtualFreeEx(process, remote_string, 0, MEM_RELEASE);
  unmap_process_handle:
    UnmapViewOfFile(exm->map_process.base);
  close_process_handle:
    CloseHandle(exm->map_process.handle);
  close_process:
    CloseHandle(process);
  close_handles:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}

static void
exm_dll_eject(Exm *exm)
{
    HANDLE thread;

    thread = CreateRemoteThread(exm->child.process2, NULL, 0,
                                (LPTHREAD_START_ROUTINE)exm->fl,
                                (void*)(uintptr_t)exm->exit_code, 0, NULL );
    WaitForSingleObject(thread, INFINITE );
    CloseHandle(thread );
    UnmapViewOfFile(exm->map_process.base);
    CloseHandle(exm->map_process.handle);
}

int main(int argc, char *argv[])
{
    Exm  *exm;

    if (argc < 2)
    {
        printf("Usage: %s file\n\n", argv[0]);
        return -1;
    }

    EXM_PRINT("Examine, a memory leak detector");
    EXM_PRINT("Copyright (c) 2013, and GNU GPL'd, by Vincent Torri");
    EXM_PRINT("Options:");

    exm = exm_new();
    if (!exm)
        return -1;

    if (!exm_file_check(exm, argv[1]))
        goto del_exm;

    EXM_PRINT("Command: %s", argv[1]);

    if (!exm_file_map(exm))
    {
        EXM_PRINT_ERROR("impossible to map filename %s", argv[1]);
        goto del_exm;
    }

    if (!exm_dll_inject(exm))
    {
        EXM_PRINT_ERROR("injection failed");
        goto unmap_exm;
    }

    Sleep(2000);
    EXM_PRINT("end of process");

    exm_dll_eject(exm);

    exm_file_unmap(exm);
    exm_del(exm);
    EXM_PRINT("resources freed");

    return 0;

  unmap_exm:
    exm_file_unmap(exm);
  del_exm:
    exm_del(exm);

    return -1;
}
