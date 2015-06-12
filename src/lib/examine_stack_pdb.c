/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2012-2013 Vincent Torri.
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

#include <stdlib.h>
#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <dbghelp.h>

#include "Examine.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


#define STACKWALK_MAX_NAMELEN 1024

struct _Exm_Stack_Data
{
    char *filename;
    char *function;
    unsigned int line;
};

struct _Exm_Stack
{
    HANDLE proc;
    HANDLE thread;
};

static HANDLE _exm_stack_process = NULL;
static HANDLE _exm_stack_thread = NULL;

static BOOL __stdcall _sw_read_memory_cb(HANDLE      hProcess,
                                         DWORD64     qwBaseAddress,
                                         PVOID       lpBuffer,
                                         DWORD       nSize,
                                         LPDWORD     lpNumberOfBytesRead)
{
    SIZE_T st;
    BOOL ret;

    ret = ReadProcessMemory(hProcess, (LPVOID)(DWORD_PTR)qwBaseAddress, lpBuffer, nSize, &st);
    *lpNumberOfBytesRead = (DWORD)st;
    return ret;
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API unsigned char
exm_stack_init(void)
{
    DWORD options;

    _exm_stack_process = GetCurrentProcess();
    _exm_stack_thread = GetCurrentThread();

    options = SymGetOptions();
    SymSetOptions(options |
                  SYMOPT_LOAD_LINES |
                  SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_UNDNAME |
                  SYMOPT_DEBUG);

    if (!SymInitialize(_exm_stack_process, NULL, TRUE))
        return 0;

    return 1;
}

EXM_API void
exm_stack_shutdown(void)
{
    SymCleanup(_exm_stack_process);
}

EXM_API Exm_List *
exm_stack_frames_get(void)
{
    CONTEXT context;
    STACKFRAME64 sf;
    IMAGEHLP_LINE64 line;
    SYMBOL_INFO *sym;
    Exm_List *list = NULL;
    DWORD arch;
    int frame_num;

    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    memset(&sf, 0, sizeof(STACKFRAME64));
#ifdef _M_IX86
    arch = IMAGE_FILE_MACHINE_I386;
    sf.AddrPC.Offset    = context.Eip;
    sf.AddrPC.Mode      = AddrModeFlat;
    sf.AddrFrame.Offset = context.Ebp;
    sf.AddrFrame.Mode   = AddrModeFlat;
    sf.AddrStack.Offset = context.Esp;
    sf.AddrStack.Mode   = AddrModeFlat;
#elif _M_X64
    arch = IMAGE_FILE_MACHINE_AMD64;
    sf.AddrPC.Offset    = context.Rip;
    sf.AddrPC.Mode      = AddrModeFlat;
    sf.AddrFrame.Offset = context.Rsp;
    sf.AddrFrame.Mode   = AddrModeFlat;
    sf.AddrStack.Offset = context.Rsp;
    sf.AddrStack.Mode   = AddrModeFlat;
#elif _M_IA64
    arch = IMAGE_FILE_MACHINE_IA64;
    sf.AddrPC.Offset     = context.StIIP;
    sf.AddrPC.Mode       = AddrModeFlat;
    sf.AddrFrame.Offset  = context.IntSp;
    sf.AddrFrame.Mode    = AddrModeFlat;
    sf.AddrBStore.Offset = context.RsBSP;
    sf.AddrBStore.Mode   = AddrModeFlat;
    sf.AddrStack.Offset  = context.IntSp;
    sf.AddrStack.Mode    = AddrModeFlat;
#else
# error "Platform not supported!"
#endif

    sym = (SYMBOL_INFO *)calloc(1, sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN + 1);
    if (!sym)
        return NULL;

    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = STACKWALK_MAX_NAMELEN;

    memset(&line, 0, sizeof(line));
    line.SizeOfStruct = sizeof(line);

    for (frame_num = 0; ; frame_num++)
    {
        if (!StackWalk64(arch, _exm_stack_process, _exm_stack_thread, &sf, &context,
                         _sw_read_memory_cb,
                         SymFunctionTableAccess64,
                         SymGetModuleBase64,
                         NULL))
        {
            printf("StackWalk64() failed\n");
            break;
        }

        if (sf.AddrPC.Offset == sf.AddrReturn.Offset)
        {
            printf("StackWalk64-Endless-Callstack!");
            break;
        }

        if ((sf.AddrPC.Offset != 0) && (sf.AddrReturn.Offset != 0))
        {
            Exm_Stack_Data *sw_data;

            sw_data = (Exm_Stack_Data *)calloc(1, sizeof(Exm_Stack_Data));
            if (sw_data)
            {
                DWORD64 offset_from_symbol;
                DWORD offset_from_line;
                size_t l;

                /* function name */
                if (SymFromAddr(_exm_stack_process, sf.AddrPC.Offset,
                                &offset_from_symbol, sym))
                {
                    l = strlen(sym->Name) + 1;
                    sw_data->function = (char *)malloc(l * sizeof(char));
                    if (sw_data->function)
                        memcpy(sw_data->function, sym->Name, l);
                }

                /* line number and file name */
                if (SymGetLineFromAddr64(_exm_stack_process, sf.AddrPC.Offset,
                                         &offset_from_line, &line))
                {
                    sw_data->line = line.LineNumber;
                    l = strlen(line.FileName) + 1;
                    sw_data->filename = (char *)malloc(l * sizeof(char));
                    if (sw_data->filename)
                        memcpy(sw_data->filename, line.FileName, l);
                }
                list = exm_list_append(list, sw_data);
            }
        }

        if (sf.AddrReturn.Offset == 0)
        {
            /* callstack_entry(SW_CALLSTACK_ENTRY_LAST, cse); */
            break;
        }
    }

    return list;
}

EXM_API const char *
exm_stack_data_filename_get(const Exm_Stack_Data *data)
{
    if (!data)
        return NULL;

    return data->filename;
}

EXM_API const char *
exm_stack_data_function_get(const Exm_Stack_Data *data)
{
    if (!data)
        return NULL;

    return data->function;
}

EXM_API unsigned int
exm_stack_data_line_get(const Exm_Stack_Data *data)
{
    if (!data)
        return 0;

    return data->line;
}

EXM_API void
exm_stack_data_free(void *ptr)
{
    Exm_Stack_Data *data;

    if (!ptr)
        return;

    data = (Exm_Stack_Data *)ptr;
    if (data->filename)
        free(data->filename);
    if (data->function)
        free(data->function);
    free(data);
}

EXM_API void
exm_stack_disp(const Exm_List *stack)
{
    const Exm_List *iter;
    unsigned char at = 1;

    iter = stack;
    while (iter)
    {
        Exm_Stack_Data *frame;

        frame = (Exm_Stack_Data *)iter->data;
        if (at)
        {
            EXM_LOG_INFO("   at 0x00000000: %s (%s:%u)",
                         exm_stack_data_function_get(frame),
                         exm_stack_data_filename_get(frame),
                         exm_stack_data_line_get(frame));
            at = 0;
        }
        else
            EXM_LOG_INFO("   by 0x00000000: %s (%s:%u)",
                         exm_stack_data_function_get(frame),
                         exm_stack_data_filename_get(frame),
                         exm_stack_data_line_get(frame));
        iter = iter->next;
    }

    EXM_LOG_INFO("");
}
