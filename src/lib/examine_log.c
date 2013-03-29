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

#include <stdio.h>
#include <windows.h>

#include "examine_log.h"

static DWORD
_exm_log_print_level_color_get(int level)
{
    switch (level)
    {
        case EXM_LOG_LEVEL_ERR:
            return FOREGROUND_INTENSITY | FOREGROUND_RED;
        case EXM_LOG_LEVEL_WARN:
            return FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN;
        case EXM_LOG_LEVEL_INFO:
            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        case EXM_LOG_LEVEL_DBG:
            return FOREGROUND_INTENSITY | FOREGROUND_BLUE;
        default:
            return FOREGROUND_INTENSITY | FOREGROUND_BLUE;
    }
}

static void
_exm_log_print_prefix_func(HANDLE std_handle, Exm_Log_Level level)
{
    CONSOLE_SCREEN_BUFFER_INFO scbi;
    char *str;
    DWORD res;
    int s;

    if (!GetConsoleScreenBufferInfo(std_handle, &scbi))
        return;

    s = snprintf(NULL, 0, "==%ld==", GetCurrentProcessId());
    if (s == -1)
        return;

    str = (char *)malloc((s + 1) * sizeof(char));
    if (!str)
        return;

    s = snprintf(str, s + 1, "==%ld==", GetCurrentProcessId());
    if (s == -1)
        goto free_str;

    SetConsoleTextAttribute(std_handle, _exm_log_print_level_color_get(level));
    if (!WriteConsole(std_handle, str, s, &res, NULL))
    {
        SetConsoleTextAttribute(std_handle, scbi.wAttributes);
        goto free_str;
    }

    if ((int)res != s)
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %ld written\n", __FUNCTION__, s, res);

    SetConsoleTextAttribute(std_handle, scbi.wAttributes);

    if (!WriteConsole(std_handle, " ", 1, &res, NULL))
        goto free_str;

    if ((int)res != 1)
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %ld written\n", __FUNCTION__, 1, res);

    return;

  free_str:
    free(str);
}

static void
_exm_log_fprint_cb(DWORD console,
                   Exm_Log_Level level,
                   const char *fmt,
                   void *data, /* later for XML output */
                   va_list args)
{
    HANDLE std_handle;
    char *str;
    DWORD res;
    int s;

    std_handle = GetStdHandle(console);
    if (std_handle == INVALID_HANDLE_VALUE)
        return;

    s = vsnprintf(NULL, 0, fmt, args);
    if (s == -1)
        return;

    str = (char *)malloc((s + 2) * sizeof(char));
    if (!str)
        return;

    s = vsnprintf(str, s + 1, fmt, args);
    if (s == -1)
    {
        free(str);
        return;
    }
    str[s] = '\n';
    str[s + 1] = '\0';

    _exm_log_print_prefix_func(std_handle, level);
    if (!WriteConsole(std_handle, str, s + 1, &res, NULL))
    {
        free(str);
        return;
    }

    if ((int)res != (s + 1))
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %ld written\n", __FUNCTION__, s + 1, res);
}

/*** API ***/

void
exm_log_print_cb_stderr(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
    _exm_log_fprint_cb(STD_ERROR_HANDLE, level, fmt, data, args);
}

void
exm_log_print_cb_stdout(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
    _exm_log_fprint_cb(STD_OUTPUT_HANDLE, level, fmt, data, args);
}

void
exm_log_print(Exm_Log_Level level, const char *fmt, ...)
{
    va_list args;

    if (!fmt)
    {
        fprintf(stderr, "ERROR: %s() fmt == NULL\n", __FUNCTION__);
        return;
    }

    va_start(args, fmt);
    exm_log_print_cb_stderr(level, fmt, NULL, args);
    va_end(args);
}
