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

#include <stdio.h>

#ifdef _WIN32
# include <stdlib.h>
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <sys/types.h>
# include <unistd.h>
#endif

#include "examine_log.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


static Exm_Log_Level _exm_log_level = EXM_LOG_LEVEL_INFO;

#ifdef _WIN32

static WORD
_exm_log_print_level_color_get(int level)
{
    switch (level)
    {
        case EXM_LOG_LEVEL_ERR:
            return FOREGROUND_INTENSITY | FOREGROUND_RED;
        case EXM_LOG_LEVEL_WARN:
            return FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN;
        case EXM_LOG_LEVEL_DBG:
          return FOREGROUND_INTENSITY | FOREGROUND_GREEN;
        case EXM_LOG_LEVEL_INFO:
            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
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

    s = _snprintf(NULL, 0, "==%ld==", GetCurrentProcessId());
    if (s == -1)
        return;

    str = (char *)malloc((s + 1) * sizeof(char));
    if (!str)
        return;

    s = _snprintf(str, s + 1, "==%ld==", GetCurrentProcessId());
    if (s == -1)
        goto free_str;

    SetConsoleTextAttribute(std_handle, _exm_log_print_level_color_get(level));
    if (!WriteConsole(std_handle, str, s, &res, NULL))
    {
        SetConsoleTextAttribute(std_handle, scbi.wAttributes);
        goto free_str;
    }

    free(str);

    if ((int)res != s)
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %ld written\n", __FUNCTION__, s, res);

    SetConsoleTextAttribute(std_handle, scbi.wAttributes);

    if (!WriteConsole(std_handle, " ", 1, &res, NULL))
      return;

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

    s = _vsnprintf(NULL, 0, fmt, args);
    if (s == -1)
        return;

    str = (char *)malloc((s + 2) * sizeof(char));
    if (!str)
        return;

    s = _vsnprintf(str, s + 1, fmt, args);
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

    free(str);

    if ((int)res != (s + 1))
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %ld written\n", __FUNCTION__, s + 1, res);
}

#else /* !_WIN32 */

static const char *
_exm_log_print_level_color_get(int level)
{
    switch (level)
    {
        case EXM_LOG_LEVEL_ERR:
            return "\033[31m";
        case EXM_LOG_LEVEL_WARN:
            return "\033[33;1m";
        case EXM_LOG_LEVEL_DBG:
            return "\033[32;1m";
        case EXM_LOG_LEVEL_INFO:
            return "\033[1m";
        default:
            return "\033[34m";
    }
}

static void
_exm_log_fprint_cb(FILE *st,
                   Exm_Log_Level level,
                   const char *fmt,
                   void *data, /* later for XML output */
                   va_list args)
{
    fprintf(st, "%s==%u==\033[0m ",
            _exm_log_print_level_color_get(level),
            (unsigned int)getpid());
    vfprintf(st, fmt, args);
    fprintf(st, "\n");
}

#endif


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


void
exm_log_print_cb_stderr(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
#ifdef _WIN32
    _exm_log_fprint_cb(STD_ERROR_HANDLE, level, fmt, data, args);
#else
    _exm_log_fprint_cb(stderr, level, fmt, data, args);
#endif
}

void
exm_log_print_cb_stdout(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
#ifdef _WIN32
    _exm_log_fprint_cb(STD_OUTPUT_HANDLE, level, fmt, data, args);
#else
    _exm_log_fprint_cb(stdout, level, fmt, data, args);
#endif
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

    if (level <= _exm_log_level)
    {
        va_start(args, fmt);
        exm_log_print_cb_stderr(level, fmt, NULL, args);
        va_end(args);
    }
}

void exm_log_level_set(Exm_Log_Level level)
{
    if ((level < EXM_LOG_LEVEL_ERR) || (level >= EXM_LOG_LEVEL_LAST))
    {
        EXM_LOG_WARN("level %s not corect", level);
        return;
    }

    _exm_log_level = level;
}

Exm_Log_Level exm_log_level_get(void)
{
    return _exm_log_level;
}
