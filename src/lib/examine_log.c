/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2012-2016 Vincent Torri.
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

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#elif !defined alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif !defined HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#include <stdio.h>

#ifdef _WIN32
# include <stdlib.h>
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
# include <io.h>
#else
# include <sys/types.h>
# include <unistd.h>
#endif

#include "Examine.h"
#include "examine_private_log.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


static Exm_Log_Level _exm_log_level = EXM_LOG_LEVEL_INFO;

#ifdef _WIN32

static HANDLE _exm_log_handle_stdout = NULL;
static HANDLE _exm_log_handle_stderr = NULL;

static WORD
_exm_log_print_level_color_get(int level, WORD original_background)
{
    WORD foreground;

    switch (level)
    {
        case EXM_LOG_LEVEL_ERR:
            foreground = FOREGROUND_INTENSITY | FOREGROUND_RED;
            break;
        case EXM_LOG_LEVEL_WARN:
            foreground = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN;
            break;
        case EXM_LOG_LEVEL_DBG:
          foreground = FOREGROUND_INTENSITY | FOREGROUND_GREEN;
          break;
        case EXM_LOG_LEVEL_INFO:
            foreground = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            break;
        default:
            foreground = FOREGROUND_INTENSITY | FOREGROUND_BLUE;
            break;
    }

    return original_background | foreground;
}

static void
_exm_log_print_prefix_func(FILE *st, Exm_Log_Level level)
{
    CONSOLE_SCREEN_BUFFER_INFO scbi_stdout;
    CONSOLE_SCREEN_BUFFER_INFO scbi_stderr;
    CONSOLE_SCREEN_BUFFER_INFO *scbi;
    HANDLE handle;
    WORD color;
    BOOL use_color;

    if (_exm_log_handle_stdout != INVALID_HANDLE_VALUE)
    {
        if (!GetConsoleScreenBufferInfo(_exm_log_handle_stdout, &scbi_stdout))
            return;
    }

    if (_exm_log_handle_stderr != INVALID_HANDLE_VALUE)
    {
        if (!GetConsoleScreenBufferInfo(_exm_log_handle_stderr, &scbi_stderr))
            return;
    }

    handle  = (st == stdout) ? _exm_log_handle_stdout : _exm_log_handle_stderr;
    scbi = (st == stdout) ? &scbi_stdout : &scbi_stderr;
    use_color = (_isatty(_fileno(st)) != 1) && (handle != INVALID_HANDLE_VALUE);
    color = use_color ? _exm_log_print_level_color_get(level, scbi->wAttributes & ~7) : 0;
    if (use_color)
    {
        fflush(st);
        SetConsoleTextAttribute(handle, color);
    }

    fprintf(st, "==%lu==", GetCurrentProcessId());
    if (use_color)
    {
        fflush(st);
        SetConsoleTextAttribute(handle, scbi->wAttributes);
    }
    fputc(' ', st);
}

static void
_exm_log_fprint_cb(FILE *st,
                   Exm_Log_Level level,
                   const char *fmt,
                   void *data, /* later for XML output */
                   va_list args)
{
    char *str;
    int res;
    int s;

    s = _vsnprintf(NULL, 0, fmt, args);
    if (s == -1)
        return;

    str = (char *)alloca((s + 2) * sizeof(char));

    s = _vsnprintf(str, s + 1, fmt, args);
    if (s == -1)
        return;

    str[s] = '\n';
    str[s + 1] = '\0';

    _exm_log_print_prefix_func(st, level);
    res = fprintf(st, str, s + 1);
    if (res != (s + 1))
        fprintf(stderr, "ERROR: %s(): want to write %d bytes, %d written\n", __FUNCTION__, s + 1, res);
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


void
exm_log_init(void)
{
#ifdef _WIN32
    _exm_log_handle_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    _exm_log_handle_stderr = GetStdHandle(STD_ERROR_HANDLE);
#endif
}

void
exm_log_shutdown(void)
{
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API void
exm_log_print_cb_stderr(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
    _exm_log_fprint_cb(stderr, level, fmt, data, args);
}

EXM_API void
exm_log_print_cb_stdout(Exm_Log_Level level,
                        const char *fmt,
                        void *data,
                        va_list args)
{
    _exm_log_fprint_cb(stdout, level, fmt, data, args);
}

EXM_API void
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

EXM_API void exm_log_level_set(Exm_Log_Level level)
{
    if ((level < EXM_LOG_LEVEL_ERR) || (level >= EXM_LOG_LEVEL_LAST))
    {
        EXM_LOG_WARN("level %s not corect", level);
        return;
    }

    _exm_log_level = level;
}

EXM_API Exm_Log_Level exm_log_level_get(void)
{
    return _exm_log_level;
}
