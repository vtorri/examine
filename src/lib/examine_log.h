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

#ifndef EXAMINE_LOG_H
#define EXAMINE_LOG_H

#include <stdarg.h>

typedef enum
{
    EXM_LOG_LEVEL_ERR,
    EXM_LOG_LEVEL_WARN,
    EXM_LOG_LEVEL_INFO,
    EXM_LOG_LEVEL_DBG,
    EXM_LOG_LEVEL_LAST
} Exm_Log_Level;

#define EXM_LOG(l, ...) \
    exm_log_print(l, __VA_ARGS__)

#define EXM_LOG_ERR(...) \
    EXM_LOG(EXM_LOG_LEVEL_ERR, __VA_ARGS__)

#define EXM_LOG_WARN(...) \
    EXM_LOG(EXM_LOG_LEVEL_WARN, __VA_ARGS__)

#define EXM_LOG_INFO(...) \
    EXM_LOG(EXM_LOG_LEVEL_INFO, __VA_ARGS__)

#define EXM_LOG_DBG(...) \
    EXM_LOG(EXM_LOG_LEVEL_DBG, __VA_ARGS__)

EXM_API void exm_log_print_cb_stderr(Exm_Log_Level level,
                                     const char *fmt,
                                     void *data,
                                     va_list args);

EXM_API void exm_log_print_cb_stdout(Exm_Log_Level level,
                                     const char *fmt,
                                     void *data,
                                     va_list args);

EXM_API void exm_log_print(Exm_Log_Level level, const char *fmt, ...);

EXM_API void exm_log_level_set(Exm_Log_Level level);

EXM_API Exm_Log_Level exm_log_level_get(void);

#endif /* EXAMINE_LOG_H */
