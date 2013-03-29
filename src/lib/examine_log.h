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

#define EXM_LOG(l, fmt, ...) \
    exm_log_print(l, fmt, ## __VA_ARGS__)

#define EXM_LOG_ERR(fmt, ...) \
    EXM_LOG(EXM_LOG_LEVEL_ERR, fmt, ## __VA_ARGS__)

#define EXM_LOG_WARN(fmt, ...) \
    EXM_LOG(EXM_LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)

#define EXM_LOG_INFO(fmt, ...) \
    EXM_LOG(EXM_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)

#define EXM_LOG_DBG(fmt, ...) \
    EXM_LOG(EXM_LOG_LEVEL_DBG, fmt, ## __VA_ARGS__)

void exm_log_print_cb_stderr(Exm_Log_Level level,
                             const char *fmt,
                             void *data,
                             va_list args);

void exm_log_print_cb_stdout(Exm_Log_Level level,
                             const char *fmt,
                             void *data,
                             va_list args);

void exm_log_print(Exm_Log_Level level, const char *fmt, ...);

#endif /* EXAMINE_LOG_H */
