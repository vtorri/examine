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

#define EXM_PRINT(fmt, ...) \
    printf("==%ld== " fmt "\n", GetCurrentProcessId(), ## __VA_ARGS__);

#define EXM_PRINT_PUSH(fmt, ...) \
    printf("==%ld== " fmt, GetCurrentProcessId(), ## __VA_ARGS__);

#define EXM_PRINT_POP(fmt) \
    printf(fmt "\n");

#define EXM_PRINT_POP_ERROR(fmt) \
    printf(fmt "\n"); \
    printf("==%ld== Exiting... \n", GetCurrentProcessId());

#define EXM_PRINT_ERROR(fmt, ...) \
    printf("==%ld== ERROR: " fmt "\n", GetCurrentProcessId(), ## __VA_ARGS__); \
    printf("==%ld== Exiting... \n", GetCurrentProcessId());


#endif /* EXAMINE_LOG_H */
