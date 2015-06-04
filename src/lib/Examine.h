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

#ifndef EXAMINE_H
#define EXAMINE_H

#ifdef EXM_API
# undef EXM_API
#endif

#ifdef _WIN32
# ifdef DLL_EXPORT
#  define EXM_API __declspec(dllexport)
# else
#  define EXM_API __declspec(dllimport)
# endif
#else
# ifdef __GNUC__
#  if __GNUC__ >= 4
#   define EXM_API __attribute__ ((visibility("default")))
#  else
#   define EXM_API
#  endif
# else
#  define EXM_API
# endif
#endif

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "examine_log.h"
#include "examine_list.h"
#include "examine_str.h"
#include "examine_map.h"
#include "examine_file.h"
#include "examine_main.h"
#include "examine_pe.h"
#include "examine_process.h"
#include "examine_injection.h"
#include "examine_stack.h"
#ifndef _WIN32
# include "examine_pe_unix.h"
#endif

#ifdef __cplusplus
}
#endif

#undef EXM_API
#define EXM_API

#endif /* EXAMINE_H */
