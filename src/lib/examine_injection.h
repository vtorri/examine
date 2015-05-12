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

#ifndef EXM_INJECTION_H
#define EXM_INJECTION_H

typedef struct _Exm_Injection Exm_Injection;

EXM_API Exm_Injection *exm_injection_new(const char *filename);

EXM_API void exm_injection_del(Exm_Injection *inj);

EXM_API int exm_injection_dll_inject(Exm_Injection *inj, const Exm_Process *proc, const char *dll_file_name);

EXM_API void exm_injection_dll_eject(Exm_Injection *inj, const Exm_Process *proc);

#endif /* EXM_INJECTION_H */
