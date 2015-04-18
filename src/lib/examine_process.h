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

#ifndef EXM_PROCESS_H
#define EXM_PROCESS_H

typedef struct _Exm_Process Exm_Process;

Exm_Process *exm_process_new(const char *filename, const char *args);

void exm_process_del(Exm_Process *process);

HANDLE exm_process_get(const Exm_Process *process);

const char *exm_process_filename_get(const Exm_Process *process);

DWORD exm_process_id_get(const Exm_Process *process);

const Exm_List *exm_process_dep_names_get(const Exm_Process *process);

const Exm_List *exm_process_crt_names_get(const Exm_Process *process);

void exm_process_run(const Exm_Process *process);

void exm_process_pause(const Exm_Process *process);

int exm_process_entry_point_patch(Exm_Process *process);

int exm_process_entry_point_unpatch(const Exm_Process *process);

int exm_process_dependencies_set(Exm_Process *process);

#endif /* EXM_PROCESS_H */
