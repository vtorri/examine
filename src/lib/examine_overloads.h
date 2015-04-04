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

#ifndef EXAMINE_OVERLOAD_H
#define EXAMINE_OVERLOAD_H

/*
 * WARNING
 *
 * Mofidy the value of EXM_OVERLOAD_COUNT and
 * EXM_OVERLOAD_COUNT_CRT when adding other overloaded
 * functions in overloads_instance
 */
#define EXM_OVERLOAD_COUNT 2
#define EXM_OVERLOAD_COUNT_CRT 4

typedef struct _Exm_Overload Exm_Overload;
typedef struct _Exm_Overload_Data_Alloc Exm_Overload_Data_Alloc;
typedef struct _Exm_Overload_Data_Free Exm_Overload_Data_Free;

int exm_overload_init(void);
void exm_overload_shutdown(void);

void exm_overload_func_proc_old_set(unsigned int i, HMODULE lib_module);
FARPROC exm_overload_func_proc_old_get(unsigned int i);
FARPROC exm_overload_func_proc_new_get(unsigned int i);
const char *exm_overload_func_name_old_get(unsigned int i);

size_t exm_overload_data_alloc_size_get(const Exm_Overload_Data_Alloc *da);
int exm_overload_data_alloc_nbr_free_get(const Exm_Overload_Data_Alloc *da);
Exm_List *exm_overload_data_alloc_stack_get(const Exm_Overload_Data_Alloc *da);
size_t exm_overload_data_free_size_get(const Exm_Overload_Data_Free *df);

Exm_List *exm_overload_data_alloc_list(void);
Exm_List *exm_overload_data_free_list(void);
int exm_overload_data_alloc_list_count(void);
int exm_overload_data_free_list_count(void);

#endif /* EXAMINE_OVERLOAD_H */
