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

#ifndef EXAMINE_STACK_H
#define EXAMINE_STACK_H


typedef struct _Exm_Stack_Data Exm_Stack_Data;

EXM_API unsigned char exm_stack_init(void);
EXM_API void exm_stack_shutdown(void);

EXM_API Exm_List *exm_stack_frames_get(void);

EXM_API const char *exm_stack_data_filename_get(const Exm_Stack_Data *data);
EXM_API const char *exm_stack_data_function_get(const Exm_Stack_Data *data);
EXM_API unsigned int exm_stack_data_line_get(const Exm_Stack_Data *data);
EXM_API void exm_stack_data_free(void *ptr);
EXM_API void exm_stack_disp(const Exm_List *stack);


#endif /* EXAMINE_STACK_H */
