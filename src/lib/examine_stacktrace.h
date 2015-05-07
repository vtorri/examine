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

#ifndef EXAMINE_STACKTRACE_H
#define EXAMINE_STACKTRACE_H


typedef struct _Exm_Sw_Data Exm_Sw_Data;

unsigned char exm_sw_init(void);
void exm_sw_shutdown(void);

Exm_List *exm_sw_frames_get(void);

const char *exm_sw_data_filename_get(const Exm_Sw_Data *data);
const char *exm_sw_data_function_get(const Exm_Sw_Data *data);
unsigned int exm_sw_data_line_get(const Exm_Sw_Data *data);
void exm_sw_data_free(void *ptr);


#endif /* EXAMINE_STACKTRACE_H */
