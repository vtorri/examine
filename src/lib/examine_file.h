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

#ifndef EXM_FILE_H
#define EXM_FILE_H

EXM_API char *exm_file_set(const char *filename);

EXM_API char *exm_file_find(const char *filename);

EXM_API unsigned long long exm_file_size_get(const char *filename);

EXM_API void exm_file_base_dir_name_get(const char *filename, char **dir_name, char **base_name);

#endif /* EXM_FILE_H */
