/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2014-2015 Vincent Torri.
 * All rights reserved.
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

#ifndef EXM_MAP_H
#define EXM_MAP_H

typedef struct _Exm_Map_Shared Exm_Map_Shared;

EXM_API Exm_Map_Shared *exm_map_shared_new(const char *name, const void *data, unsigned int size);

EXM_API void exm_map_shared_del(Exm_Map_Shared *map);

EXM_API unsigned char exm_map_shared_read(const char *name, unsigned int size, void *data);

#endif /* EXM_MAP_H */
