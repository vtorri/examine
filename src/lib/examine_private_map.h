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

#ifndef EXM_PRIVATE_MAP_H
#define EXM_PRIVATE_MAP_H

typedef struct _Exm_Map Exm_Map;

Exm_Map *exm_map_new(const char *filename);

#ifdef _WIN32

Exm_Map *exm_map_new_from_base(const void *base, DWORD size);

#endif

void exm_map_del(Exm_Map *map);

const void *exm_map_base_get(const Exm_Map *map);

unsigned long long exm_map_size_get(const Exm_Map *map);

#endif /* EXM_PRIVATE_MAP_H */
