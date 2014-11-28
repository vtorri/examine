/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2014 Vincent Torri.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EXM_MAP_H
#define EXM_MAP_H

typedef struct _Exm_Map Exm_Map;

Exm_Map *exm_map_new(const char *filename);
void exm_map_del(Exm_Map *map);
const void *exm_map_base_get(const Exm_Map *map);

#endif /* EXM_MAP_H */
