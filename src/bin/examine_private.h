/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2014-2015 Vincent Torri.
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

#ifndef EXAMINE_BIN_PRIVATE_H
#define EXAMINE_BIN_PRIVATE_H


void examine_memcheck_run(Exm_List *options, char *filename, char *args);
void examine_trace_run(Exm_List *options, char *filename, char *args);
void exm_depends_run(Exm_List *options, char *filename, unsigned char display_list, unsigned char gui);
void exm_view_run(Exm_List *options, char *filename, unsigned char gui);


#endif /* EXAMINE_BIN_PRIVATE_H */
