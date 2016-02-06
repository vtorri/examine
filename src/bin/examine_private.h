/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2014-2016 Vincent Torri.
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


void exm_mc_run(const char *filename, char *args);
void exm_trace_run(const char *filename, char *args);
void exm_depends_run(const char *filename, unsigned char display_list, unsigned char gui, Exm_Log_Level log_level);
void exm_view_run(const char *filename, unsigned char gui, Exm_Log_Level log_level);
void exm_sigcheck_run(const char *module, unsigned char gui, Exm_Log_Level log_level);


#endif /* EXAMINE_BIN_PRIVATE_H */
