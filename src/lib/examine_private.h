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

#ifndef EXAMINE_PRIVATE_H
#define EXAMINE_PRIVATE_H

/***** UNIX compatibility *****/

#ifndef _WIN32

#define MAX_PATH 260

#define _strdup(s) strdup(s)
#define _stricmp(s1,s2) strcasecmp(s1,s2)
#define _fullpath(buf, file, sz) realpath(file, buf)

#endif


/***** Hook *****/

Exm_List *exm_memcheck_dep_names_get(void);


#endif /* EXAMINE_PRIVATE_H */
