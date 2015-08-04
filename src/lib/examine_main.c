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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "Examine.h"

#include "examine_private_log.h"
#include "examine_private_file.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


static int _exm_init_count = 0;


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/

EXM_API int
exm_init(void)
{
    if (++_exm_init_count != 1)
        return _exm_init_count;

    exm_log_init();
    exm_file_path_set();

    return _exm_init_count;
}

EXM_API int
exm_shutdown(void)
{
    if (--_exm_init_count != 0)
        return _exm_init_count;

    exm_file_path_free();
    exm_log_shutdown();

    return _exm_init_count;
}
