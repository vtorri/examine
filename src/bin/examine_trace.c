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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <Examine.h>

#include "examine_private.h"

void
exm_trace_run(Exm_List *options, char *filename, char *args)
{
    Exm_List *option;

    EXM_LOG_INFO("Command : %s %s", filename, args);
    EXM_LOG_INFO("");
    EXM_LOG_INFO("Examine options:");
    option = options;
    while (option)
    {
        EXM_LOG_INFO("   %s", (char *)option->data);
        option = option->next;
    }
    EXM_LOG_ERR("trace tool not done yet");
}
