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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <examine_log.h>
#include <examine_list.h>
#include <examine_pe.h>

#include "examine_private.h"

static void
examine_depends_cmd_run(Exm_Pe_File *pe)
{
    Exm_List *l = NULL;
    Exm_List *iter;

    l = exm_pe_modules_list_string_get(l, exm_pe_filename_get(pe), 1);
    if (!l)
        return;

    iter = l;
    while (iter)
    {
        if (iter->data)
            printf("%s\n", (char *)iter->data);
        iter = iter->next;
    }

    exm_list_free(l, free);
}

static void
examine_depends_gui_run(char *module)
{
    EXM_LOG_ERR("depends tool with gui not done yet");
}

void
examine_depends_run(char *module, unsigned char gui)
{
    Exm_Pe_File *pe;

    EXM_LOG_INFO("Examine, a memory leak detector");
    EXM_LOG_INFO("Copyright (c) 2013-2014, and GNU GPL2'd, by Vincent Torri");
    EXM_LOG_INFO("Options: --tool=depends%s", gui ? "" : " --gui");

    pe = exm_pe_file_new(module);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        return;
    }

    if (gui)
        examine_depends_gui_run(module);
    else
        examine_depends_cmd_run(pe);

    exm_pe_file_free(pe);

    EXM_LOG_DBG("resources freed");
}
