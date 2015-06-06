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

#include <stdlib.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#ifdef _MSC_VER
# include <direct.h>
#endif

#include <Examine.h>

#include "examine_private.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


typedef struct _Exm Exm;

struct _Exm
{
    char          *filename;
    Exm_Map_Shared *map_lens; /* array of 2 int's for the length of vals and names*/
    Exm_Map_Shared *map_vals; /* values to have in the injected DLL */
    Exm_Map_Shared *map_names; /* file names to have in the injected DLL */
};



static Exm *
_exm_new(const char *filename)
{
    Exm *exm;

    exm = (Exm *)calloc(1, sizeof(Exm));
    if (!exm)
        return NULL;

    exm->filename = (char *)filename;

    return exm;
}

static void
_exm_del(Exm *exm)
{
    if (exm->map_names)
        exm_map_shared_del(exm->map_names);
    if (exm->map_vals)
        exm_map_shared_del(exm->map_vals);
    if (exm->map_vals)
        exm_map_shared_del(exm->map_lens);
    free(exm->filename);
    free(exm);
}

static int
_exm_map(Exm *exm, Exm_Process *process)
{
    /*
     * Signification of lens:
     * 0: length of vals in bytes
     * 1: length of names in bytes
     */
    int lens[2];
    /*
     * Signification of vals:
     * 0: log level
     * 1: number of CRT files
     * 2: number of dependencies
     * 3-*: CRT file name lengths (with null terminating char) length, or 0
     * *-*: dep file name lengths (with null terminating char) length, or 0
     */
    int *vals;
    /*
     * Signification of names:
     * concatenation of ASCIIZ strings based on vals
     * first the CRT names
     * then the dep names
     */
    char *names;
    const Exm_List *crt_names;
    const Exm_List *dep_names;
    size_t total_len;
    size_t idx;
    int crt_count;
    int dep_count;
    int i;

    /* first, the names count */
    crt_names = exm_process_crt_names_get(process);
    crt_count = exm_list_count(crt_names);

    dep_names = exm_process_dep_names_get(process);
    dep_count = exm_list_count(dep_names);

    lens[0] = (1 + 1 + 1 + crt_count + dep_count) * sizeof(int);
    vals = (int *)malloc(lens[0]);
    if (!vals)
    {
        EXM_LOG_ERR("Can not allocate memory");
        return 0;
    }

    vals[0] = exm_log_level_get();
    vals[1] = crt_count;
    vals[2] = dep_count;

    /* second, the crt file lengths */

    total_len = 0;
    i = 3;
    while (crt_names)
    {
        size_t crt_len;

        crt_len = strlen((char *)crt_names->data) + 1;
        total_len += crt_len;
        vals[i] = (int)crt_len;
        i++;
        crt_names = crt_names->next;
    }

    /* third, the dep file lengths */

    while (dep_names)
    {
        size_t dep_len;

        dep_len = strlen((char *)dep_names->data) + 1;
        total_len += dep_len;
        vals[i] = (int)dep_len;
        i++;
        dep_names = dep_names->next;
    }

    /* fourth, we store the CRT names */

    lens[1] = (int)(total_len * sizeof(char));
    names = (char *)malloc(lens[1]);
    if (!names)
    {
        EXM_LOG_ERR("Can not allocate memory");
        goto free_vals;
    }

    idx = 0;
    i = 3;
    crt_names = exm_process_crt_names_get(process);
    while (crt_names)
    {
        memcpy(names + idx, crt_names->data, vals[i]);
        idx += vals[i];
        i++;
        crt_names = crt_names->next;
    }

    /* finally, we store the dependency names */

    dep_names = exm_process_dep_names_get(process);
    while (dep_names)
    {
        memcpy(names + idx, dep_names->data, vals[i]);
        idx += vals[i];
        i++;
        dep_names = dep_names->next;
    }

    exm->map_lens = exm_map_shared_new("exm_memcheck_shared_lens",
                                       lens, sizeof(lens));
    if (!exm->map_lens)
    {
        EXM_LOG_ERR("Can not map lengths shared memory to pass to injected DLL");
        goto free_names;
    }

    exm->map_vals = exm_map_shared_new("exm_memcheck_shared_vals",
                                       vals, lens[0]);
    if (!exm->map_vals)
    {
        EXM_LOG_ERR("Can not map values shared memory to pass to injected DLL");
        goto del_map_lens;
    }

    exm->map_names = exm_map_shared_new("exm_memcheck_shared_names",
                                        names, lens[1]);
    if (!exm->map_names)
    {
        EXM_LOG_ERR("Can not map names shared memory file name to pass to injected DLL");
        goto del_map_vals;
    }

    return 1;

  del_map_vals:
    exm_map_shared_del(exm->map_vals);
  del_map_lens:
    exm_map_shared_del(exm->map_lens);
  free_names:
    free(names);
  free_vals:
    free(vals);

    return 0;
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


void
exm_mc_run(Exm_List *options, char *filename, char *args)
{
    char buf[32768];
    Exm *exm;
    Exm_Process *process;
    Exm_Injection *inj;

    buf[0] = '\0';
    exm_str_append(buf, filename);
    exm_str_append(buf, args);

    EXM_LOG_INFO("Command : %s", buf);
    EXM_LOG_INFO("");
    if (exm_list_count(options) > 0)
    {
        Exm_List *option;

        EXM_LOG_INFO("Examine options:");
        option = options;
        while (option)
        {
            EXM_LOG_INFO("   %s", (char *)option->data);
            option = option->next;
        }
    }

    exm = _exm_new(filename);
    if (!exm)
        return;

    process = exm_process_new(filename, args);
    if (!process)
    {
        EXM_LOG_ERR("Creation of process %s %s failed", filename, args);
        goto del_exm;
    }

    if (!exm_process_entry_point_patch(process))
    {
        EXM_LOG_ERR("can not patch entry point of the process %s",
                    filename);
        goto del_process;
    }

    if (!exm_process_dependencies_set(process))
    {
        EXM_LOG_ERR("can not find dependencies of the process %s",
                    filename);
        goto unpatch_process;
    }

    if (!_exm_map(exm, process))
    {
        EXM_LOG_ERR("can not map shared memory to pass to injected DLL");
        goto unpatch_process;
    }

    inj = exm_injection_new(filename);
    if (!inj)
    {
        EXM_LOG_ERR("Can not create initialise injection");
        goto unpatch_process;
    }

    if (!exm_injection_dll_inject(inj, process, "libexamine_memcheck.dll"))
    {
        EXM_LOG_ERR("injection failed");
        goto del_injection;
    }

    if (!exm_process_entry_point_unpatch(process))
    {
        EXM_LOG_ERR("can not patch entry point of the process %s",
                    filename);
        goto dll_eject;
    }

    exm_process_run(process);

    EXM_LOG_DBG("end of process");

    exm_injection_dll_eject(inj, process);

    _exm_del(exm);
    EXM_LOG_DBG("resources freed");

    return;

  dll_eject:
    exm_injection_dll_eject(inj, process);
  del_injection:
    exm_injection_del(inj);
  unpatch_process:
    exm_process_entry_point_unpatch(process);
  del_process:
    exm_process_run(process);
    exm_process_del(process);
  del_exm:
    _exm_del(exm);
}
