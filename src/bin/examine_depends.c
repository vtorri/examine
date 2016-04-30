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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#endif

#include <Examine.h>
#include "examine_private.h"

#define EXM_DEPENDS_LIST_DLLCHAR_SET(val, str) \
do { \
    if (dllchar & val) \
    { \
        if (is_first) \
        { \
            is_first = 0; \
            *ptr++ = ' '; \
            *ptr++ = '('; \
        } \
        else \
        { \
            *ptr++ = ','; \
            *ptr++ = ' '; \
        } \
        memcpy(ptr, str, strlen(str)); \
        ptr += strlen(str); \
    } \
} while (0)

static char _exm_depends_list_dllcharacteristics[4096];
static unsigned int _exm_indent = 0;

static int
_exm_depends_cmd_cmp_cb(const void *d1, const void *d2)
{
    return _stricmp((const char *)d1, (const char *)d2);
}

static Exm_List *
_exm_depends_cmd_tree_fill(Exm_List *list, const char *filename)
{
    const IMAGE_IMPORT_DESCRIPTOR *iter_import;
    const IMAGE_DELAYLOAD_DESCRIPTOR *iter_delayload;
    Exm_Pe *pe;

    pe = exm_pe_new(filename);
    if (!pe)
        return list;

    _exm_indent += 2;

    iter_import = exm_pe_import_descriptor_get(pe, NULL);
    if (iter_import)
    {
        while (iter_import->Name != 0)
        {
            const char *desc_name;

            desc_name = exm_pe_import_descriptor_file_name_get(pe, iter_import);
            if (!desc_name)
            {
                EXM_LOG_ERR("Can not retrieve the import filename");
                goto import_next;
            }

            printf("%*c%s", _exm_indent, ' ', desc_name);

            if (!exm_list_data_is_found(list, desc_name, _exm_depends_cmd_cmp_cb))
            {
                char *name;

                name = _strdup(desc_name);
                if (name)
                {
                    printf("\n");
                    list = exm_list_append(list, name);
                    list = _exm_depends_cmd_tree_fill(list, name);
                }
                else
                    EXM_LOG_ERR("Can not allocate memory for import filename");
            }
            else
                printf(" (f)\n");

          import_next:
            iter_import++;
        }
    }

    iter_delayload = exm_pe_delayload_descriptor_get(pe, NULL);
    if (iter_delayload)
    {
        while (iter_delayload->DllNameRVA != 0)
        {
            const char *desc_name;

            desc_name =exm_pe_delayload_descriptor_file_name_get(pe, iter_delayload);
            if (!desc_name)
            {
                EXM_LOG_ERR("Can not retrieve the delay loaded filename");
                goto delayload_next;
            }

            printf("%*c%s", _exm_indent, ' ', desc_name);

            if (!exm_list_data_is_found(list, desc_name, _exm_depends_cmd_cmp_cb))
            {
                char *name;

                name = _strdup(desc_name);
                if (name)
                {
                    printf(" (dl)\n");
                    list = exm_list_append(list, name);
                    list = _exm_depends_cmd_tree_fill(list, name);
                }
                else
                    EXM_LOG_ERR("Can not allocate memory for delay loaded filename");

            }
            else
                printf(" (dl, f)\n");

          delayload_next:
            iter_delayload++;
        }
    }

    exm_pe_free(pe);

    _exm_indent -= 2;

    return list;
}

static void
_exm_depends_cmd_tree_run(Exm_Pe *pe)
{
    Exm_List *list = NULL;
    char *bn;

    exm_file_base_dir_name_get(exm_pe_filename_get(pe), NULL, &bn);
    printf("%s\n", bn);
    free(bn);

    list = _exm_depends_cmd_tree_fill(list, exm_pe_filename_get(pe));

    exm_list_free(list, free);
}

static const char *
_exm_depends_cmd_list_dllcharacteristics_get(const Exm_Pe *pe)
{
    char *ptr = _exm_depends_list_dllcharacteristics;
    WORD dllchar;
    unsigned char is_first = 1;

    if (exm_pe_is_64bits(pe))
        dllchar = ((const IMAGE_NT_HEADERS64 *)exm_pe_nt_header_get(pe))->OptionalHeader.DllCharacteristics;
    else
        dllchar = ((const IMAGE_NT_HEADERS32 *)exm_pe_nt_header_get(pe))->OptionalHeader.DllCharacteristics;

    if (!dllchar)
        return "";

#ifdef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    EXM_DEPENDS_LIST_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "high_entropy_va");
#endif
    EXM_DEPENDS_LIST_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "dynamic_base");
    EXM_DEPENDS_LIST_DLLCHAR_SET(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "nx_compat");

    if (!is_first)
    {
        *ptr = ')';
        ptr++;
    }

    *ptr = '\0';

    return _exm_depends_list_dllcharacteristics;
}

static Exm_List *
_exm_depends_cmd_list_fill(Exm_List *list, const Exm_Pe *pe)
{
    const IMAGE_IMPORT_DESCRIPTOR *iter_import;
    const IMAGE_DELAYLOAD_DESCRIPTOR *iter_delayload;

    if (!pe)
        return list;

    iter_import = exm_pe_import_descriptor_get(pe, NULL);
    if (iter_import)
    {
        while (iter_import->Name != 0)
        {
            const char *desc_name;

            desc_name = exm_pe_import_descriptor_file_name_get(pe, iter_import);
            if (!desc_name)
            {
                EXM_LOG_ERR("Can not retrieve the import filename");
                goto import_next;
            }

            if (!exm_list_data_is_found(list, desc_name, _exm_depends_cmd_cmp_cb))
            {
                char *name;

                name = _strdup(desc_name);
                if (name)
                {
                    Exm_Pe *p;
                    Exm_List *tmp;
                    const char *fullname;

                    list = exm_list_append(list, name);
                    printf("   %s", name);
                    p = exm_pe_new(name);
                    if (p)
                    {
                        fullname = exm_pe_filename_get(p);
                        if (fullname)
                            printf(" => %s", fullname);
                        printf("%s\n", _exm_depends_cmd_list_dllcharacteristics_get(p));
                        tmp = _exm_depends_cmd_list_fill(list, p);
                        exm_pe_free(p);
                        if (tmp)
                            list = tmp;
                    }
                    else
                        printf(" (not found)\n");
                }
                else
                    EXM_LOG_ERR("Can not allocate memory for import filename");
            }

          import_next:
            iter_import++;
        }
    }

    iter_delayload = exm_pe_delayload_descriptor_get(pe, NULL);
    if (iter_delayload)
    {
        while (iter_delayload->DllNameRVA != 0)
        {
            const char *desc_name;

            desc_name =exm_pe_delayload_descriptor_file_name_get(pe, iter_delayload);
            if (!desc_name)
            {
                EXM_LOG_ERR("Can not retrieve the delay loaded filename");
                goto delayload_next;
            }

            if (!exm_list_data_is_found(list, desc_name, _exm_depends_cmd_cmp_cb))
            {
                char *name;

                name = _strdup(desc_name);
                if (name)
                {
                    Exm_Pe *p;
                    Exm_List *tmp;
                    const char *fullname;

                    list = exm_list_append(list, name);
                    printf("   %s", name);
                    p = exm_pe_new(name);
                    if (p)
                    {
                        fullname = exm_pe_filename_get(p);
                        if (fullname)
                            printf(" => %s", fullname);
                        printf("%s\n", _exm_depends_cmd_list_dllcharacteristics_get(p));
                        tmp = _exm_depends_cmd_list_fill(list, p);
                        exm_pe_free(p);
                        if (tmp)
                            list = tmp;
                    }
                    else
                        printf(" (not found)\n");
                }
                else
                    EXM_LOG_ERR("Can not allocate memory for delay loaded filename");
            }

          delayload_next:
            iter_delayload++;
        }
    }

    return list;
}

static void
_exm_depends_cmd_list_run(const Exm_Pe *pe)
{
    Exm_List *list = NULL;
    char *bn;

    exm_file_base_dir_name_get(exm_pe_filename_get(pe), NULL, &bn);

    printf("   %s => %s%s\n",
           bn,
           exm_pe_filename_get(pe),
           _exm_depends_cmd_list_dllcharacteristics_get(pe));
    free(bn);
    list = exm_list_append(list, _strdup(exm_pe_filename_get(pe)));
    list = _exm_depends_cmd_list_fill(list, pe);

    exm_list_free(list, free);
}

#ifdef _WIN32
static void
_exm_depends_gui_run(Exm_Pe *pe, Exm_Log_Level log_level)
{
    char args[32768];
    Exm_Process *process;
    Exm_Map_Shared *map;
    char *cmd_gui;

    cmd_gui = exm_file_find("examine_depends.exe");
    if (!cmd_gui)
    {
        EXM_LOG_ERR("Can not allocate memory for application name");
        return;
    }

    args[0] = '\0';
    exm_str_append(args, exm_pe_filename_get(pe));

    process = exm_process_new(cmd_gui, args);
    if (!process)
    {
        EXM_LOG_ERR("Creation of process %s %s failed", cmd_gui, args);
        return;
    }
    free(cmd_gui);

    map = exm_map_shared_new("exm_depends_gui_shared",
                             &log_level, sizeof(Exm_Log_Level));
    if (!map)
    {
        EXM_LOG_ERR("Can not map shared memory to pass to Examine Depends GUI");
        exm_process_del(process);
        return;
    }

    exm_process_run(process);
    exm_map_shared_del(map);
    exm_process_del(process);
}
#endif

void
exm_depends_run(const char *module, unsigned char display_list, unsigned char gui, Exm_Log_Level log_level)
{
    Exm_Pe *pe;

    pe = exm_pe_new(module);
    if (!pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        return;
    }

#ifdef _WIN32
    if (gui)
      _exm_depends_gui_run(pe, log_level);
    else
#endif
    {
        if (display_list)
            _exm_depends_cmd_list_run(pe);
        else
            _exm_depends_cmd_tree_run(pe);
    }

    exm_pe_free(pe);

    EXM_LOG_DBG("resources freed");
}
