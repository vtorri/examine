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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <limits.h>
#endif

#include "Examine.h"
#ifndef _WIN32
# include "examine_pe_unix.h"
#endif

#include "examine_private_file.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


static Exm_List *_exm_file_path = NULL;

#ifndef _WIN32
static int
_exm_file_name_strcmp(const void *d1, const void *d2)
{
    return strcmp((const char *)d1, (const char *)d2);
}
#endif

#ifdef _WIN32
static int
_exm_file_name_strcasecmp(const void *d1, const void *d2)
{
    return _stricmp((const char *)d1, (const char *)d2);
}
#endif

static char *
_exm_file_concat(const char *path, const char *filename)
{
    char *res;
    size_t l1;
    size_t l2;

    l1 = strlen(path);
    l2 = strlen(filename);
    res = (char *)malloc((l1 + l2 + 1) * sizeof(char));
    if (!res)
        return NULL;

    memcpy(res, path, l1);
    memcpy(res + l1, filename, l2);
    res[l1 + l2] = '\0';

    return res;
}

static unsigned char
_exm_file_exists(const char *path, const char *filename)
{
    char *tmp;
    struct stat buf;
    unsigned char res = 1;

    tmp = _exm_file_concat(path, filename);
    if (!tmp)
        return 0;

    if (stat(tmp, &buf) != 0)
        res = 0;
    free(tmp);

    return res;
}

#ifdef _WIN32
static void
_exm_file_backslash_final_set(char *filename)
{
    size_t length;

    length = strlen(filename);
    if (filename[length - 1] != '\\')
    {
        filename[length] = '\\';
        filename[length + 1] = '\0';
    }
}
#endif


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


void
exm_file_path_set(void)
{
#ifdef _WIN32
    char buf[32768];

    /* system directory */

    {
        UINT length;

        length = GetSystemDirectory(buf, sizeof(buf));
        if ((length != 0) && (length <= sizeof(buf)))
        {
            _exm_file_backslash_final_set(buf);
            _exm_file_path = exm_list_append(_exm_file_path, _strdup(buf));
        }
    }

    /* Windows directory */

    {
        UINT length;

        length = GetWindowsDirectory(buf, sizeof(buf));
        if ((length != 0) && (length <= sizeof(buf)))
        {
            _exm_file_backslash_final_set(buf);
            _exm_file_path = exm_list_append(_exm_file_path, _strdup(buf));
        }
    }

    /* PATH directories */

    {
        char *env;
        char *iter;
        char *s;

        /*
         * don't use GetEnvironmentVariable() as MSYS' profile can
         * override $PATH value.
         */
        env = getenv("PATH");
        iter = env;
        while (iter)
        {
            size_t length;

            s = strchr(iter, ';');
            if (!s)
            {
                length = strlen(iter);
                memcpy(buf, iter, length + 1);
                _exm_file_backslash_final_set(buf);
                _exm_file_path = exm_list_append(_exm_file_path, _strdup(buf));
                break;
            }

            *s = '\0';
            length = strlen(iter);
            memcpy(buf, iter, length + 1);
            _exm_file_backslash_final_set(buf);
            _exm_file_path = exm_list_append(_exm_file_path, _strdup(buf));

            iter = s + 1;
        }
    }
#endif
}

void
exm_file_path_free(void)
{
    exm_list_free(_exm_file_path, free);
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API char *
exm_file_set(const char *filename)
{
    Exm_List *tmp;
    char *dir_name = NULL;
    char *base_name = NULL;
    char *dir_name_new = NULL;
    Exm_List_Cmp_Cb cmp_cb;
    size_t l;

    if (!filename)
        return NULL;

#ifdef _WIN32
    cmp_cb = _exm_file_name_strcasecmp;
#else
    cmp_cb = _exm_file_name_strcmp;
#endif

    EXM_LOG_DBG("Set file %s", filename);

    exm_file_base_dir_name_get(filename, &dir_name, &base_name);
    if (!dir_name || !base_name)
    {
        EXM_LOG_ERR("Can not find base dir or base name for %s", filename);
        goto free_names;
    }

    l = strlen(dir_name);
    dir_name_new = (char *)malloc((l + 2) * sizeof(char));
    if (!dir_name_new)
    {
        EXM_LOG_ERR("Can not allocate memory for path");
        goto free_names;
    }

    memcpy(dir_name_new, dir_name, l);
    dir_name_new[l] = '\\';
    dir_name_new[l + 1] = '\0';
    free(dir_name);
    tmp = exm_list_prepend_if_new(_exm_file_path,
                                  dir_name_new,
                                  cmp_cb);
    /* dir_name is already in the list and is not added, so free it */
    if (tmp == _exm_file_path)
    {
        free(dir_name_new);
    }
    else
        _exm_file_path = tmp;


    return base_name;

  free_names:
    if (base_name)
        free(base_name);
    if (dir_name)
        free(dir_name);

    return NULL;
}

EXM_API char *
exm_file_find(const char *filename)
{
    Exm_List *iter;
    char *file = NULL;
    char *base_name = NULL;

    exm_file_base_dir_name_get(filename, NULL, &base_name);

    if (!base_name)
    {
        EXM_LOG_ERR("Can not find base name for %s", filename);
        return NULL;
    }

    iter = _exm_file_path;
    while (iter)
    {
        EXM_LOG_DBG("Searching for file %s with base directory %s...",
                    base_name, (const char *)iter->data);
        if (_exm_file_exists((const char *)iter->data, base_name))
        {
            file = _exm_file_concat((const char *)iter->data, base_name);
            EXM_LOG_DBG("Find file %s", file);
            break;
        }
        iter = iter->next;
    }

    free(base_name);
    return file;
}

EXM_API unsigned long long
exm_file_size_get(const char *filename)
{
#ifdef _WIN32
    struct _stati64 buf;

    if (_stati64(filename, &buf) != 0)
        return 0;

    return buf.st_size;
#else
    struct stat buf;

    if (stat(filename, &buf) != 0)
        return 0;

    return buf.st_size;
#endif
}

/**
 * @brief Retrieve the base name and directory name of the given file name.
 *
 * @param[in] filename The file name.
 * @param[out] dir_name The directory part of the file name.
 * @param[out] base_name The file part of the file name.
 *
 * This function retrieves the directory name and base name of @filename and
 * respectively stores them in @p dir_name and @p base_name. @p dir_name and
 * @p base_name can be @c NULL.
 */
EXM_API void
exm_file_base_dir_name_get(const char *filename, char **dir_name, char **base_name)
{
#ifdef _WIN32
    char *full_name = NULL;
    char *file_part;
    size_t length;
    DWORD res;
#else
    char full_name[PATH_MAX];
    char *res;
    char *file_part;
#endif

    if (dir_name) *dir_name = NULL;
    if (base_name) *base_name = NULL;

    if (!filename)
        return;

#ifdef _WIN32
    res = GetFullPathName(filename, 0, NULL, NULL);
    if (res == 0)
        return;

    res++;
    full_name = (char *)malloc(res * sizeof(char));
    if (!full_name)
        return;

    length = GetFullPathName(filename, res, full_name, &file_part);
    if (length == 0)
    {
        free(full_name);
        return;
    }
#else
    res = realpath(filename, full_name);
    if (!res)
        return;

    file_part = strrchr(full_name, '/');
    if (!file_part) // should never get there
        return;

    file_part++;
#endif

    if (base_name)
    {
        char *bname;

        length = strlen(file_part) + 1;
        bname = (char *)malloc(length * sizeof(char));
        if (bname)
        {
            memcpy(bname, file_part, length);
            *base_name = bname;
        }
    }

    if (dir_name)
    {
        char *dname;

        full_name[file_part - full_name - 1] = '\0';
        length = file_part - full_name;
        dname = (char *)malloc(length * sizeof(char));
        if (dname)
        {
            memcpy(dname, full_name, length);
            *dir_name = dname;
        }
    }

#ifdef _WIN32
    if (full_name)
        free(full_name);
#endif
}
