/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2012-2013 Vincent Torri.
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

#include <stdlib.h>
#include <stdio.h>

#include <windows.h>
#include <bfd.h>

#include "examine_list.h"
#include "examine_log.h"
#include "examine_stacktrace.h"
#include "examine_private.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


typedef struct _Exm_Sw_Find_Data Exm_Sw_Find_Data;
typedef struct _Exm_Sw_Bfd_Data Exm_Sw_Bfd_Data;

struct _Exm_Sw_Find_Data
{
    char     *function;
    asymbol **symbol_table;
    bfd_vma   counter;
    Exm_List *list;
};

struct _Exm_Sw_Data
{
    char *filename;
    char *function;
    int   line;
};

struct _Exm_Sw_Bfd_Data
{
    bfd *fd;
    asymbol **symbol_table;
};

struct _Exm_Sw
{
    Exm_List *bfds;
};

static Exm_Sw_Bfd_Data *
_exm_sw_bfd_data_new(const char *filename)
{
    Exm_Sw_Bfd_Data  *data;
    char            **formats = NULL;
    unsigned int      dummy = 0;

    if (!filename || !*filename)
        return NULL;

    data = (Exm_Sw_Bfd_Data *)malloc(sizeof(Exm_Sw_Bfd_Data));
    if (!data)
        return NULL;

    data->fd = bfd_openr(filename, NULL);
    if (!data->fd)
        goto free_data;

    if (!bfd_check_format(data->fd, bfd_object))
    {
        EXM_LOG_ERR("bfd_check_format failed: %s", bfd_errmsg(bfd_get_error()));
        goto close_fd;
    }

    if (!bfd_check_format_matches(data->fd, bfd_object, &formats))
        goto close_fd;

    if (!(bfd_get_file_flags(data->fd) & HAS_SYMS))
    {
        free(formats);
        goto close_fd;
    }

    free(formats);

    if ((bfd_read_minisymbols(data->fd, FALSE, (void **)&data->symbol_table, &dummy) == 0) &&
        (bfd_read_minisymbols(data->fd, TRUE, (void **)&data->symbol_table, &dummy) < 0))
        goto close_fd;

    return data;

  close_fd:
    if (data->symbol_table)
        free(data->symbol_table);
    bfd_close(data->fd);
  free_data:
    free(data);

    return NULL;
}

static void
_exm_sw_bfd_data_free(void *ptr)
{
    Exm_Sw_Bfd_Data *data;

    if (!ptr)
        return;

    data = (Exm_Sw_Bfd_Data *)ptr;
    free(data->symbol_table);
    bfd_close(data->fd);
    free(data);
}

static void
_exm_sw_find_function_name_in_section(bfd      *abfd,
                                      asection *sec,
                                      void     *obj)
{
    Exm_Sw_Find_Data *data;
    bfd_vma           vma;
    const char       *func = NULL;
    const char       *file = NULL;
    unsigned          line = 0;

    if (!sec)
    {
        fprintf(stderr, "no section\n");
        return;
    }

    data = (Exm_Sw_Find_Data *)obj;
    if (data->function && (*data->function != '\0'))
    {
        /* fprintf(stderr, "function already found : %s\n", data->function); */
        /* function already found */
        return;
    }

    if (!(bfd_get_section_flags(abfd, sec) & SEC_ALLOC))
    {
        /* fprintf(stderr, "bad flags\n"); */
        return;
    }

    vma = bfd_get_section_vma(abfd, sec);
    if (data->counter < vma)
        return;
    if ((vma + bfd_get_section_size(sec)) <= data->counter)
    {
        /* fprintf(stderr, "wrong size\n"); */
        return;
    }

    if (bfd_find_nearest_line(abfd, sec,
                              data->symbol_table,
                              data->counter - vma,
                              &file, &func, &line))
    {
        Exm_Sw_Data *sw_data;
        size_t       l;

        sw_data = (Exm_Sw_Data *)calloc(1, sizeof(Exm_Sw_Data));
        if (!sw_data)
            return;

        l = strlen(file) + 1;
        sw_data->filename = (char *)malloc(l * sizeof(char));
        if (!sw_data->filename)
        {
            free(sw_data);
            return;
        }
        memcpy(sw_data->filename, file, l);

        if (func)
        {
            l = strlen(func) + 1;
            sw_data->function = (char *)malloc(l * sizeof(char));
            if (!sw_data->function)
            {
                free(sw_data->filename);
                free(sw_data);
                return;
            }
            memcpy(sw_data->function, func, l);
        }

        sw_data->line = line;
        data->list = exm_list_append(data->list, sw_data);
    }
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


Exm_Sw *
exm_sw_new(void)
{
    char             filename[MAX_PATH];
    Exm_Sw          *sw;
    Exm_List        *iter;
    Exm_Sw_Bfd_Data *bfd_data;

    if (!GetModuleFileName(NULL, filename, sizeof(filename)))
        return NULL;

    sw = (Exm_Sw *)calloc(1, sizeof(Exm_Sw));
    if (!sw)
        return NULL;

    bfd_init();

    iter = exm_hook_instance_dll_get();
    while (iter)
    {
        bfd_data = _exm_sw_bfd_data_new((const char *)iter->data);
        if (!bfd_data)
            goto free_list;

        sw->bfds = exm_list_append(sw->bfds, bfd_data);

        iter = iter->next;
    }

    return sw;

  free_list:
    exm_list_free(sw->bfds, _exm_sw_bfd_data_free);
    free(sw);

    return NULL;
}

void
exm_sw_free(Exm_Sw *sw)
{
    if (!sw)
        return;

    exm_list_free(sw->bfds, _exm_sw_bfd_data_free);
    free(sw);
}

Exm_List *
exm_sw_frames_get(Exm_Sw *sw)
{
#define MAX_ENTRIES 50
    Exm_List        *iter;
    Exm_Sw_Find_Data data;
    void            *frames[MAX_ENTRIES];
    unsigned short   frames_nbr;
    unsigned int     i;

    if (!sw)
    {
        printf("Stackwalk NULL\n");
        return NULL;
    }

#if 1
    frames_nbr = CaptureStackBackTrace(0, MAX_ENTRIES, frames, NULL);
    if (frames_nbr == 0)
    {
        fprintf(stderr, "error %ld\n", GetLastError());
    }
#else
    {
        void **frame = NULL;

        i = 0;
        __asm__ __volatile__ ("movl %%ebp, %0" : : "m" (frame) : "memory");
        while(frame && i < MAX_ENTRIES)
        {
            frames[i++] = frame[1];
            frame = (void **)frame[0];
        }
        frames_nbr = i;
    }
#endif

    data.list = NULL;
    iter = sw->bfds;
    while (iter)
    {
        Exm_Sw_Bfd_Data *bfd_data;

        bfd_data = iter->data;

        for (i = 0; i < frames_nbr; i++)
        {
            data.function = NULL;
            data.symbol_table = bfd_data->symbol_table;
            /* we substract 1 because (From Kai Tietz) : */
            /* the back-trace address collected is the return-address of the call. */
            /* So this location might be pointing already to next line.*/
            data.counter = (bfd_vma)((char *)frames[i] - 1);
            bfd_map_over_sections(bfd_data->fd,
                                  &_exm_sw_find_function_name_in_section,
                                  &data);
        }

        iter = iter->next;
    }

    return data.list;
}

const char *
exm_sw_data_filename_get(const Exm_Sw_Data *data)
{
    if (!data)
        return NULL;

    return data->filename;
}

const char *
exm_sw_data_function_get(const Exm_Sw_Data *data)
{
    if (!data)
        return NULL;

    return data->function;
}

int
exm_sw_data_line_get(const Exm_Sw_Data *data)
{
    if (!data)
        return 0;

    return data->line;
}

void
exm_sw_data_free(void *ptr)
{
    Exm_Sw_Data *data;

    if (!ptr)
        return;

    data = (Exm_Sw_Data *)ptr;
    if (data->filename)
        free(data->filename);
    if (data->function)
        free(data->function);
    free(data);
}
