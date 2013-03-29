/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2012-2013 Vincent Torri.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#include <windows.h>
#include <bfd.h>

#include "examine_list.h"
#include "examine_stacktrace.h"

typedef struct _Exm_Sw_Find_Data Exm_Sw_Find_Data;

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

struct _Exm_Sw
{
    bfd *fd;
    asymbol **symbol_table;
};

static void
sw_find_function_name_in_section(bfd      *abfd,
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

Exm_Sw *
exm_sw_init(void)
{
    char         filename[MAX_PATH];
    Exm_Sw      *sw;
    char       **formats = NULL;
    unsigned int dummy = 0;

    if (!GetModuleFileName(NULL, filename, sizeof(filename)))
        return NULL;

    sw = (Exm_Sw *)calloc(1, sizeof(Exm_Sw));
    if (!sw)
        return NULL;

    bfd_init();

    sw->fd = bfd_openr(filename, NULL);
    if (!sw->fd)
        goto free_sw;

    if (!bfd_check_format(sw->fd, bfd_object))
    {
        printf("error : %s\n", bfd_errmsg(bfd_get_error()));
        goto close_fd;
    }
    if (!bfd_check_format_matches(sw->fd, bfd_object, &formats))
        goto close_fd;
    if (!(bfd_get_file_flags(sw->fd) & HAS_SYMS))
    {
        free(formats);
        goto close_fd;
    }
    free(formats);

    if ((bfd_read_minisymbols(sw->fd, FALSE, (void **)&sw->symbol_table, &dummy) == 0) &&
        (bfd_read_minisymbols(sw->fd, TRUE, (void **)&sw->symbol_table, &dummy) < 0))
        goto close_fd;

    return sw;

  close_fd:
    if (sw->symbol_table)
        free(sw->symbol_table);
    bfd_close(sw->fd);
  free_sw:
    free(sw);

    return NULL;
}

void
exm_sw_shutdown(Exm_Sw *sw)
{
    if (!sw)
        return;

    free(sw->symbol_table);
    bfd_close(sw->fd);
    free(sw);
}

Exm_List *
exm_sw_frames_get(Exm_Sw *sw)
{
#define MAX_ENTRIES 50
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
    for (i = 0; i < frames_nbr; i++)
    {
        data.function = NULL;
        data.symbol_table = sw->symbol_table;
        /* we substract 1 because (From Kai Tietz) : */
        /* the back-trace address collected is the return-address of the call. */
        /* So this location might be pointing already to next line.*/
        data.counter = (bfd_vma)((char *)frames[i] - 1);
        bfd_map_over_sections(sw->fd, &sw_find_function_name_in_section, &data);
    }

    return data.list;
}

const char *
exm_sw_data_filename_get(Exm_Sw_Data *data)
{
    if (!data)
        return NULL;

    return data->filename;
}

const char *
exm_sw_data_function_get(Exm_Sw_Data *data)
{
    if (!data)
        return NULL;

    return data->function;
}

int
exm_sw_data_line_get(Exm_Sw_Data *data)
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
