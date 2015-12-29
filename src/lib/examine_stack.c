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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <bfd.h>

#include "Examine.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


typedef struct _Exm_Stack_Find_Data Exm_Stack_Find_Data;

struct _Exm_Stack_Find_Data
{
    char     *function;
    asymbol **symbol_table;
    bfd_vma   counter;
    Exm_List *list;
};

struct _Exm_Stack_Data
{
    char *filename;
    char *function;
    unsigned int line;
};

static void
_exm_stack_find_function_name_in_section(bfd *abfd, asection *sec, void *obj)
{
    Exm_Stack_Find_Data *data;
    bfd_vma vma;
    const char *fct;
    const char *func = NULL;
    const char *file = NULL;
    unsigned int line = 0;

    /* printf(" $$$$ %s\n", bfd_get_filename(abfd)); */

    if (!sec)
    {
        EXM_LOG_ERR("Can not find section");
        return;
    }

    data = (Exm_Stack_Find_Data *)obj;
    if (data->function)// && (*data->function != '\0'))
    {
        EXM_LOG_ERR("function already found : %s", data->function);
        /* function already found */
        return;
    }

    if (!(bfd_get_section_flags(abfd, sec) & SEC_ALLOC))
    {
        /* EXM_LOG_ERR("bad flags"); */
        /* return; */
    }

    vma = bfd_get_section_vma(abfd, sec);
    if (data->counter < vma)
        return;
    if ((vma + bfd_get_section_size(sec)) <= data->counter)
    {
        EXM_LOG_ERR("wrong size");
        return;
    }

    if (bfd_find_nearest_line(abfd, sec,
                              data->symbol_table,
                              data->counter - vma,
                              &file, &func, &line))
    {
        Exm_Stack_Data *sw_data;
        size_t l;
        char *iter;

        if (!file)
            file = bfd_get_filename(abfd);

        if (!file)
            file = "???";

        iter = (char *)file;
        while (*iter)
        {
            if (*iter == '/') *iter = '\\';
            iter++;
        }

        iter = strrchr(file, '\\');
        if (iter)
            iter++;
        else
            iter = (char *)file;

        if (strcmp(iter, "examine_stack.c") == 0)
            return;

        sw_data = (Exm_Stack_Data *)calloc(1, sizeof(Exm_Stack_Data));
        if (!sw_data)
            return;

        l = strlen(iter) + 1;
        sw_data->filename = (char *)malloc(l * sizeof(char));
        if (!sw_data->filename)
        {
            free(sw_data);
            return;
        }

        memcpy(sw_data->filename, iter, l);

        fct = func ? func : "???";
        l = strlen(fct) + 1;
        sw_data->function = (char *)malloc(l * sizeof(char));
        if (!sw_data->function)
        {
            free(sw_data->filename);
            free(sw_data);
            return;
        }
        memcpy(sw_data->function, fct, l);

        sw_data->line = line;
        data->list = exm_list_append(data->list, sw_data);
    }
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API unsigned char
exm_stack_init(void)
{
    bfd_init();

    return 1;
}

EXM_API void
exm_stack_shutdown(void)
{
}

EXM_API Exm_List *
exm_stack_frames_get(void)
{
#define MAX_ENTRIES 100
    Exm_Stack_Find_Data data;
    void            *frames[MAX_ENTRIES];
    unsigned short   frames_nbr;
    unsigned int     i;

#if 1
    frames_nbr = CaptureStackBackTrace(0, MAX_ENTRIES, frames, NULL);
    if (frames_nbr == 0)
    {
        EXM_LOG_ERR("CaptureStackBackTrace failed with error %ld", GetLastError());
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
        TCHAR tpath[PATH_MAX];
        MEMORY_BASIC_INFORMATION mbi;
        bfd *fd;
        asymbol **symbol_table;
        char **formats = NULL;
        unsigned int dummy = 0;

        /* Get the name and base address of the module */

        if (!VirtualQuery(frames[i], &mbi, sizeof(mbi)))
        {
            EXM_LOG_WARN("VirtualQuery failed on frame #%d (0x%p), skipping",
                        i, frames[i]);
            continue;
        }

        if (mbi.State != MEM_COMMIT)
        {
            EXM_LOG_WARN("Address 0x%p of frame #%d is not available, skipping",
                        frames[i], i);
            continue;
        }

        if (!mbi.AllocationBase)
        {
            EXM_LOG_WARN("Address 0x%p of frame #%d is not available, skipping",
                        frames[i], i);
            continue;
        }

        if (!GetModuleFileName(mbi.AllocationBase, (LPTSTR)&tpath, PATH_MAX))
        {
            EXM_LOG_WARN("Can not retrieve the file name of the module for frame #%d, skipping",
                        i);
            continue;
        }

        EXM_LOG_DBG("Frame #%d in module %s", i, tpath);

        /* set up bfd data for the module found above */

        fd = bfd_openr(tpath, NULL);
        if (!fd)
        {
            EXM_LOG_WARN("Can not open file descriptor for frame #%d, skipping",
                        i);
            continue;
        }

        if (!bfd_check_format(fd, bfd_object))
        {
            EXM_LOG_ERR("bfd_check_format failed: %s",
                        bfd_errmsg(bfd_get_error()));
            goto close_fd;
        }

        if (!bfd_check_format_matches(fd, bfd_object, &formats))
            goto close_fd;

        if (!(bfd_get_file_flags(fd) & HAS_SYMS))
        {
            free(formats);
            goto close_fd;
        }

        free(formats);

        if ((bfd_read_minisymbols(fd, FALSE, (void **)&symbol_table, &dummy) == 0) &&
            (bfd_read_minisymbols(fd, TRUE, (void **)&symbol_table, &dummy) < 0))
            goto free_symbol_table;

        EXM_LOG_DBG("bfd set up for frame #%d", i);

        data.function = NULL;
        data.symbol_table = symbol_table;
        /* we substract 1 because (From Kai Tietz) : */
        /* the back-trace address collected is the return-address of the call. */
        /* So this location might be pointing already to next line.*/
        data.counter = (bfd_vma)(uintptr_t)((char *)frames[i] - 1);
        bfd_map_over_sections(fd,
                              &_exm_stack_find_function_name_in_section,
                              &data);

      free_symbol_table:
        free(symbol_table);
      close_fd:
        bfd_close(fd);
    }

    return data.list;
}

EXM_API const char *
exm_stack_data_filename_get(const Exm_Stack_Data *data)
{
    if (!data)
        return NULL;

    return data->filename;
}

EXM_API const char *
exm_stack_data_function_get(const Exm_Stack_Data *data)
{
    if (!data)
        return NULL;

    return data->function;
}

EXM_API unsigned int
exm_stack_data_line_get(const Exm_Stack_Data *data)
{
    if (!data)
        return 0;

    return data->line;
}

EXM_API void
exm_stack_data_free(void *ptr)
{
    Exm_Stack_Data *data;

    if (!ptr)
        return;

    data = (Exm_Stack_Data *)ptr;
    if (data->filename)
        free(data->filename);
    if (data->function)
        free(data->function);
    free(data);
}

EXM_API void
exm_stack_disp(const Exm_List *stack)
{
    const Exm_List *iter;
    unsigned char at = 1;

    iter = stack;
    while (iter)
    {
        Exm_Stack_Data *frame;

        frame = (Exm_Stack_Data *)iter->data;
        if (at)
        {
            EXM_LOG_INFO("   at 0x00000000: %s (%s:%u)",
                         exm_stack_data_function_get(frame),
                         exm_stack_data_filename_get(frame),
                         exm_stack_data_line_get(frame));
            at = 0;
        }
        else
            EXM_LOG_INFO("   by 0x00000000: %s (%s:%u)",
                         exm_stack_data_function_get(frame),
                         exm_stack_data_filename_get(frame),
                         exm_stack_data_line_get(frame));
        iter = iter->next;
    }
}
