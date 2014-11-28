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

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <unistd.h>
# include <fcntl.h>
#endif

#include "examine_log.h"
#include "examine_map.h"


/**
 * @defgroup Map Shared mapped file functions
 *
 * The main purpose of this file is to provide a cross-platform way to
 * map a file in shared memory. It is used only for parsing PE files.
 *
 * @{
 */

/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


struct _Exm_Map
{
    void *base;
#ifdef _WIN32
    HANDLE file;
    HANDLE map;
#else
    off_t size;
    int fd;
#endif
};


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


#ifdef _WIN32

Exm_Map *
exm_map_new(const char *filename)
{
    Exm_Map *map;

    map = (Exm_Map *)calloc(1, sizeof(Exm_Map));
    if (!map)
        return NULL;

    map->file = CreateFile(filename,
                           GENERIC_READ,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (map->file == INVALID_HANDLE_VALUE)
    {
        EXM_LOG_ERR("Can not open file %s", filename);
        goto free_map;
    }

    map->map = CreateFileMapping(map->file,
                                      NULL, PAGE_READONLY,
                                      0, 0, NULL);
    if (!map->map)
    {
        EXM_LOG_ERR("Can not create file mapping for file %s", filename);
        goto close_file;
    }

    map->base = MapViewOfFile(map->map, FILE_MAP_READ, 0, 0, 0);
    if (!map->base)
    {
        EXM_LOG_ERR("Can not create view for file mapping 0x%p", map->map);
        goto close_file_map;
    }

    return map;

  close_file_map:
    CloseHandle(map->map);
  close_file:
    CloseHandle(map->file);
  free_map:
    free(map);

    return NULL;
}

void
exm_map_del(Exm_Map *map)
{
    UnmapViewOfFile(map->base);
    CloseHandle(map->map);
    CloseHandle(map->file);
    free(map);
}

#else

Exm_Map *
exm_map_new(const char *filename)
{
    struct stat st;
    Exm_Map *map;

    map = (Exm_Map *)calloc(1, sizeof(Exm_Map));
    if (!map)
        return NULL;

    map->fd = open(filename, O_RDONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (map->fd == -1)
    {
        EXM_LOG_ERR("Can not open file %s", filename);
        goto free_map;
    }

    if (fstat(map->fd, &st) == -1)
    {
        EXM_LOG_ERR("Can not retrieve stat from file %s", filename);
        goto close_fd;
    }

    map->size = st.st_size;

    map->base = mmap(NULL, map->size, PROT_READ, MAP_SHARED, map->fd, 0);
    if (!map->base)
        goto close_fd;

    return map;

  close_fd:
    close(map->fd);
  free_map:
    free(map);

    return NULL;
}

void
exm_map_del(Exm_Map *map)
{
    munmap(map->base, map->size);
    close(map->fd);
    free(map);
}

#endif

const void *
exm_map_base_get(const Exm_Map *map)
{
    return map->base;
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


/**
 * @}
 */
