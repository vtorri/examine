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
#include <string.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN
#else
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <unistd.h>
# include <fcntl.h>
#endif

#include "Examine.h"

#include "examine_private_map.h"


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
    unsigned long long size;
    unsigned int from_base : 1;
#else
    off_t size;
    int fd;
#endif
};

struct _Exm_Map_Shared
{
    void *base;
#ifdef _WIN32
    HANDLE handle;
#else
    char *name;
    off_t size;
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
    LARGE_INTEGER size;

    map = (Exm_Map *)calloc(1, sizeof(Exm_Map));
    if (!map)
        return NULL;

    map->file = CreateFile(filename,
                           GENERIC_READ | FILE_READ_ATTRIBUTES,
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

    if (!GetFileSizeEx(map->file, &size))
    {
        EXM_LOG_ERR("Can not retrieve size of file %s", filename);
        goto close_file;
    }

    map->size = size.QuadPart;

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

Exm_Map *
exm_map_new_from_base(const void *base, DWORD size)
{
    Exm_Map *map;

    if (!base ||(size <= 0))
    {
        EXM_LOG_ERR("Base address of the module is invalid");
        return NULL;
    }

    map = (Exm_Map *)calloc(1, sizeof(Exm_Map));
    if (!map)
        return NULL;

    map->base = (void *)base;
    map->size = size;
    map->from_base = 1;

    return map;
}

void
exm_map_del(Exm_Map *map)
{
    if (!map->from_base)
    {
        UnmapViewOfFile(map->base);
        CloseHandle(map->map);
        CloseHandle(map->file);
    }
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

unsigned long long
exm_map_size_get(const Exm_Map *map)
{
    return map->size;
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


EXM_API Exm_Map_Shared *
exm_map_shared_new(const char *name, const void *data, unsigned int size)
{
    Exm_Map_Shared *map;
#ifndef _WIN32
    size_t len;
    int fd;
#endif

    if (!name || (size <= 0))
    {
        EXM_LOG_ERR("Base address of the module is invalid");
        return NULL;
    }

    map = (Exm_Map_Shared *)calloc(1, sizeof(Exm_Map_Shared));
    if (!map)
    {
        EXM_LOG_ERR("Can not allocate memory for shared map");
        return NULL;
    }

#ifdef _WIN32
    map->handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                    NULL, PAGE_READWRITE, 0, size, name);
    if (!map->handle)
    {
        EXM_LOG_ERR("Can not create file mapping object");
        exm_map_shared_del(map);
        return NULL;
    }

    map->base = MapViewOfFile(map->handle, FILE_MAP_WRITE, 0, 0, size);
    if (!map->base)
    {
        EXM_LOG_ERR("Can not map memory for shared map");
        exm_map_shared_del(map);
        return NULL;
    }
#else
    len = strlen(name);
    /* len + first '/' + last '\0' <= 255 */
    if (len > 253)
    {
        EXM_LOG_ERR("Name length for the shared memory object is too high");
        exm_map_shared_del(map);
        return NULL;
    }

    map->name = (char *)malloc((len + 2) * sizeof(char));
    if (!map->name)
    {
        EXM_LOG_ERR("Can not allocate memory for the name of the shared memory object");
        exm_map_shared_del(map);
        return NULL;
    }

    map->name[0] = '/';
    memcpy(map->name + 1, name, len + 1);

    EXM_LOG_DBG("Create shared memory object of name %s", map->name);
    fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        EXM_LOG_ERR("Can not create shared memory object");
        exm_map_shared_del(map);
        return NULL;
    }

    map->size = size;

    if (ftruncate(fd, map->size) == -1)
    {
        EXM_LOG_ERR("Can not set the size of the shared memory object");
        exm_map_shared_del(map);
        return NULL;
    }

    map->base = mmap(NULL, map->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map->base == MAP_FAILED)
    {
        EXM_LOG_ERR("Can not map memory for shared memory object");
        exm_map_shared_del(map);
        return NULL;
    }
#endif

    memcpy(map->base, data, size);

    return map;
}

EXM_API void
exm_map_shared_del(Exm_Map_Shared *map)
{
    if (!map)
        return;

#ifdef _WIN32
    if (map->base)
        UnmapViewOfFile(map->base);
    if (map->handle)
        CloseHandle(map->handle);
#else
    if (map->base)
        munmap(map->base, map->size);
    if (map->name)
    {
        shm_unlink(map->name);
        free(map->name);
    }
#endif
    free(map);
}

EXM_API unsigned char
exm_map_shared_read(const char *name, unsigned int size, void *data)
{
#ifdef _WIN32
    HANDLE handle;
#else
    char buf[255];
    size_t len;
    int fd;
#endif
    void *base;

    if (!name || ! data)
    {
        EXM_LOG_ERR("arguments invalids");
        return 0;
    }

#ifdef _WIN32
    handle = CreateFileMapping(INVALID_HANDLE_VALUE,
                               NULL, PAGE_READWRITE, 0, size,
                               name);
    if (!handle)
        return 0;

    base = MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, size);
    if (!base)
    {
        CloseHandle(handle);
        return 0;
    }

    CopyMemory(data, base, size);

    UnmapViewOfFile(base);
    CloseHandle(handle);
#else
    len = strlen(name);
    /* len + first '/' + last '\0' <= 255 */
    if (len > 253)
    {
        EXM_LOG_ERR("Name length for the shared memory object is too high");
        return 0;
    }

    buf[0] = '/';
    memcpy(buf + 1, name, len + 1);

    fd = shm_open(buf, O_RDONLY, S_IRUSR);
    if (fd == -1)
    {
        EXM_LOG_ERR("Can not open shared memory object named %s", buf);
        return 0;
    }

    base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED)
    {
        EXM_LOG_ERR("Can not map memory for shared memory object");
        shm_unlink(buf);
        return 0;
    }

    memcpy(data, base, size);

    munmap(base, size);
    shm_unlink(buf);
#endif

    return 1;
}


/**
 * @}
 */
