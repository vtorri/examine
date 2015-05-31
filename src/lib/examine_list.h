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

#ifndef EXAMINE_LIST_H
#define EXAMINE_LIST_H


typedef struct _Exm_List Exm_List;

struct _Exm_List
{
    void *data;
    Exm_List *next;
};

typedef void (*Exm_List_Free_Cb)(void *ptr);
typedef int (*Exm_List_Cmp_Cb)(const void *d1, const void *d2);

EXM_API Exm_List *exm_list_append(Exm_List *l, const void *data);

EXM_API Exm_List *exm_list_prepend(Exm_List *l, const void *data);

EXM_API Exm_List *exm_list_insert(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb);

EXM_API Exm_List *exm_list_remove(Exm_List *l, void *data, Exm_List_Free_Cb free_cb);

EXM_API unsigned char exm_list_data_is_found(const Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb);

EXM_API Exm_List *exm_list_append_if_new(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb);

EXM_API Exm_List *exm_list_prepend_if_new(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb);

EXM_API void exm_list_free(Exm_List *l, Exm_List_Free_Cb free_cb);

EXM_API int exm_list_count(const Exm_List *l);


#endif /* EXAMINE_LIST_H */
