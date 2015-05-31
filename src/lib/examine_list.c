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

#include "Examine.h"


/**
 * @defgroup List functions
 *
 * @{
 */


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


/**
 * @brief Append an element to the given list.
 *
 * @param[inout] l The list.
 * @param[in] data The element.
 * @return The list with the appended element.
 *
 * This function appends @p data to the list @p l. If @p data is
 * @c NULL, this function returns @p l. To create a new list, @p l
 * must be @c NULL.
 */
EXM_API Exm_List *
exm_list_append(Exm_List *l, const void *data)
{
    Exm_List *iter;
    Exm_List *n;

    if (!data)
        return l;

    n = (Exm_List *)malloc(sizeof(Exm_List));
    if (!n)
        return l;

    n->data = (void *)data;
    n->next = NULL;

    if (!l)
        return n;

    iter = l;
    while (iter->next)
        iter = iter->next;

    iter->next = n;

    return l;
}

/**
 * @brief Prepend an element to the given list.
 *
 * @param[inout] l The list.
 * @param[in] data The element.
 * @return The list with the prepended element.
 *
 * This function prepends @p data to the list @p l. If @p data is
 * @c NULL, this function returns @p l. To create a new list, @p l
 * must be @c NULL.
 */
EXM_API Exm_List *
exm_list_prepend(Exm_List *l, const void *data)
{
    Exm_List *n;

    if (!data)
        return l;

    n = (Exm_List *)malloc(sizeof(Exm_List));
    if (!n)
        return l;

    n->data = (void *)data;
    n->next = l;

    return n;
}

EXM_API Exm_List *
exm_list_insert(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb)
{
    Exm_List *n;
    Exm_List *iter;

    if (!data)
        return l;

    /* empty list ? we just append the item */
    if (!l)
        return exm_list_append(l, data);

    /* data is the smallest ? we prepend the item */
    if (cmp_cb(data, l->data) <= 0)
        return exm_list_prepend(l, data);

    iter = l;
    while (iter)
    {
        if ((iter->next) && (cmp_cb(data, iter->next->data) < 0))
            break;

        iter = iter->next;
    }

    if (!iter)
        return exm_list_append(l, data);

    n = (Exm_List *)malloc(sizeof(Exm_List));
    if (!n)
        return l;

    n->data = (void *)data;
    n->next = iter->next;
    iter->next = n;

    return l;
}

EXM_API Exm_List *
exm_list_remove(Exm_List *l, void *data, Exm_List_Free_Cb free_cb)
{
    Exm_List *iter;

    if (!l)
        return NULL;

    if (!data)
        return l;

    /* First case : data is the first element */
    if (l->data == data)
    {
        Exm_List *res;

        res = l->next;
        free_cb(l->data);
        free(l);

        return res;
    }

    /* Second case: it is not the first element ! */
    iter = l;
    while (iter)
    {
        if (iter->next)
        {
            if (iter->next->data == data)
            {
                Exm_List *n;

                n = iter->next->next;
                free_cb(iter->next->data);
                free(iter->next);
                iter->next = n;

                return l;
            }
        }

        iter = iter->next;
    }

    return l;
}

/**
 * @brief Check if the given data already belongs to the given list.
 *
 * @param[inout] l The list.
 * @param[in] data The data to check.
 * @param[in] cmp_cb The comparison callback.
 * @return 1 if the data is found, 0 otherwise.
 *
 * This function checks if @p data belongs to @p l. It returns 1 if it
 * belongs to @p l, 0 otherwise.
 */
EXM_API unsigned char
exm_list_data_is_found(const Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb)
{
    Exm_List *iter;

    if (!data)
        return 0;

    iter = (Exm_List *)l;
    while (iter)
    {
        if (cmp_cb(iter->data, data) == 0)
            return 1;

        iter = iter->next;
    }

    return 0;
}

/**
 * @brief Append an element to the given list with a comparison callback.
 *
 * @param[inout] l The list.
 * @param[in] data The data to append.
 * @param[in] cmp_cb The comparison callback.
 * @return The list with the appended element.
 *
 * This function appends @p data to @p l if it satisfies the
 * comparison callback @p cmp_cb. If @cmp_cb returns 0, @p data is not
 * added to @p l.
 */
EXM_API Exm_List *
exm_list_append_if_new(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb)
{
    Exm_List *iter;
    int append = 1;

    if (!data)
        return l;

    iter = l;
    while (iter)
    {
        if (cmp_cb(iter->data, data) == 0)
        {
            append = 0;
            break;
        }
        iter = iter->next;
    }

    if (append)
        l = exm_list_append(l, data);

    return l;
}

/**
 * @brief Prepend an element to the given list with a comparison callback.
 *
 * @param[inout] l The list.
 * @param[in] data The data to prepend.
 * @param[in] cmp_cb The comparison callback.
 * @return The list with the prepended element.
 *
 * This function prepends @p data to @p l if it satisfies the
 * comparison callback @p cmp_cb. If @cmp_cb returns 0, @p data is not
 * added to @p l.
 */
EXM_API Exm_List *
exm_list_prepend_if_new(Exm_List *l, const void *data, Exm_List_Cmp_Cb cmp_cb)
{
    Exm_List *iter;
    int prepend = 1;

    if (!data)
        return l;

    iter = l;
    while (iter)
    {
        if (cmp_cb(iter->data, data) == 0)
        {
            prepend = 0;
            break;
        }
        iter = iter->next;
    }

    if (prepend)
        l = exm_list_prepend(l, data);

    return l;
}

/**
 * @brief Free the given list.
 *
 * @param[inout] l The list to free.
 * @param[in] free_cb The free callback.
 *
 * This function frees the list @l using the free callback @p free_cb
 * to free each element. If @p l is @c NULL, nothing is done.
 */
EXM_API void
exm_list_free(Exm_List *l, Exm_List_Free_Cb free_cb)
{
    Exm_List *iter;

    if (!l)
        return;

    iter = l;
    while (iter)
    {
        Exm_List *n;

        if (iter->data && free_cb)
            free_cb(iter->data);
        n = iter->next;
        free(iter);
        iter = n;
    }
}

/**
 * @brief Return the nmber of elements of the given list.
 *
 * @param[in] l The list.
 * @return The number of elements.
 *
 * This function returns the number of elements of the list @p l. If
 * @p l is @c null, 0 is returned.
 */
EXM_API int
exm_list_count(const Exm_List *l)
{
    Exm_List *iter;
    int count = 0;

    if (!l)
        return 0;

    iter = (Exm_List *)l;
    while (iter)
    {
        count ++;
        iter = iter->next;
    }

    return count;
}

/**
 * @}
 */
