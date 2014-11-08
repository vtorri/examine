/* Examine - a tool for memory leak detection on Windows
 *
 * Copyright (C) 2012-2014 Vincent Torri.
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

#include "examine_list.h"


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
Exm_List *
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
 * @brief append an element to the given list with a comparison callback.
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
Exm_List *
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
 * @brief Free the given list.
 *
 * @param[inout] l The list to free.
 * @param[in] free_cb The free callback.
 *
 * This function frees the list @l using the free callback @p free_cb
 * to free each element. If @p l is @c NULL, nothing is done.
 */
void
exm_list_free(Exm_List *l, Exm_List_Free_Cb free_cb)
{
    Exm_List *iter;

    if (!l)
        return;

    iter = l;
    while (iter)
    {
        Exm_List *n;

        if (iter->data)
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
int
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
