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
#include <string.h>

#include "Examine.h"

#include "examine_private_str.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


/**
 * @brief Append the given string to the given buffer string with quotes.
 *
 * @param[inout] buf The buffer string;
 * @param[in] str The string to apppend.
 *
 * This function appends the string @p str to the buffer @p buf with
 * quotes around it. The buffer must be initialize at first as an
 * empty string. If @p str is @c NULL, the function does nothing. No
 * check is done on @p buf.
 */
void
exm_str_append_with_quotes(char *buf, const char *str)
{
    if (!str)
        return;

    if (!*buf)
    {
        size_t l;

        l = strlen(str);
        buf[0] = '\"';
        memcpy(buf + 1, str, l);
        buf[l + 1] = '\"';
        buf[l + 2] = '\0';
    }
    else
    {
        size_t l1;
        size_t l2;

        l1 = strlen(buf);
        l2 = strlen(str);
        buf[l1] = ' ';
        buf[l1 + 1] = '\"';
        memcpy(buf + l1 + 2, str, l2);
        buf[l1 + l2 + 2] = '\"';
        buf[l1 + l2 + 3] = '\0';
    }
}


/*============================================================================*
 *                                   API                                      *
 *============================================================================*/


/**
 * @brief Append the given string to the given buffer string.
 *
 * @param[inout] buf The buffer string;
 * @param[in] str The string to apppend.
 *
 * This function appends the string @p str to the buffer @p buf. The
 * buffer must be initialize at first as an empty string. If @p str is
 * @c NULL, the function does nothing. No check is done on @p buf.
 */
void
EXM_API exm_str_append(char *buf, const char *str)
{
    if (!str)
        return;

    if (!*buf)
        memcpy(buf, str, strlen(str) + 1);
    else
    {
        size_t l1;

        l1 = strlen(buf);
        buf[l1] = ' ';
        memcpy(buf + l1 + 1, str, strlen(str) + 1);
    }
}
