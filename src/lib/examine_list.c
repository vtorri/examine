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

#include "examine_list.h"


Exm_List *
exm_list_append(Exm_List *l, void *data)
{
    Exm_List *iter;
    Exm_List *n;

    if (!data)
        return l;

    n = (Exm_List *)malloc(sizeof(Exm_List));
    if (!n)
        return l;

    n->data = data;
    n->next = NULL;

    if (!l)
        return n;

    iter = l;
    while (iter->next)
        iter = iter->next;

    iter->next = n;

    return l;
}

void
exm_list_free(Exm_List *l, void (*free_cb)(void *ptr))
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

int
exm_list_count(Exm_List *l)
{
    Exm_List *iter;
    int count = 0;

    if (!l)
        return 0;

    iter = l;
    while (iter)
    {
        count ++;
        iter = iter->next;
    }

    return count;
}
