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
#include <string.h>

#include <examine_log.h>

#include "examine_private.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


static void
_exm_usage(void)
{
  printf("Usage:\n");
  printf("  examine [options] file [args]\n");
  printf("\n");
  printf("  tool-selection option, with default in [ ]:\n");
  printf("    --tool=<name>              use the Examine tool named <name> [memcheck]\n");
  printf("\n");
  printf("  basic user options for all Examine tools, with defaults in [ ]:\n");
  printf("    -h, --help                 show this message\n");
  printf("    -V, --version              show version\n");
  printf("\n");
  printf("  user options for Depends:\n");
  printf("    --gui                      run in graphical mode\n");
  printf("\n");
  printf("  Examine is Copyright (C) 2012-2014, and GNU GPL2'd, by Vincent Torri.\n");
  printf("\n");
  printf("  Bug reports, feedback, remarks, ... to https://github.com/vtorri/examine.\n");
  printf("\n");
}

int main(int argc, char *argv[])
{
    char *module = NULL;
    char *args = NULL;
    int i;
    unsigned char tool = 0; /* 0 : memcheck, 1 : trace, 2 : depends */
    unsigned char depends_gui = 0;

    if (argc < 2)
    {
        _exm_usage();
        return -1;
    }

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            _exm_usage();
            return 0;
        }
        else if ((strcmp(argv[i], "-V") == 0) || (strcmp(argv[i], "--version") == 0))
        {
            printf("%s\n", PACKAGE_STRING);
            return 0;
        }
        else if (memcmp(argv[i], "--tool=", sizeof("--tool=") - 1) == 0)
        {
            if (strcmp(argv[i], "--tool=memcheck") == 0)
            {
                tool = 0;
            }
            else if (strcmp(argv[i], "--tool=trace") == 0)
            {
                tool = 1;
            }
            else if (strcmp(argv[i], "--tool=depends") == 0)
            {
                tool = 2;
                if ((i + 1) < argc)
                {
                    if (strcmp(argv[i + 1], "--gui") == 0)
                    {
                        depends_gui = 1;
                        i++;
                    }
                }
            }
            else
            {
                _exm_usage();
                return -1;
            }
        }
        else
        {
            if (!module)
            {
                module = strdup(argv[i]);
                if (!module)
                {
                    EXM_LOG_ERR("memory allocation error");
                    return -1;
                }
            }
            else
            {
                if (!args)
                {
                    args = strdup(argv[i]);
                    if (!args)
                    {
                        EXM_LOG_ERR("memory allocation error");
                        free(module);
                        return -1;
                    }
                }
                else
                {
                    size_t l1;
                    size_t l2;

                    l1 = strlen(args);
                    l2 = strlen(argv[i]);
                    args = realloc(args, l1 + l2 + 2);
                    if (!args)
                    {
                        EXM_LOG_ERR("memory allocation error");
                        free(module);
                        return -1;
                    }
                    args[l1] = ' ';
                    memcpy(args + l1 + 1, argv[i], l2 + 1);
                }
            }
        }
    }

    if (tool == 0)
        examine_memcheck_run(module, args);
    else if (tool == 1)
        examine_trace_run(module, args);
    else
    {
        if (args)
            free(args);
        examine_depends_run(module, depends_gui);
    }

    return 0;
}
