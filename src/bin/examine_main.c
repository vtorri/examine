/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2012-2016 Vincent Torri.
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
#include <stdio.h>
#include <string.h>

#include <Examine.h>

#include "examine_private.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/


typedef enum
{
    EXM_TOOL_MEMCHECK,
    EXM_TOOL_TRACE,
    EXM_TOOL_DEPENDS,
    EXM_TOOL_VIEW,
    EXM_TOOL_SIGCHECK
} Exm_Tool;

static void
_exm_usage(void)
{
    printf("Usage:\n");
    printf("  examine [options] file [args]\n");
    printf("\n");
    printf("  tool-selection option, with default in [ ]:\n");
    printf("    --tool=<name>             use the Examine tool named <name> [memcheck]\n");
    printf("\n");
    printf("    Available tools:\n");
    printf("      memcheck: memory checker\n");
    printf("      trace:    trace calling functions\n");
    printf("      depends:  dependencies of PE files\n");
    printf("      view:     view content of PE header file\n");
    printf("      sigcheck: view signature of an application\n");
    printf("\n");
    printf("  basic user options for all Examine tools, with defaults in [ ]:\n");
    printf("    -h, --help                show this message\n");
    printf("    -V, --version             show version\n");
    printf("    -l, --log-level=lvl       set log level to lvl, print log with level less or equal than lvl [2]\n");
    printf("                                0: error\n");
    printf("                                1: warning\n");
    printf("                                2: information\n");
    printf("                                3: debug\n");
    printf("    -v, --verbose             synonym to --log-level=3\n");
    printf("    -q, --quiet               synonym to --log-level=0\n");
    printf("\n");
    printf("  user options for Depends:\n");
    printf("    --list                    run in text mode, display the list of dependencies\n");
    printf("                              default is the tree of dependencies\n");
    printf("    --gui                     run in graphical mode\n");
    printf("\n");
    printf("  user options for View:\n");
    printf("    --gui                     run in graphical mode\n");
    printf("\n");
    printf("  Examine is Copyright (C) 2012-2016, and GNU LGPL3'd, by Vincent Torri.\n");
    printf("\n");
    printf("  Bug reports, feedback, remarks, ... to https://github.com/vtorri/examine.\n");
    printf("\n");
}

static int main2(int argc, char *argv[])
{
    char buf_command[32768];
    char buf_args[32768];
    char *module;
    Exm_List *options = NULL;
    int i;
    Exm_Tool tool = EXM_TOOL_MEMCHECK;
    Exm_Log_Level log_level = EXM_LOG_LEVEL_INFO;
    unsigned int argv_idx = 0;
    unsigned char lvl = 0;
    unsigned char verbose = 0;
    unsigned char quiet = 0;
    unsigned char depends_list = 0;
    unsigned char depends_gui = 0;
    unsigned char view_gui = 0;

    if (argc < 2)
    {
        _exm_usage();
        return -1;
    }

    buf_args[0] = '\0';
    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            if (argv_idx == 0)
            {
                _exm_usage();
                return 0;
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if ((strcmp(argv[i], "-V") == 0) || (strcmp(argv[i], "--version") == 0))
        {
            if (argv_idx == 0)
            {
                printf("%s\n", PACKAGE_STRING);
                return 0;
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if (strcmp(argv[i], "-l") == 0)
        {
            if (argv_idx == 0)
            {
                char buf[8];

                buf[0] = '\0';
                exm_str_append(buf, "-l");
                if ((i + 1) < argc)
                {
                    i++;
                    if ((argv[i][0] >= '0') &&
                        (argv[i][0] <= '3') &&
                        (argv[i][1] == '\0'))
                    {
                        lvl = 1;
                        log_level = argv[i][0] - '0';
                        exm_str_append(buf, argv[i]);
                        options = exm_list_append(options, _strdup(buf));
                    }
                    else
                    {
                        EXM_LOG_ERR("-l option must be followed by a number between 0 and 3");
                        _exm_usage();
                        return 0;
                    }
                }
                else
                {
                    EXM_LOG_ERR("-l option must be followed by a number");
                    _exm_usage();
                    return 0;
                }
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if (strncmp(argv[i], "--log-level=", sizeof("--log-level=") - 1) == 0)
        {
            if (argv_idx == 0)
            {
                char *ll;

                ll = argv[i] +  sizeof("--log-level=") - 1;
                if ((ll[0] >= '0') &&
                    (ll[0] <= '3') &&
                    (ll[1] == '\0'))
                {
                    lvl = 1;
                    log_level = ll[0] - '0';
                    options = exm_list_append(options, _strdup(argv[i]));
                }
                else
                {
                    EXM_LOG_ERR("--log-level option must be followed by a number");
                    _exm_usage();
                    return 0;
                }
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if ((strcmp(argv[i], "-v") == 0) || (strcmp(argv[i], "--verbose") == 0))
        {
            if (argv_idx == 0)
            {
                verbose = 1;
                log_level = EXM_LOG_LEVEL_DBG;
                options = exm_list_append(options, _strdup(argv[i]));
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if ((strcmp(argv[i], "-q") == 0) || (strcmp(argv[i], "--quiet") == 0))
        {
            if (argv_idx == 0)
            {
                quiet = 1;
                log_level = EXM_LOG_LEVEL_ERR;
                options = exm_list_append(options, _strdup(argv[i]));
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else if (memcmp(argv[i], "--tool=", sizeof("--tool=") - 1) == 0)
        {
            if (argv_idx == 0)
            {
                if (strcmp(argv[i], "--tool=memcheck") == 0)
                {
                    tool = 0;
                    options = exm_list_append(options, _strdup(argv[i]));
                }
                else if (strcmp(argv[i], "--tool=trace") == 0)
                {
                    tool = 1;
                    options = exm_list_append(options, _strdup(argv[i]));
                }
                else if (strcmp(argv[i], "--tool=depends") == 0)
                {
                    tool = 2;
                    options = exm_list_append(options, _strdup(argv[i]));
                    if ((i + 1) < argc)
                    {
                        if (strcmp(argv[i + 1], "--gui") == 0)
                        {
                            depends_gui = 1;
                            i++;
                            options = exm_list_append(options, _strdup(argv[i]));
                        }
                        else if (strcmp(argv[i + 1], "--list") == 0)
                        {
                            depends_list = 1;
                            i++;
                            options = exm_list_append(options, _strdup(argv[i]));
                        }
                    }
                }
                else if (strcmp(argv[i], "--tool=view") == 0)
                {
                    tool = 3;
                    options = exm_list_append(options, _strdup(argv[i]));
                    if ((i + 1) < argc)
                    {
                        if (strcmp(argv[i + 1], "--gui") == 0)
                        {
                            view_gui = 1;
                            i++;
                            options = exm_list_append(options, _strdup(argv[i]));
                        }
                    }
                }
                else if (strcmp(argv[i], "--tool=sigcheck") == 0)
                {
                    tool = 4;
                    options = exm_list_append(options, _strdup(argv[i]));
                }
                else
                {
                    _exm_usage();
                    return -1;
                }
            }
            else
                exm_str_append(buf_args, argv[i]);
        }
        else
        {
            if (argv_idx == 0)
                argv_idx = i;
            else
                exm_str_append(buf_args, argv[i]);
        }
    }

    if (argv_idx == 0)
    {
        EXM_LOG_ERR("No file name is provided");
        _exm_usage();
        exm_list_free(options, free);
        return -1;
    }

    if ((verbose && quiet) ||
        (verbose && lvl) ||
        (lvl && quiet))
    {
        EXM_LOG_ERR("can not pass log level, verbose or quiet options at the same time");
        _exm_usage();
        exm_list_free(options, free);
        return -1;
    }

    buf_command[0] = '\0';
    exm_str_append(buf_command, argv[argv_idx]);
    switch (tool)
    {
        case EXM_TOOL_MEMCHECK:
        case EXM_TOOL_TRACE:
            exm_str_append(buf_command, buf_args);
            break;
        default:
            break;
    }

    EXM_LOG_INFO("Examine, a memory leak detector, function and I/O tracer, and PE file viewer");
    EXM_LOG_INFO("Copyright (c) 2012-2016, and GNU LGPL3'd, by Vincent Torri");
    EXM_LOG_INFO("Using %s; rerun with -h for help and copyright notice", PACKAGE_STRING);
    EXM_LOG_INFO("");
    EXM_LOG_INFO("Command : %s", buf_command);
    EXM_LOG_INFO("");
    if (exm_list_count(options) > 0)
    {
        Exm_List *option;

        EXM_LOG_INFO("Examine options:");
        option = options;
        while (option)
        {
            EXM_LOG_INFO("   %s", (char *)option->data);
            option = option->next;
        }
    }

    exm_list_free(options, free);

    exm_log_level_set(log_level);

    if (!exm_init())
    {
        EXM_LOG_ERR("can not initialise Examine. Exiting...");
        return -1;
    }

    module = exm_file_set(argv[argv_idx]);
    if (!module)
    {
        EXM_LOG_ERR("Can not retrieve base name of %s. Exiting...", argv[argv_idx]);
        return -1;
    }

    switch (tool)
    {
        case EXM_TOOL_MEMCHECK:
        {
#ifdef _WIN32
            exm_mc_run(module, buf_args);
#else
            EXM_LOG_ERR("memcheck tool not available on UNIX");
#endif
            break;
        }
        case EXM_TOOL_TRACE:
            exm_trace_run(module, buf_args);
            break;
        case EXM_TOOL_DEPENDS:
            exm_depends_run(module, depends_list, depends_gui, log_level);
            break;
        case EXM_TOOL_VIEW:
            exm_view_run(module, view_gui, log_level);
            break;
        case EXM_TOOL_SIGCHECK:
#ifdef _WIN32
            exm_sigcheck_run(module, view_gui, log_level);
#else
            EXM_LOG_ERR("sigcheck tool not available on UNIX");
#endif
            break;
        default:
            EXM_LOG_ERR("unknown tool");
            break;
    }
    free(module);

    exm_shutdown();

    return 0;
}

int main(int argc, char *argv[])
{
#if defined(_MSC_VER) && defined(_DEBUG)
    _CrtMemState last_state;
    _HFILE file;
    int mode;
    int flags;
#endif
    int ret;

#if defined(_MSC_VER) && defined(_DEBUG)
    file  = _CRTDBG_FILE_STDERR;
    mode  = _CRTDBG_MODE_FILE;
    flags = _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_DELAY_FREE_MEM_DF;

    _CrtSetReportFile (_CRT_WARN, file);
    _CrtSetReportMode (_CRT_WARN, mode);
    _CrtSetDbgFlag (flags);
    _CrtMemCheckpoint (&last_state);
#endif

    ret = main2(argc, argv);

#if defined(_MSC_VER) && defined(_DEBUG)
    _CrtMemDumpAllObjectsSince (&last_state);
#endif

    return ret;
}
