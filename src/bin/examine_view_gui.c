/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2015 Vincent Torri.
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

#include <Elementary.h>

#include <Examine.h>

typedef struct
{
    char *filename;

    struct
    {
        Exm_Pe *pe;
    } pe;

    struct
    {
        Evas_Object *win;
    } gui;
} Exm_View;

/************  build of the tree and lists  ************/

/************  build of the GUI  ************/

static void
_exm_view_delete_cb(void *data, Evas_Object *obj, void *event_info)
{
    elm_exit();
}

static void
_exm_view_usage(void)
{
  printf("Usage:\n");
  printf("  examine_view [options] file\n");
  printf("\n");
  printf("  user options for Examine view tools:\n");
  printf("\n");
  printf("    -h, --help                 show this message\n");
  printf("    -V, --version              show version\n");
  printf("\n");
  printf("    file must be given with absolute path.");
  printf("\n");
  printf("  Examine is Copyright (C) 2012-2014, and GNU GPL2'd, by Vincent Torri.\n");
  printf("\n");
  printf("  Bug reports, feedback, remarks, ... to https://github.com/vtorri/examine.\n");
  printf("\n");
}

EAPI_MAIN int
elm_main(int argc, char **argv)
{
    Exm_View *exm;
    Exm_List *iter_list;
    char *module;
    Exm_Log_Level log_level;
    int argv_idx = -1;
    int i;
    Evas_Object *o;
    Evas_Object *box;
    Evas_Object *frame_dos;
    Evas_Object *table_dos;
    int col;

    if (argc < 2)
    {
        _exm_view_usage();
        return -1;
    }

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            _exm_view_usage();
            return 0;
        }
        else if ((strcmp(argv[i], "-V") == 0) || (strcmp(argv[i], "--version") == 0))
        {
            printf("%s\n", PACKAGE_STRING);
            return 0;
        }
        else
        {
            argv_idx = i;
            break;
        }
    }

    if (!exm_map_shared_read("exm_view_gui_shared",
                             sizeof(Exm_Log_Level), &log_level))
    {
        EXM_LOG_ERR("Can not retrieve shared lengths data");
        return -1;
    }

    exm_log_level_set(log_level);

    if (!exm_init())
    {
        EXM_LOG_ERR("can not initialise Examine. Exiting...");
        return -1;
    }

    module = exm_file_set(argv[argv_idx]);

    exm = (Exm_View *)calloc(1, sizeof(Exm_View));
    if (!exm)
    {
        EXM_LOG_ERR("memory allocation error");
        return -1;
    }

    exm->pe.pe = exm_pe_new(module);
    if (!exm->pe.pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        free(module);
        free(exm);
        return -1;
    }

    free(module);

    elm_policy_set(ELM_POLICY_QUIT, ELM_POLICY_QUIT_LAST_WINDOW_CLOSED);

    o = elm_win_add(NULL, "Examine View GUI", ELM_WIN_BASIC);
    elm_win_title_set(o, "Examine View");
    evas_object_smart_callback_add(o, "delete,request",
                                   _exm_view_delete_cb, NULL);
    exm->gui.win = o;

    o = elm_bg_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    elm_win_resize_object_add(exm->gui.win, o);
    evas_object_show(o);

    o = elm_box_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_win_resize_object_add(exm->gui.win, o);
    evas_object_show(o);
    box = o;

    o = elm_table_add(exm->gui.win);
    /* elm_table_padding_set(o, 0, 10); */
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_box_pack_end(box, o);
    evas_object_show(o);
    table_dos = o;

    o = elm_frame_add(exm->gui.win);
    elm_object_text_set(o, "DOS Header");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_object_content_set(frame_dos, table_dos);
    evas_object_show(o);
    frame_dos = o;

    col = 0;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Field");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 0, 1, 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Type");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 0, 1, 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Value");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 0, 1, 1);
    evas_object_show(o);




    col = 0;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Field");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 1, 1, 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Type");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 1, 1, 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Value");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(table_dos, o, col++, 1, 1, 1);
    evas_object_show(o);




    evas_object_resize(exm->gui.win, 480, 640);
    evas_object_show(exm->gui.win);

    elm_run();

    return 0;
}
ELM_MAIN()
