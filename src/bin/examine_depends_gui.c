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

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <Elementary.h>

#include <Examine.h>

typedef struct _Exm_List_Modules_Node Exm_List_Modules_Node;

typedef struct
{
    unsigned short major;
    unsigned short minor;
} Exm_Version;

typedef struct
{
    WORD ordinal;
    char *name;
    DWORD address;
} Exm_Exported_Fct;

typedef struct
{
    Exm_Pe *file;
    Exm_Pe *parent;
    Exm_List *child;
    const Exm_List_Modules_Node *list_node;
    unsigned int is_found : 1;
} Exm_Tree_Modules_Node;

struct _Exm_List_Modules_Node
{
    char *filename;
    time_t creation_date;
    time_t modification_date;
    unsigned __int64 size;
    char perm[9];
    unsigned int checksum;
    unsigned int cpu;
    unsigned int subsystem;
    unsigned long long preferred_base;
    Exm_Version version_image;
    Exm_Version version_linker;
    Exm_Version version_os;
    Exm_Version version_subsystem;
    unsigned int exported_fct_count;
    Exm_Exported_Fct *exported_fct;
    unsigned int is_64bits : 1;
};

typedef struct
{
    char *filename;

    struct
    {
        Exm_Pe *pe;
        Exm_List *tree_modules;
        Exm_List *list_modules;
    } pe;

    struct
    {
        Evas_Object *win;
        Evas_Object *dependency_tree;
        Evas_Object *parent_fcts;
        Evas_Object *export_fcts;
        Evas_Object *modules;
        Evas_Object *logs;
        Elm_Genlist_Item_Class *itc;
    } gui;
} Exm_Depends;

/************  build of the tree and lists  ************/

double
_exm_time_get(void)
{
   struct timeval timev;

   gettimeofday(&timev, NULL);
   return (double)timev.tv_sec + (((double)timev.tv_usec) / 1000000);
}

static int
_exm_depends_cmp_cb(const void *d1, const void *d2)
{
    return _stricmp((const char *)(((Exm_List_Modules_Node *)d1)->filename), (const char *)d2);
}

static Exm_List_Modules_Node *
_exm_depends_list_modules_node_new(Exm_Pe *pe)
{
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    struct _stati64 buf;
#else
    struct stat buf;
#endif
    const IMAGE_NT_HEADERS *nt_header;
    const IMAGE_EXPORT_DIRECTORY *ed;
    const IMAGE_IMPORT_DESCRIPTOR *id;
    Exm_List_Modules_Node *node;
    unsigned long long seconds;
    DWORD i;

    if (exm_pe_is_64bits(pe) == -1)
        return NULL;

    node = (Exm_List_Modules_Node *)calloc(1, sizeof(Exm_List_Modules_Node));
    if (!node)
        return NULL;

    node->is_64bits = exm_pe_is_64bits(pe);

    node->filename = strdup(exm_pe_filename_get(pe));
    if (!node->filename)
        goto free_node;

#ifdef _WIN32
    if (_stati64(node->filename, &buf) != 0)
        goto free_filename;
#else
    if (stat(node->filename, &buf) != 0)
        goto free_filename;
#endif

    node->creation_date = buf.st_ctime;

    nt_header = exm_pe_nt_header_get(pe);

#define EXM_WINDOWS_TICK 10000000
#define EXM_SEC_TO_UNIX_EPOCH 11644473600LL

    seconds = (nt_header->FileHeader.TimeDateStamp / EXM_WINDOWS_TICK - EXM_SEC_TO_UNIX_EPOCH);
    node->modification_date = (time_t)seconds;
    if (seconds != (unsigned long long)node->modification_date) /* checks for truncation/overflow/underflow */
    {
        EXM_LOG_ERR("Can not transform Windows time to POSIX time");
        goto free_filename;
    }

    node->size = buf.st_size;
#ifdef _WIN32
    if (!GetFileAttributesEx(node->filename,
                             GetFileExInfoStandard,
                             &fad))
    {
        goto free_filename;
    }

    node->perm[0] = (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY)   ? 'R' : ' ';
    node->perm[1] = (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)     ? 'H' : ' ';
    node->perm[2] = (fad.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)     ? 'S' : ' ';
    node->perm[3] = (fad.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)    ? 'A' : ' ';
    node->perm[4] = (fad.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY)  ? 'T' : ' ';
    node->perm[5] = (fad.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) ? 'C' : ' ';
    node->perm[6] = (fad.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE)    ? '0' : ' ';
    node->perm[7] = (fad.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)  ? 'E' : ' ';
#else
    node->perm[0] = ' ';
    node->perm[1] = ' ';
    node->perm[2] = ' ';
    node->perm[3] = S_ISREG(buf.st_mode) ? 'A' : ' ';
    node->perm[4] = ' ';
    node->perm[5] = ' ';
    node->perm[6] = ' ';
    node->perm[7] = ' ';
#endif
    node->perm[8] = '\0';

    node->checksum = nt_header->OptionalHeader.CheckSum;
    node->cpu = nt_header->FileHeader.Machine;
    node->subsystem = nt_header->OptionalHeader.Subsystem;
    node->preferred_base = nt_header->OptionalHeader.ImageBase;

    node->version_image.major = nt_header->OptionalHeader.MajorImageVersion;
    node->version_image.minor = nt_header->OptionalHeader.MinorImageVersion;
    node->version_linker.major = nt_header->OptionalHeader.MajorLinkerVersion;
    node->version_linker.minor = nt_header->OptionalHeader.MinorLinkerVersion;
    node->version_os.major = nt_header->OptionalHeader.MajorOperatingSystemVersion;
    node->version_os.minor = nt_header->OptionalHeader.MinorOperatingSystemVersion;
    node->version_subsystem.major = nt_header->OptionalHeader.MajorSubsystemVersion;
    node->version_subsystem.minor = nt_header->OptionalHeader.MinorSubsystemVersion;

    /* { */
    /*     const IMAGE_DEBUG_DIRECTORY *dd; */
    /*     DWORD count; */

    /*     dd = exm_pe_debug_directory_get(pe, &count); */
    /*     if (dd && count) */
    /*     { */
    /*         int i; */

    /*         printf(" debug count : %ld\n", count); */
    /*         for (i = 0; i < count / sizeof(IMAGE_DEBUG_DIRECTORY); i++, dd++) */
    /*         { */
    /*             printf("debug type : %d\n", dd->Type); */
    /*         } */
    /*     } */
    /* } */

    ed = exm_pe_export_directory_get(pe, NULL);
    node->exported_fct_count = ed->NumberOfFunctions;
    node->exported_fct = (Exm_Exported_Fct *)calloc(node->exported_fct_count, sizeof(Exm_Exported_Fct));
    if (!node->exported_fct)
        goto free_filename;

    for (i = 0; i < node->exported_fct_count; i++)
    {
        DWORD j;

        node->exported_fct[i].ordinal = i + 1;
        node->exported_fct[i].address = exm_pe_export_directory_function_address_get(pe, ed, i);
        for (j = 0; j < ed->NumberOfNames; j++)
        {
            DWORD ordinal;

            if (exm_pe_export_directory_function_ordinal_get(pe, ed, j, &ordinal))
            {
                if (node->exported_fct[i].ordinal == ordinal)
                {
                    node->exported_fct[i].name = strdup(exm_pe_export_directory_function_name_get(pe, ed, i));
                    break;
                }
            }
        }
    }

    /* printf(" ** 1 : %s\n", exm_pe_filename_get(pe)); */
    id = exm_pe_import_descriptor_get(pe, NULL);
    /* if (id) */
    /*     printf(" ** name : %s\n", */
    /*            exm_pe_import_descriptor_file_name_get(pe, id)); */
    /* printf(" ** 3\n"); */

    return node;

  free_filename:
    free(node->filename);
  free_node:
    free(node);

    return NULL;
}

static void
_exm_depends_list_modules_node_free(void *ptr)
{
    Exm_List_Modules_Node *node;

    node = (Exm_List_Modules_Node *)ptr;
    free(node->filename);
    free(node);
}

static Exm_Tree_Modules_Node *
_exm_depends_tree_modules_node_new(const Exm_Pe *parent, const Exm_Pe *current, const Exm_List_Modules_Node *list_node)
{
    Exm_Tree_Modules_Node *node;
    const IMAGE_EXPORT_DIRECTORY *ed;
    DWORD i;

    node = (Exm_Tree_Modules_Node *)calloc(1, sizeof(Exm_Tree_Modules_Node));
    if (!node)
        return NULL;

    node->file = (Exm_Pe *)current;
    node->parent = (Exm_Pe *)parent;
    node->list_node = list_node;

    return node;

  free_node:
    free(node);

    return NULL;
}

static void
_exm_depends_tree_modules_node_free(void *ptr)
{
    Exm_Tree_Modules_Node *node;

    node = (Exm_Tree_Modules_Node *)ptr;
    /* free(node->filename); */
    exm_pe_free(node->file);
    free(node);
}

static void
_exm_depends_tree_modules_fill(const Exm_Pe *parent, Exm_List **tree_modules, Exm_List **list_modules)
{
    const IMAGE_IMPORT_DESCRIPTOR *iter_import;
    const IMAGE_DELAYLOAD_DESCRIPTOR *iter_delayload;
    Exm_List *iter_tree;
    DWORD count;
    DWORD i;

    iter_import = exm_pe_import_descriptor_get(parent, NULL);
    if (iter_import)
    {
        while (iter_import->Name != 0)
        {
            Exm_Tree_Modules_Node *tree_node;
            Exm_List_Modules_Node *list_node;
            Exm_Pe *pe;

            pe = exm_pe_new(exm_pe_import_descriptor_file_name_get(parent, iter_import));
            if (!pe)
                continue;

            list_node = _exm_depends_list_modules_node_new(pe);
            tree_node = _exm_depends_tree_modules_node_new(parent, pe, list_node);
            if (!tree_node)
            {
                EXM_LOG_ERR("Can not allocate memory for tree node");
                exm_pe_free(pe);
                continue;
            }

            *tree_modules = exm_list_append(*tree_modules, tree_node);

            tree_node->is_found = exm_list_data_is_found(*list_modules,
                                                         exm_pe_filename_get(tree_node->file),
                                                         _exm_depends_cmp_cb);

            if (!tree_node->is_found)
            {
                *list_modules = exm_list_append(*list_modules, list_node);
            }

            iter_import++;
        }
    }

    iter_delayload = exm_pe_delayload_descriptor_get(parent, &count);
    count /= sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    if (iter_delayload)
    {
        for (i = 0; i < (count - 1); i++, iter_delayload++)
        {
            Exm_Tree_Modules_Node *tree_node;
            Exm_List_Modules_Node *list_node;
            Exm_Pe *pe;

            pe = exm_pe_new(exm_pe_delayload_descriptor_file_name_get(parent, iter_delayload));
            if (!pe)
                continue;

            list_node = _exm_depends_list_modules_node_new(pe);
            tree_node = _exm_depends_tree_modules_node_new(parent, pe, list_node);
            if (!tree_node)
            {
                EXM_LOG_ERR("Can not allocate memory for tree node");
                exm_pe_free(pe);
                continue;
            }

            *tree_modules = exm_list_append(*tree_modules, tree_node);

            tree_node->is_found = exm_list_data_is_found(*list_modules,
                                                         exm_pe_filename_get(tree_node->file),
                                                         _exm_depends_cmp_cb);

            if (!tree_node->is_found)
            {
                *list_modules = exm_list_append(*list_modules, list_node);
            }
        }
    }

    iter_tree = *tree_modules;
    while (iter_tree)
    {
        Exm_Tree_Modules_Node *tree_node;

        tree_node = (Exm_Tree_Modules_Node *)iter_tree->data;
        if (!tree_node->is_found)
            _exm_depends_tree_modules_fill(tree_node->file,
                                            &tree_node->child,
                                            list_modules);
        iter_tree = iter_tree->next;
    }
}

static void
_exm_depends_tree_modules_get(Exm_Pe *pe, Exm_List **tree_modules, Exm_List **list_modules)
{
    Exm_Tree_Modules_Node *tree_node;
    Exm_List_Modules_Node *list_node;

    printf(" ** debut build tree 1\n");
    list_node = _exm_depends_list_modules_node_new(pe);
    *list_modules = exm_list_append(NULL, list_node);

    tree_node = _exm_depends_tree_modules_node_new(NULL, pe, list_node);
    _exm_depends_tree_modules_fill(pe, &tree_node->child, list_modules);

    *tree_modules = exm_list_append(NULL, tree_node);
    printf(" ** fin build tree\n");
}

/************  build of the GUI  ************/

static char *
_exm_depends_item_text_get_cb(void *data, Evas_Object *obj EINA_UNUSED, const char *part EINA_UNUSED)
{
    Exm_List *l = (Exm_List *)data;

    return strdup((char *)l->data);
}

static Evas_Object *
_exm_depends_item_content_get_cb(void *data EINA_UNUSED, Evas_Object *obj, const char *part EINA_UNUSED)
{
    Evas_Object *ic = elm_icon_add(obj);

    if (!strcmp(part, "elm.swallow.icon"))
        elm_icon_standard_set(ic, "clock");

    evas_object_size_hint_aspect_set(ic, EVAS_ASPECT_CONTROL_VERTICAL, 1, 1);

    return ic;
}

static void
_exm_depends_item_selection_get_cb(void *data, Evas_Object *obj, void *event_info)
{
    printf("sel item data [%s] on genlist obj [%p], item pointer [%p]\n",
           data, obj, event_info);
}

static void
_exm_depends_delete_cb(void *data, Evas_Object *obj, void *event_info)
{
    elm_exit();
}

/*
 * genlist item callbacks
 */

static void
_exm_depends_genlist_item_selected(void *data, Evas_Object *obj, void *event_info)
{
    char buf[16];
    Exm_Depends *exm;
    /* Elm_Object_Item *glit; */
    Exm_Tree_Modules_Node *node;
    Evas_Object *o;
    unsigned int i;
    unsigned int col;
    double t1, t2;

    t1 = _exm_time_get();
    exm = evas_object_data_get(obj, "exm");
    /* glit = (Elm_Object_Item *)event_info; */
    node = (Exm_Tree_Modules_Node *)data;
    printf("selection ! %p  %p %s  %s\n",
           (void *)obj, evas_object_data_get(obj, "exm"),
           exm_pe_filename_get(node->file),
           node->list_node->filename);

    elm_table_clear(exm->gui.export_fcts, EINA_TRUE);

    col = 0;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "E");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < node->list_node->exported_fct_count; i++)
    {
        Evas_Object *o;

        o = elm_label_add(exm->gui.win);
        elm_object_text_set(o, "C");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Ordinal");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < node->list_node->exported_fct_count; i++)
    {
        Evas_Object *o;
        WORD ordinal;

        ordinal = node->list_node->exported_fct[i].ordinal;
        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%hu (0x%04hx)", ordinal, ordinal);
        buf[sizeof(buf) - 1] = '\0';
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Function");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < node->list_node->exported_fct_count; i++)
    {
        Evas_Object *o;
        const char *name;

        o = elm_label_add(exm->gui.win);
        name = node->list_node->exported_fct[i].name;
        if (name)
            elm_object_text_set(o, name);
        else
            elm_object_text_set(o, "N/A");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Entry Point");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < node->list_node->exported_fct_count; i++)
    {
        Evas_Object *o;

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "0x%08lx",
                 node->list_node->exported_fct[i].address);
        buf[sizeof(buf) - 1] = '\0';
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }
    t2 = _exm_time_get();
    printf("export fill : %E\n", t2 - t1);
}

/* genlist item text label */
static char *
_exm_depends_genlist_item_text_get(void *data, Evas_Object *obj EINA_UNUSED, const char *part EINA_UNUSED)
{
    Exm_Tree_Modules_Node *node;

    node = (Exm_Tree_Modules_Node *)data;
    printf(" ** tree text : %p %s\n", node, exm_pe_filename_get(node->file));
    return strdup(exm_pe_filename_get(node->file));
}

/* genlist item left icon */
static Evas_Object *
_exm_depends_genlist_item_content_get(void *data EINA_UNUSED, Evas_Object *obj, const char *part)
{
   char buf[PATH_MAX];
   //printf("elm data dir : %s\n", elm_app_data_dir_get());
   if (!strcmp(part, "elm.swallow.icon"))
     {
        Evas_Object *ic = elm_icon_add(obj);
        /* snprintf(buf, sizeof(buf), "/opt/windows_64/share/elementary/images/logo_small.png", elm_app_data_dir_get()); */
        elm_image_file_set(ic, "C:/MinGW/msys/1.0/opt/windows_64/share/elementary/images/logo_small.png", NULL);
        evas_object_size_hint_aspect_set(ic, EVAS_ASPECT_CONTROL_VERTICAL, 1, 1);
        evas_object_show(ic);
        return ic;
     }
   /* else if (!strcmp(part, "elm.swallow.end")) */
   /*   { */
   /*      Evas_Object *ck; */
   /*      ck = elm_check_add(obj); */
   /*      evas_object_propagate_events_set(ck, EINA_FALSE); */
   /*      evas_object_show(ck); */
   /*      return ck; */
   /*   } */
    return NULL;
}

/* genlist item state */
static Eina_Bool
_exm_depends_genlist_item_state_get(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED, const char *part EINA_UNUSED)
{
   return EINA_FALSE;
}

/* genlist item delete */
static void
_exm_depends_genlist_item_del(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED)
{
   printf("item deleted.\n");
}

/*
 * Genlist signal callbacks
 */

/* expand,request signal. event_info == genlist item. */
static void
_exm_depends_genlist_expand_request(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED, void *event_info)
{
   Elm_Object_Item *glit;

   glit = (Elm_Object_Item *)event_info;
   elm_genlist_item_expanded_set(glit, EINA_TRUE);
}

/* contract,request signal. event_info == genlist item. */
static void
_exm_depends_genlist_contract_request(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED, void *event_info)
{
   Elm_Object_Item *glit;

   glit = (Elm_Object_Item *)event_info;
   elm_genlist_item_expanded_set(glit, EINA_FALSE);
}

/* expanded signal. event_info == genlist item. */
static void
_exm_depends_genlist_expanded(void *data, Evas_Object *obj EINA_UNUSED, void *event_info)
{
   Elm_Object_Item *glit;
   Evas_Object *gl = elm_object_item_widget_get(glit);
   Exm_Tree_Modules_Node *node;
   Exm_List *iter;
   Exm_Depends *exm;

   glit = (Elm_Object_Item *)event_info;
   gl = (Evas_Object *)elm_object_item_widget_get(glit);
   node = (Exm_Tree_Modules_Node *)elm_object_item_data_get(glit);
   exm = (Exm_Depends *)data;

   iter = node->child;
   while (iter)
   {
       Elm_Genlist_Item_Type type;
       Exm_Tree_Modules_Node *n;

       n = (Exm_Tree_Modules_Node *)iter->data;
       if (n->child)
           type = ELM_GENLIST_ITEM_TREE;
       else
           type = ELM_GENLIST_ITEM_NONE;

       elm_genlist_item_append(gl, exm->gui.itc,
                               iter->data, glit, type,
                               _exm_depends_genlist_item_selected, n);
       iter = iter->next;
   }
}

/* contracted signal. event_info == genlist item. */
static void
_exm_depends_genlist_contracted(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED, void *event_info)
{
   Elm_Object_Item *glit;

   glit = (Elm_Object_Item *)event_info;
   elm_genlist_item_subitems_clear(glit);
}

/*
 * Functions that fill the GUI with the PE data
 */

static void
_exm_depends_tree_fill(Exm_Depends *exm)
{
    Exm_List *iter;

    iter = exm->pe.tree_modules;
    printf(" ** tree fill : %p %p\n", iter, iter->data);
    while (iter)
    {
        elm_genlist_item_append(exm->gui.dependency_tree, exm->gui.itc,
                                iter->data, NULL, ELM_GENLIST_ITEM_TREE,
                                _exm_depends_genlist_item_selected, iter->data);
        iter = iter->next;
    }
}

static void
_exm_depends_parents_functions_fill(Exm_Depends *exm)
{
    Evas_Object *o;
    int col;

    col = 0;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "P");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.parent_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    col++;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Ordinal");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.parent_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    col++;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Function");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.parent_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    col++;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Entry Point");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.parent_fcts, o, col, 0, 1, 1);
    evas_object_show(o);
}

static void
_exm_depends_export_functions_fill(Exm_Depends *exm)
{
    char buf[16];
    const IMAGE_EXPORT_DIRECTORY *ed;
    Evas_Object *o;
    DWORD i;
    int col;

    double t1, t2;

    /* elm_table_clear(exm->gui.export_fcts); */

    ed = exm_pe_export_directory_get(exm->pe.pe, NULL);

    t1 = _exm_time_get();

    col = 0;

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "E");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < ed->NumberOfNames; i++)
    {
        o = elm_label_add(exm->gui.win);
        elm_object_text_set(o, "C");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Ordinal");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < ed->NumberOfNames; i++)
    {
        DWORD ordinal;

        o = elm_label_add(exm->gui.win);
        if (exm_pe_export_directory_function_ordinal_get(exm->pe.pe, ed, i, &ordinal))
        {
            snprintf(buf, sizeof(buf), "%hu (0x%04hx)", ordinal, ordinal);
            buf[sizeof(buf) - 1] = '\0';
            elm_object_text_set(o, buf);
        }
        else
            elm_object_text_set(o, "N/A");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Function");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < ed->NumberOfNames; i++)
    {
        const char *name;

        o = elm_label_add(exm->gui.win);
        name = exm_pe_export_directory_function_name_get(exm->pe.pe, ed, i);
        if (name)
            elm_object_text_set(o, name);
        else
            elm_object_text_set(o, "N/A");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    col++;

    o = elm_separator_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col++, 0, 1, i + 1);
    evas_object_show(o);

    o = elm_label_add(exm->gui.win);
    elm_object_text_set(o, "Entry Point");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
    elm_table_pack(exm->gui.export_fcts, o, col, 0, 1, 1);
    evas_object_show(o);

    for (i = 0; i < ed->NumberOfNames; i++)
    {
        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "0x%08lx",
                 exm_pe_export_directory_function_address_get(exm->pe.pe, ed, i));
        buf[sizeof(buf) - 1] = '\0';
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.export_fcts, o, col, i + 1, 1, 1);
        evas_object_show(o);
    }

    t2 = _exm_time_get();
    printf("export fill : %E\n", t2 - t1);
}

static void
_exm_depends_modules_fill(Exm_Depends *exm)
{
    Exm_List *iter;
    int list_count;
    int col;
    int i;

    list_count = exm_list_count(exm->pe.list_modules);
    iter = exm->pe.list_modules;
    i = 0;
    while (iter)
    {
        char buf[32];
        Exm_List_Modules_Node *list_node;
        Evas_Object *o;
        struct tm *t;
        int col;

        list_node = (Exm_List_Modules_Node *)iter->data;
        col = 0;

        o = elm_label_add(exm->gui.win);
        if (list_node->is_64bits)
            elm_object_text_set(o, "PE32+");
        else
            elm_object_text_set(o, "PE32");
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        elm_object_text_set(o, list_node->filename);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        t = localtime(&list_node->creation_date);
        snprintf(buf, sizeof(buf), "%02u/%02u/%4u %02u:%02u",
                 t->tm_mday, t->tm_mon, t->tm_year + 1900,
                 t->tm_hour, t->tm_min);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        /* o = elm_label_add(exm->gui.win); */
        /* t = localtime(&list_node->modification_date); */
        /* snprintf(buf, sizeof(buf), "%02u/%02u/%4u %02u:%02u", */
        /*          t->tm_mday, t->tm_mon, t->tm_year + 1900, */
        /*          t->tm_hour, t->tm_min); */
        /* elm_object_text_set(o, buf); */
        /* evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND); */
        /* evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL); */
        /* elm_table_pack(exm->gui.modules, o, col++, i, 1, 1); */
        /* evas_object_show(o); */

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%I64u", list_node->size);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        elm_object_text_set(o, list_node->perm);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "0x%08X", list_node->checksum);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        switch (list_node->cpu)
        {
            case IMAGE_FILE_MACHINE_I386:
                elm_object_text_set(o, "x86");
                break;
            case IMAGE_FILE_MACHINE_R3000:
                elm_object_text_set(o, "MIPS R3000");
                break;
            case IMAGE_FILE_MACHINE_R4000:
                elm_object_text_set(o, "MIPS R4000");
                break;
            case IMAGE_FILE_MACHINE_R10000:
                elm_object_text_set(o, "MIPS R10000");
                break;
            case IMAGE_FILE_MACHINE_WCEMIPSV2:
                elm_object_text_set(o, "MIPS WinCE V2");
                break;
            case IMAGE_FILE_MACHINE_ALPHA:
                elm_object_text_set(o, "Alpha");
                break;
            case IMAGE_FILE_MACHINE_SH3:
                elm_object_text_set(o, "SH3");
                break;
            case IMAGE_FILE_MACHINE_SH3DSP:
                elm_object_text_set(o, "SH3 DSP");
                break;
            case IMAGE_FILE_MACHINE_SH3E:
                elm_object_text_set(o, "SH3E");
                break;
            case IMAGE_FILE_MACHINE_SH4:
                elm_object_text_set(o, "SH4");
                break;
            case IMAGE_FILE_MACHINE_SH5:
                elm_object_text_set(o, "SH5");
                break;
            case IMAGE_FILE_MACHINE_ARM:
                elm_object_text_set(o, "ARM");
                break;
            case IMAGE_FILE_MACHINE_ARMV7:
                elm_object_text_set(o, "ARM v7");
                break;
                /* case IMAGE_FILE_MACHINE_ARMNT: */
                /*     elm_object_text_set(o, "ARM NT"); */
                /*     break; */
            case IMAGE_FILE_MACHINE_THUMB:
                elm_object_text_set(o, "Thumb");
                break;
            case IMAGE_FILE_MACHINE_AM33:
                elm_object_text_set(o, "AM33");
                break;
            case IMAGE_FILE_MACHINE_POWERPC:
                elm_object_text_set(o, "PowerPC");
                break;
            case IMAGE_FILE_MACHINE_POWERPCFP:
                elm_object_text_set(o, "PowerPC FP");
                break;
            case IMAGE_FILE_MACHINE_IA64:
                elm_object_text_set(o, "Itanium 64");
                break;
            case IMAGE_FILE_MACHINE_MIPS16:
                elm_object_text_set(o, "MIPS 16");
                break;
            case IMAGE_FILE_MACHINE_ALPHA64:
                elm_object_text_set(o, "Alpha 64");
                break;
            case IMAGE_FILE_MACHINE_MIPSFPU:
                elm_object_text_set(o, "MIPS FPU");
                break;
            case IMAGE_FILE_MACHINE_MIPSFPU16:
                elm_object_text_set(o, "MIPS FPU 16");
                break;
                /* case IMAGE_FILE_MACHINE_AXP64: */
                /*     elm_object_text_set(o, "Alpha 64"); */
                /*     break; */
            case IMAGE_FILE_MACHINE_TRICORE:
                elm_object_text_set(o, "Tricore");
                break;
            case IMAGE_FILE_MACHINE_CEF:
                elm_object_text_set(o, "CEF");
                break;
            case IMAGE_FILE_MACHINE_EBC:
                elm_object_text_set(o, "EBC");
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                elm_object_text_set(o, "X86-64");
                break;
            case IMAGE_FILE_MACHINE_M32R:
                elm_object_text_set(o, "M32R");
                break;
            case IMAGE_FILE_MACHINE_CEE:
                elm_object_text_set(o, "CEE");
                break;
            case IMAGE_FILE_MACHINE_UNKNOWN:
            default:
                elm_object_text_set(o, "Unknown");
                break;
        }
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        switch (list_node->subsystem)
        {
            case IMAGE_SUBSYSTEM_NATIVE:
                elm_object_text_set(o, "Native");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                elm_object_text_set(o, "Windows GUI");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                elm_object_text_set(o, "Windows Console");
                break;
            case IMAGE_SUBSYSTEM_OS2_CUI:
                elm_object_text_set(o, "OS/2 Console");
                break;
            case IMAGE_SUBSYSTEM_POSIX_CUI:
                elm_object_text_set(o, "POSIX Console");
                break;
            case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
                elm_object_text_set(o, "Win9x Driver");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
                elm_object_text_set(o, "WinCE GUI");
                break;
            case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                elm_object_text_set(o, "EFI");
                break;
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                elm_object_text_set(o, "EFI Boot Driver");
                break;
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                elm_object_text_set(o, "EFI Runtime Driver");
                break;
            case IMAGE_SUBSYSTEM_EFI_ROM:
                elm_object_text_set(o, "EFI ROM");
                break;
            case IMAGE_SUBSYSTEM_XBOX:
                elm_object_text_set(o, "Xbox");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                elm_object_text_set(o, "Boot Application");
                break;
            case IMAGE_SUBSYSTEM_UNKNOWN:
            default:
                elm_object_text_set(o, "Unknown");
                break;
        }
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 0.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        if (list_node->is_64bits)
            snprintf(buf, sizeof(buf), "0x%016I64X", list_node->preferred_base);
        else
            snprintf(buf, sizeof(buf), "0x--------%08X", (unsigned int)(list_node->preferred_base));
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%u.%u", list_node->version_image.major, list_node->version_image.minor);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%u.%u", list_node->version_linker.major, list_node->version_linker.minor);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%u.%u", list_node->version_os.major, list_node->version_os.minor);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);

        o = elm_separator_add(exm->gui.win);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, 0, 1, list_count);
        evas_object_show(o);

        o = elm_label_add(exm->gui.win);
        snprintf(buf, sizeof(buf), "%u.%u", list_node->version_subsystem.major, list_node->version_subsystem.minor);
        elm_object_text_set(o, buf);
        evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
        evas_object_size_hint_align_set(o, 1.0, EVAS_HINT_FILL);
        elm_table_pack(exm->gui.modules, o, col++, i, 1, 1);
        evas_object_show(o);
        evas_object_show(o);

        iter = iter->next;
        i++;
    }
}

static void
_exm_depends_usage(void)
{
    printf("Usage:\n");
    printf("  examine_depends [options] file\n");
    printf("\n");
    printf("  user options for Examine depends tools:\n");
    printf("\n");
    printf("    -h, --help                 show this message\n");
    printf("    -V, --version              show version\n");
    printf("\n");
    printf("  file must be given with absolute path.\n");
    printf("\n");
    printf("  Examine is Copyright (C) 2012-2015, and GNU LGPL3'd, by Vincent Torri.\n");
    printf("\n");
    printf("  Bug reports, feedback, remarks, ... to https://github.com/vtorri/examine.\n");
    printf("\n");
}

EAPI_MAIN int
elm_main(int argc, char **argv)
{
    Exm_Depends *exm;
    Exm_List *iter_list;
    char *module;
    Exm_Log_Level log_level;
    int argv_idx = -1;
    int i;
    Evas_Object *o;
    Evas_Object *bg;
    Evas_Object *panes_h_1;
    Evas_Object *panes_h_2;
    Evas_Object *panes_h_3;
    Evas_Object *panes_v_1;
    Evas_Object *sc;
    Elm_Object_Item *it;
    double t1, t2;

    if (argc < 2)
    {
        _exm_depends_usage();
        return -1;
    }

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            _exm_depends_usage();
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

    if (!exm_map_shared_read("exm_depends_gui_shared",
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

    exm = (Exm_Depends *)calloc(1, sizeof(Exm_Depends));
    if (!exm)
    {
        EXM_LOG_ERR("memory allocation error");
        return -1;
    }

    t1 = _exm_time_get();
    exm->pe.pe = exm_pe_new(module);
    t2 = _exm_time_get();
    printf("pe new : %E\n", t2 - t1);
    if (!exm->pe.pe)
    {
        EXM_LOG_ERR("%s is not a binary nor a DLL.", module);
        free(module);
        free(exm);
        return -1;
    }

    free(module);

    t1 = _exm_time_get();
    _exm_depends_tree_modules_get(exm->pe.pe, &exm->pe.tree_modules, &exm->pe.list_modules);
    t2 = _exm_time_get();
    printf("get tree data : %E\n", t2 - t1);

    elm_policy_set(ELM_POLICY_QUIT, ELM_POLICY_QUIT_LAST_WINDOW_CLOSED);

    o = elm_win_add(NULL, "Examine Depends GUI", ELM_WIN_BASIC);
    elm_win_title_set(o, "Examine Depends");
    evas_object_smart_callback_add(o, "delete,request",
                                   _exm_depends_delete_cb, NULL);
    exm->gui.win = o;

    o = elm_bg_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    elm_win_resize_object_add(exm->gui.win, o);
    evas_object_show(o);
    bg = o;

    o = elm_panes_add(exm->gui.win);
    elm_panes_horizontal_set(o, EINA_TRUE);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    elm_win_resize_object_add(exm->gui.win, o);
    evas_object_show(o);
    panes_h_1 = o;

    o = elm_panes_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_1, "top", o);
    panes_v_1 = o;

    o = elm_genlist_add(exm->gui.win);
    elm_genlist_tree_effect_enabled_set(o, EINA_TRUE);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    evas_object_data_set(o, "exm", exm);
    elm_object_part_content_set(panes_v_1, "left", o);
    exm->gui.dependency_tree = o;
    printf(" ** genlist : %p  exm : %p\n", (void *)o, (void *)exm);

    exm->gui.itc = elm_genlist_item_class_new();
    exm->gui.itc->item_style = "tree_effect";
    exm->gui.itc->func.text_get = _exm_depends_genlist_item_text_get;
    exm->gui.itc->func.content_get = _exm_depends_genlist_item_content_get;
    exm->gui.itc->func.state_get = _exm_depends_genlist_item_state_get;
    exm->gui.itc->func.del = _exm_depends_genlist_item_del;

    evas_object_smart_callback_add(exm->gui.dependency_tree, "expand,request",
                                   _exm_depends_genlist_expand_request, exm);
    evas_object_smart_callback_add(exm->gui.dependency_tree, "contract,request",
                                   _exm_depends_genlist_contract_request, exm);
    evas_object_smart_callback_add(exm->gui.dependency_tree, "expanded",
                                   _exm_depends_genlist_expanded, exm);
    evas_object_smart_callback_add(exm->gui.dependency_tree, "contracted",
                                   _exm_depends_genlist_contracted, exm);

    o = elm_panes_add(exm->gui.win);
    elm_panes_horizontal_set(o, EINA_TRUE);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_v_1, "right", o);
    panes_h_2 = o;

    o = elm_scroller_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, 0.0);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_2, "top", o);
    sc = o;

    o = elm_table_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, 0.0);
    evas_object_show(o);
    elm_object_content_set(sc, o);
    exm->gui.parent_fcts = o;

    o = elm_scroller_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_2, "bottom", o);
    sc = o;

    o = elm_table_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_content_set(sc, o);
    exm->gui.export_fcts = o;

    o = elm_panes_add(exm->gui.win);
    elm_panes_horizontal_set(o, EINA_TRUE);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_1, "bottom", o);
    panes_h_3 = o;

    o = elm_scroller_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_3, "top", o);
    sc = o;

    o = elm_table_add(exm->gui.win);
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_content_set(sc, o);
    exm->gui.modules = o;

    o = elm_button_add(exm->gui.win);
    elm_object_text_set(o, "log messages");
    evas_object_size_hint_weight_set(o, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
    evas_object_size_hint_align_set(o, EVAS_HINT_FILL, EVAS_HINT_FILL);
    evas_object_show(o);
    elm_object_part_content_set(panes_h_3, "bottom", o);
    exm->gui.logs = o;

    /* we fill the modules tree */
    t1 = _exm_time_get();
    _exm_depends_tree_fill(exm);
    t2 = _exm_time_get();
    printf("tree fill : %E\n", t2 - t1);

    /* we fill the modules list */
    t1 = _exm_time_get();
    _exm_depends_modules_fill(exm);
    t2 = _exm_time_get();
    printf("modules fill : %E\n", t2 - t1);

    t1 = _exm_time_get();
    _exm_depends_parents_functions_fill(exm);
    t2 = _exm_time_get();
    printf("parent fill : %E\n", t2 - t1);

    /* t1 = _exm_time_get(); */
    /* _exm_depends_export_functions_fill(exm); */
    /* t2 = _exm_time_get(); */
    /* printf("export fill : %E\n", t2 - t1); */

    evas_object_resize(exm->gui.win, 1024, 512);
    evas_object_show(exm->gui.win);

    it = elm_genlist_first_item_get(exm->gui.dependency_tree);
    printf(" ** first obj item %p\n", it);
    elm_genlist_item_selected_set(it, EINA_TRUE);

    elm_run();

    exm_list_free(exm->pe.list_modules, _exm_depends_list_modules_node_free);

    exm_shutdown();

    return 0;
}
ELM_MAIN()
