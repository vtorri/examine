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
#include <mbstring.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <imagehlp.h>

#include <Examine.h>

#include "examine_memcheck_hook.h"


/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

typedef enum
{
    EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC,
    EXM_HOOK_ERROR_MULTIPLE_FREES,
    EXM_HOOK_ERROR_MISMATCHED_FREE,
    EXM_HOOK_ERROR_MEMORY_OVERLAP
} Exm_Hook_Error;

typedef struct _Exm_Hook Exm_Hook;

struct _Exm_Hook
{
    Exm_Hook_Fct fct;
    FARPROC fct_proc_old;
    FARPROC fct_proc_new;
};

static Exm_Hook _exm_hook_instance[EXM_HOOK_FCT_COUNT];

struct _Exm_Hook_Error_Data
{
    Exm_Hook_Error error_type;
    union
    {
        struct
        {
            Exm_List *stack;
        } free_without_alloc;
        struct
        {
            Exm_List *stack_free;
            Exm_List *stack_alloc;
            Exm_List *stack_first_free;
            void *address_alloc;
            size_t size_alloc;
        } multiple_frees;
        struct
        {
            Exm_List *stack_free;
            Exm_List *stack_alloc;
            void *address_alloc;
            size_t size_alloc;
        } mismatched_free;
        struct
        {
            void *dst;
            const void *src;
            size_t dst_len;
            size_t src_len;
            Exm_List *stack;
            Exm_Hook_Fct fct;
        } memory_overlap;

    } error;
};

/*
 * Overlapping:
 *
 * src:  XXXXXXXXX
 *       \___  __/
 *           \/
 * dst:       XXXXXXXXXX
 *
 * or
 *
 * src:       XXXXXXXXX
 *        ___/\___
 *       /	      \
 * dst:  XXXXXXXXXX
 */
static inline unsigned char
_exm_hook_memory_overlap(void *dst, const void *src, size_t dst_len, size_t src_len)
{
    if ((src_len == 0) || (dst_len == 0))
        return 0;

    if (((src <= dst) && (dst <= (void *)((unsigned char *)src + (src_len - 1)))) ||
        ((dst <= src) && (src <= (void *)((unsigned char *)dst + (dst_len - 1)))))
        return 1;

    return 0;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_free_without_alloc_new(Exm_List *stack)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC;
    data->error.free_without_alloc.stack = stack;

    return data;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_multiple_frees_new(Exm_List *stack_free, Exm_Hook_Data_Alloc *da)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_MULTIPLE_FREES;
    data->error.multiple_frees.stack_free = stack_free;
    data->error.multiple_frees.stack_alloc = da->stack;
    data->error.multiple_frees.stack_first_free = da->stack_first_free;
    data->error.multiple_frees.address_alloc = da->data;
    data->error.multiple_frees.size_alloc = da->size;

    return data;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_mismatched_free_new(Exm_List *stack_free, Exm_Hook_Data_Alloc *da)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_MISMATCHED_FREE;
    data->error.mismatched_free.stack_free = stack_free;
    data->error.mismatched_free.stack_alloc = da->stack;
    data->error.mismatched_free.address_alloc = da->data;
    data->error.mismatched_free.size_alloc = da->size;

    return data;
}

static Exm_Hook_Error_Data*
_exm_hook_error_data_memory_overlap_new(Exm_List *stack, void *dst, const void *src, size_t dst_len, size_t src_len, Exm_Hook_Fct fct)
{
    Exm_Hook_Error_Data *data;

    data = (Exm_Hook_Error_Data *)calloc(1, sizeof(Exm_Hook_Error_Data));
    if (!data)
        return NULL;

    data->error_type = EXM_HOOK_ERROR_MEMORY_OVERLAP;
    data->error.memory_overlap.dst = dst;
    data->error.memory_overlap.src = src;
    data->error.memory_overlap.dst_len = dst_len;
    data->error.memory_overlap.src_len = src_len;
    data->error.memory_overlap.stack = stack;
    data->error.memory_overlap.fct = fct;

    return data;
}

static void
_exm_hook_error_data_del(void *ptr)
{
    Exm_Hook_Error_Data *data;

    if (!ptr)
        return;

    data = (Exm_Hook_Error_Data *)ptr;
    switch(data->error_type)
    {
        case EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC:
            exm_list_free(data->error.free_without_alloc.stack, exm_stack_data_free);
            break;
        case EXM_HOOK_ERROR_MULTIPLE_FREES:
            exm_list_free(data->error.multiple_frees.stack_free, exm_stack_data_free);
            break;
        case EXM_HOOK_ERROR_MISMATCHED_FREE:
            exm_list_free(data->error.mismatched_free.stack_free, exm_stack_data_free);
            break;
        case EXM_HOOK_ERROR_MEMORY_OVERLAP:
            exm_list_free(data->error.memory_overlap.stack, exm_stack_data_free);
            break;
        default:
            break;
    }
}

static Exm_Hook_Data_Alloc *
_exm_hook_data_alloc_new(Exm_Hook_Fct fct, size_t size, void *data, unsigned char is_gdi, Exm_List *stack)
{
    Exm_Hook_Data_Alloc *da;

    if (!stack)
        return NULL;

    da = (Exm_Hook_Data_Alloc *)calloc(1, sizeof(Exm_Hook_Data_Alloc));
    if (!da)
      return NULL;

    da->fct = fct;
    da->size = size;
    da->data = data;
    da->nbr_frees = 0;
    da->stack = stack;
    da->stack_first_free = NULL;
    da->gdi32 = !!is_gdi;

    return da;
}

static void
_exm_hook_data_alloc_del(void *ptr)
{
    Exm_Hook_Data_Alloc *da = ptr;

    if (!da)
        return;

    exm_list_free(da->stack_first_free, exm_stack_data_free);
    exm_list_free(da->stack, exm_stack_data_free);
    free(da);
}

static void
_exm_hook_allocations_sanitize(void *data)
{
    Exm_List *iter;

    iter = exm_hook_allocations;
    while (iter)
    {
        Exm_Hook_Data_Alloc *d;

        d = (Exm_Hook_Data_Alloc *)iter->data;
        if (data == d->data)
        {
            if (d->nbr_frees == 0)
            {
                /* we should never go there */
                EXM_LOG_ERR("CRITICAL ERROR: The OS allocated memory twice on the same address (0x%p)",
                            data);
            }

            exm_hook_allocations = exm_list_remove(exm_hook_allocations, data, _exm_hook_data_alloc_del);
        }

        iter = iter->next;
    }
}

typedef unsigned char (*Exm_Hook_Alloc_Free_Mismatch)(Exm_Hook_Fct fct);

static unsigned char
_exm_hook_rtlallocateheap_rtlfreeheap_mismatch(Exm_Hook_Fct fct)
{

    return (fct != EXM_HOOK_FCT_RTLALLOCATEHEAP);
}

static unsigned char
_exm_hook_heapalloc_heapfree_mismatch(Exm_Hook_Fct fct)
{

    return ((fct != EXM_HOOK_FCT_HEAPALLOC) &&
            (fct != EXM_HOOK_FCT_HEAPREALLOC));
}

static unsigned char
_exm_hook_globalalloc_globalfree_mismatch(Exm_Hook_Fct fct)
{

    return ((fct != EXM_HOOK_FCT_GLOBALALLOC) &&
            (fct != EXM_HOOK_FCT_GLOBALREALLOC));
}

static unsigned char
_exm_hook_localalloc_localfree_mismatch(Exm_Hook_Fct fct)
{

    return ((fct != EXM_HOOK_FCT_LOCALALLOC) &&
            (fct != EXM_HOOK_FCT_LOCALREALLOC));
}

static unsigned char
_exm_hook_malloc_free_mismatch(Exm_Hook_Fct fct)
{

    return ((fct != EXM_HOOK_FCT_MALLOC) &&
            (fct != EXM_HOOK_FCT__STRDUP) &&
            (fct != EXM_HOOK_FCT_CALLOC) &&
            (fct != EXM_HOOK_FCT_REALLOC));
}

static unsigned char
_exm_hook_gdi_objects_mismatch(Exm_Hook_Fct fct)
{

    return ((fct != EXM_HOOK_FCT_CREATEBITMAP) &&
            (fct != EXM_HOOK_FCT_CREATEBITMAPINDIRECT) &&
            (fct != EXM_HOOK_FCT_CREATECOMPATIBLEBITMAP) &&
            (fct != EXM_HOOK_FCT_CREATEDIBITMAP) &&
            (fct != EXM_HOOK_FCT_CREATEDIBSECTION));
}

static void
_exm_hook_alloc_manage(void *data, size_t size, unsigned char gdi32, Exm_Hook_Fct fct)
{
    Exm_Hook_Data_Alloc *da;

    _exm_hook_allocations_sanitize(data);

    da = _exm_hook_data_alloc_new(fct, size, data, gdi32, exm_stack_frames_get());
    if (da)
    {
        exm_hook_allocations = exm_list_append(exm_hook_allocations, da);
    }

    if (gdi32)
    {
        exm_hook_summary.total_count_gdi_handles++;
    }
    else
    {
        exm_hook_summary.total_count_allocs++;
        exm_hook_summary.total_bytes_allocated += size;
    }
}

static unsigned char
_exm_hook_free_errors_manage(void *memblock, Exm_Hook_Alloc_Free_Mismatch mismatch_cb)
{
    Exm_Hook_Error_Data *err_data = NULL;
    Exm_List *iter_alloc;
    unsigned char alloc_not_found = 1;
    unsigned char no_free_error = 1;

    iter_alloc = exm_hook_allocations;
    while (iter_alloc)
    {
        Exm_Hook_Data_Alloc *da;

        da = (Exm_Hook_Data_Alloc *)iter_alloc->data;
        if (da->data == memblock)
        {
            alloc_not_found = 0;
            da->nbr_frees++;

            /* multiple frees */
            if (da->nbr_frees > 1)
            {
                err_data = _exm_hook_error_data_multiple_frees_new(exm_stack_frames_get(),
                                                                   da);
                exm_hook_error_disp(err_data);
                exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
                no_free_error = 0;
            }
            else
                da->stack_first_free = exm_stack_frames_get();

            /* mismatched alloc / free */
            if (mismatch_cb(da->fct))
            {
                err_data = _exm_hook_error_data_mismatched_free_new(exm_stack_frames_get(),
                                                                    da);
                exm_hook_error_disp(err_data);
                exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
            }

            break;
        }
        iter_alloc = iter_alloc->next;
    }

    if (alloc_not_found)
    {
        err_data = _exm_hook_error_data_free_without_alloc_new(exm_stack_frames_get());
        exm_hook_error_disp(err_data);
        exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
        no_free_error = 0;
    }

    exm_hook_summary.total_count_frees++;

    return no_free_error;
}

static void
_exm_hook_realloc_manage(void *old_data, void *new_data, size_t new_size, Exm_Hook_Alloc_Free_Mismatch mismatch_cb)
{
    Exm_List *iter_alloc;
    Exm_Hook_Data_Alloc *old_da = NULL;

    /* Search for previous allocated memory */
    iter_alloc = exm_hook_allocations;
    while (iter_alloc)
    {
        Exm_Hook_Data_Alloc *da;
        da = (Exm_Hook_Data_Alloc *)iter_alloc->data;
        if (da->data == old_data)
        {
            Exm_Hook_Error_Data *err_data = NULL;

            /* mismatched alloc / free */
            if (mismatch_cb(da->fct))
            {
                err_data = _exm_hook_error_data_mismatched_free_new(exm_stack_frames_get(),
                                                                    da);
                exm_hook_error_disp(err_data);
                exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
            }

            old_da = da;
            break;
        }
        iter_alloc = iter_alloc->next;
    }

    if (!old_da)
    {
        /* FIXME: add error ? */
        EXM_LOG_WARN("Memory allocation not found when realloc() is called.");
        return;
    }

    if (new_data != old_data)
    {
        /* there is a alloc + free */
        exm_hook_summary.total_count_allocs++;
        exm_hook_summary.total_count_frees++;
    }

    /* update memory */
    exm_hook_summary.total_bytes_allocated += (new_size - old_da->size);
    old_da->size = new_size;
}

/*
 * Hooking functions
 */

static PVOID
_exm_hook_RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T size)
{
    typedef PVOID (*exm_rtl_allocate_heap_t)(PVOID HeapHandle,
                                      ULONG Flags,
                                      SIZE_T size);
    exm_rtl_allocate_heap_t ah;
    PVOID data;

    EXM_LOG_WARN("RtlAllocateHeap !!!");

    ah = (exm_rtl_allocate_heap_t)_exm_hook_instance[EXM_HOOK_FCT_RTLALLOCATEHEAP].fct_proc_old;
    data = ah(HeapHandle, Flags, size);

    _exm_hook_alloc_manage(data, size, 0, EXM_HOOK_FCT_RTLALLOCATEHEAP);

    return data;
}

static BOOLEAN
_exm_hook_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
{
    typedef BOOL (*exm_rtl_free_heap_t)(PVOID HeapHandle,
                                        ULONG Flags,
                                        PVOID HeapBase);
    exm_rtl_free_heap_t fh;
    BOOLEAN res = FALSE;

    EXM_LOG_WARN("RtlFreeHeap !!!");

    if (_exm_hook_free_errors_manage(HeapHandle,
                                     _exm_hook_rtlallocateheap_rtlfreeheap_mismatch))
    {
        fh = (exm_rtl_free_heap_t)_exm_hook_instance[EXM_HOOK_FCT_RTLFREEHEAP].fct_proc_old;
        res = fh(HeapHandle, Flags, HeapBase);
    }

    return res;
}

static LPVOID WINAPI
_exm_hook_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    typedef LPVOID (WINAPI *exm_heap_alloc_t)(HANDLE hHeap,
                                              DWORD dwFlags,
                                              SIZE_T dwBytes);
    exm_heap_alloc_t ha;
    LPVOID data;

    EXM_LOG_WARN("HeapAlloc !!!");

    ha = (exm_heap_alloc_t)_exm_hook_instance[EXM_HOOK_FCT_HEAPALLOC].fct_proc_old;
    data = ha(hHeap, dwFlags, dwBytes);

    _exm_hook_alloc_manage(data, dwBytes, 0, EXM_HOOK_FCT_HEAPALLOC);

    return data;
}

static void *
_exm_hook_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    typedef LPVOID (WINAPI *exm_heap_realloc_t)(HANDLE hHeap,
                                                DWORD dwFlags,
                                                LPVOID lpMem,
                                                SIZE_T dwBytes);
    exm_heap_realloc_t rea;
    LPVOID data;

    EXM_LOG_WARN("HeapReAlloc !!!");

    rea = (exm_heap_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_HEAPREALLOC].fct_proc_old;
    data = rea(hHeap, dwFlags, lpMem, dwBytes);

    /* if data is NULL, nothing is done */
    if (data)
        _exm_hook_realloc_manage(lpMem, data, dwBytes,
                                 _exm_hook_heapalloc_heapfree_mismatch);

    return data;
}

static BOOL WINAPI
_exm_hook_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    typedef BOOL (WINAPI *exm_heap_free_t)(HANDLE hHeap,
                                           DWORD dwFlags,
                                           LPVOID lpMem);
    exm_heap_free_t hf;
    BOOL res = FALSE;

    EXM_LOG_WARN("HeapFree !!!");

    if (_exm_hook_free_errors_manage(lpMem,
                                     _exm_hook_heapalloc_heapfree_mismatch))
    {
        hf = (exm_heap_free_t)_exm_hook_instance[EXM_HOOK_FCT_HEAPFREE].fct_proc_old;
        res = hf(hHeap, dwFlags, lpMem);
    }

    return res;
}

static HGLOBAL WINAPI
_exm_hook_GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    typedef HGLOBAL (WINAPI *exm_global_alloc_t)(UINT uFlags,
                                                 SIZE_T dwBytes);
    exm_global_alloc_t ga;
    LPVOID data;

    EXM_LOG_WARN("GlobalAlloc !!!");

    ga = (exm_global_alloc_t)_exm_hook_instance[EXM_HOOK_FCT_GLOBALALLOC].fct_proc_old;
    data = ga(uFlags, dwBytes);

    _exm_hook_alloc_manage(data, dwBytes, 0, EXM_HOOK_FCT_GLOBALALLOC);

    return data;
}

static HGLOBAL WINAPI
_exm_hook_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    typedef HGLOBAL (WINAPI *exm_global_realloc_t)(HGLOBAL hMem,
                                                   SIZE_T dwBytes,
                                                   UINT uFlags);
    exm_global_realloc_t grea;
    LPVOID data;

    EXM_LOG_WARN("GlobalReAlloc !!!");

    grea = (exm_global_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_GLOBALREALLOC].fct_proc_old;
    data = grea(hMem, dwBytes, uFlags);

    /* if data is NULL, nothing is done */
    if (data)
        _exm_hook_realloc_manage(hMem, data, dwBytes,
                                 _exm_hook_globalalloc_globalfree_mismatch);

    return data;
}

static HGLOBAL WINAPI
_exm_hook_GlobalFree(HGLOBAL hMem)
{
    typedef HGLOBAL (WINAPI *exm_global_free_t)(HGLOBAL hMem);
    exm_global_free_t gf;
    HGLOBAL res = FALSE;

    EXM_LOG_WARN("GlobalFree !!!");

    if (_exm_hook_free_errors_manage(hMem,
                                     _exm_hook_globalalloc_globalfree_mismatch))
    {
        gf = (exm_global_free_t)_exm_hook_instance[EXM_HOOK_FCT_GLOBALFREE].fct_proc_old;
        res = gf(hMem);
    }

    return res;
}

static HLOCAL WINAPI
_exm_hook_LocalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    typedef HLOCAL (WINAPI *exm_local_alloc_t)(UINT uFlags,
                                               SIZE_T dwBytes);
    exm_local_alloc_t la;
    LPVOID data;

    EXM_LOG_WARN("LocalAlloc !!!");

    la = (exm_local_alloc_t)_exm_hook_instance[EXM_HOOK_FCT_LOCALALLOC].fct_proc_old;
    data = la(uFlags, dwBytes);

    _exm_hook_alloc_manage(data, dwBytes, 0, EXM_HOOK_FCT_LOCALALLOC);

    return data;
}

static HLOCAL WINAPI
_exm_hook_LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags)
{
    typedef HLOCAL (WINAPI *exm_local_realloc_t)(HLOCAL hMem,
                                                 SIZE_T uBytes,
                                                 UINT uFlags);
    exm_local_realloc_t lrea;
    LPVOID data;

    EXM_LOG_WARN("LocalReAlloc !!!");

    lrea = (exm_local_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_LOCALREALLOC].fct_proc_old;
    data = lrea(hMem, uBytes, uFlags);

    /* if data is NULL, nothing is done */
    if (data)
        _exm_hook_realloc_manage(hMem, data, uBytes,
                                 _exm_hook_localalloc_localfree_mismatch);

    return data;
}

static HLOCAL WINAPI
_exm_hook_LocalFree(HLOCAL hMem)
{
    typedef HLOCAL (WINAPI *exm_local_free_t)(HLOCAL hMem);
    exm_local_free_t lf;
    HLOCAL res = FALSE;

    EXM_LOG_WARN("LocalFree !!!");

    if (_exm_hook_free_errors_manage(hMem,
                                     _exm_hook_localalloc_localfree_mismatch))
    {
        lf = (exm_local_free_t)_exm_hook_instance[EXM_HOOK_FCT_LOCALFREE].fct_proc_old;
        res = lf(hMem);
    }

    return res;
}

static HBITMAP
_exm_hook_CreateBitmap(int nWidth, int nHeight, UINT cPlanes, UINT cBitsPerPel, const VOID *lpvBits)
{
    typedef HBITMAP(*exm_create_bitmap_t)(int  nWidth, int  nHeight, UINT cPlanes, UINT cBitsPerPel, const VOID *lpvBits);
    exm_create_bitmap_t cb;
    HBITMAP bm;

    EXM_LOG_WARN("CreateBitmap !!!");

    cb = (exm_create_bitmap_t)_exm_hook_instance[EXM_HOOK_FCT_CREATEBITMAP].fct_proc_old;
    bm = cb(nWidth, nHeight, cPlanes, cBitsPerPel, lpvBits);

    /* if data is NULL, nothing is done */
    if (bm)
        _exm_hook_alloc_manage(bm, 0, 1, EXM_HOOK_FCT_CREATEBITMAP);

    return bm;
}

static HBITMAP
_exm_hook_CreateBitmapIndirect(const BITMAP *lpbm)
{
    typedef HBITMAP(*exm_create_bitmap_indirect_t)(const BITMAP *lpbm);
    exm_create_bitmap_indirect_t cbi;
    HBITMAP bm;

    EXM_LOG_WARN("CreateBitmapIndirect !!!");

    cbi = (exm_create_bitmap_indirect_t)_exm_hook_instance[EXM_HOOK_FCT_CREATEBITMAPINDIRECT].fct_proc_old;
    bm = cbi(lpbm);

    /* if data is NULL, nothing is done */
    if (bm)
        _exm_hook_alloc_manage(bm, 0, 1, EXM_HOOK_FCT_CREATEBITMAPINDIRECT);

    return bm;
}

static HBITMAP
_exm_hook_CreateCompatibleBitmap(HDC hdc, int nWidth, int nHeight)
{
    typedef HBITMAP(*exm_create_compatible_bitmap_t)(HDC hdc, int  nWidth, int  nHeight);
    exm_create_compatible_bitmap_t ccb;
    HBITMAP bm;

    EXM_LOG_WARN("CreateCompaticleBitmap !!!");

    ccb = (exm_create_compatible_bitmap_t)_exm_hook_instance[EXM_HOOK_FCT_CREATECOMPATIBLEBITMAP].fct_proc_old;
    bm = ccb(hdc, nWidth, nHeight);

    /* if data is NULL, nothing is done */
    if (bm)
        _exm_hook_alloc_manage(bm, 0, 1, EXM_HOOK_FCT_CREATECOMPATIBLEBITMAP);

    return bm;
}

static HBITMAP
_exm_hook_CreateDIBitmap(HDC hdc, const BITMAPINFOHEADER *lpbmih, DWORD fdwInit, const VOID *lpbInit, const BITMAPINFO *lpbmi, UINT fuUsage)
{
    typedef HBITMAP(*exm_create_di_bitmap_t)(HDC hdc, const BITMAPINFOHEADER *lpbmih, DWORD fdwInit, const VOID *lpbInit, const BITMAPINFO *lpbmi, UINT fuUsage);
    exm_create_di_bitmap_t cdb;
    HBITMAP bm;

    EXM_LOG_WARN("CreateDIBitmap !!!");

    cdb = (exm_create_di_bitmap_t)_exm_hook_instance[EXM_HOOK_FCT_CREATEDIBITMAP].fct_proc_old;
    bm = cdb(hdc, lpbmih, fdwInit, lpbInit, lpbmi, fuUsage);

    /* if data is NULL, nothing is done */
    if (bm)
        _exm_hook_alloc_manage(bm, 0, 1, EXM_HOOK_FCT_CREATEDIBITMAP);

    return bm;
}

static HBITMAP
_exm_hook_CreateDIBSection(HDC hdc, const BITMAPINFO *lpbmi, UINT iuUsage, VOID **ppvBits, HANDLE hSection, DWORD dwOffset)
{
    typedef HBITMAP(*exm_create_dib_secion_t)(HDC hdc, const BITMAPINFO *lpbmi, UINT iuUsage, VOID **ppvBits, HANDLE hSection, DWORD dwOffset);
    exm_create_dib_secion_t cds;
    HBITMAP bm;

    EXM_LOG_WARN("CreateDIBSection !!!");

    cds = (exm_create_dib_secion_t)_exm_hook_instance[EXM_HOOK_FCT_CREATEDIBSECTION].fct_proc_old;
    bm = cds(hdc, lpbmi, iuUsage, ppvBits, hSection, dwOffset);

    /* if data is NULL, nothing is done */
    if (bm)
        _exm_hook_alloc_manage(bm, 0, 1, EXM_HOOK_FCT_CREATEDIBSECTION);

    return bm;
}

static BOOL
_exm_hook_DeleteObject(HGDIOBJ hObject)
{
    typedef BOOL (*exm_delete_object_t)(HGDIOBJ hObject);
    exm_delete_object_t delobj;
    BOOL res = FALSE;

    EXM_LOG_WARN("DeleteObject !!!");

    if (_exm_hook_free_errors_manage(hObject,
                                     _exm_hook_gdi_objects_mismatch))
    {
        delobj = (exm_delete_object_t)_exm_hook_instance[EXM_HOOK_FCT_DELETEOBJECT].fct_proc_old;
        res = delobj(hObject);
    }

    return res;
}

static void *
_exm_hook_malloc(size_t size)
{
    typedef void *(*exm_malloc_t)(size_t size);
    exm_malloc_t ma;
    void *data;

    EXM_LOG_WARN("malloc !!!");

    ma = (exm_malloc_t)_exm_hook_instance[EXM_HOOK_FCT_MALLOC].fct_proc_old;
    data = ma(size);

    _exm_hook_alloc_manage(data, size, 0, EXM_HOOK_FCT_MALLOC);

    return data;
}

static void *
_exm_hook__aligned_malloc(size_t size, size_t alignment)
{
    typedef void *(*exm__aligned_malloc_t)(size_t size, size_t alignment);
    exm__aligned_malloc_t ama;
    void *data;

    EXM_LOG_WARN("malloc !!!");

    ama = (exm__aligned_malloc_t)_exm_hook_instance[EXM_HOOK_FCT__ALIGNED_MALLOC].fct_proc_old;
    data = ama(size, alignment);

    _exm_hook_alloc_manage(data, size, 0, EXM_HOOK_FCT__ALIGNED_MALLOC);

    return data;
}

static char *
_exm_hook__strdup(const char *strSource)
{
    typedef char *(*exm__strdup_t)(const char *strSource);
    exm__strdup_t sdup;
    char *data;

    EXM_LOG_WARN("_strdup !!!");

    sdup = (exm__strdup_t)_exm_hook_instance[EXM_HOOK_FCT__STRDUP].fct_proc_old;
    data = sdup(strSource);

    _exm_hook_alloc_manage(data, _msize(data), 0, EXM_HOOK_FCT__STRDUP);

    return data;
}

static void *
_exm_hook_calloc(size_t num, size_t size)
{
    typedef void *(*exm_calloc_t)(size_t nmemb, size_t size);
    exm_calloc_t ca;
    void *data;

    EXM_LOG_WARN("calloc !!!");

    ca = (exm_calloc_t)_exm_hook_instance[EXM_HOOK_FCT_CALLOC].fct_proc_old;
    data = ca(num, size);

    _exm_hook_alloc_manage(data, num * size, 0, EXM_HOOK_FCT_CALLOC);

    return data;
}

static void *
_exm_hook_realloc(void *memblock, size_t size)
{
    typedef void *(*exm_realloc_t)(void *memblock, size_t size);
    exm_realloc_t rea;
    void *data = NULL;

    EXM_LOG_WARN("realloc !!!");

    if (memblock == NULL)
    {
        /* malloc() is actually called */

        rea = (exm_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_REALLOC].fct_proc_old;
        data = rea(memblock, size);

        _exm_hook_alloc_manage(data, size, 0, EXM_HOOK_FCT_REALLOC);
    }
    else
    {
        if (size == 0)
        {
            /* free() is actually called */

            if (_exm_hook_free_errors_manage(memblock,
                                             _exm_hook_malloc_free_mismatch))
            {
                rea = (exm_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_REALLOC].fct_proc_old;
                data = rea(memblock, size);
            }

            exm_hook_summary.total_count_frees++;
        }
        else
        {
            /* we re-alloc memory */

            rea = (exm_realloc_t)_exm_hook_instance[EXM_HOOK_FCT_REALLOC].fct_proc_old;
            data = rea(memblock, size);

            /* if data is NULL, nothing is done */
            if (data)
                _exm_hook_realloc_manage(memblock, data, size,
                                         _exm_hook_malloc_free_mismatch);
        }
    }

    return data;
}

static void *
_exm_hook__expand(void *memblock, size_t size)
{
    typedef void *(*exm__expand_t)(void *memblock, size_t size);
    exm__expand_t ea;
    void *data;

    EXM_LOG_WARN("_expand !!!");

    /* we expand memory */

    ea = (exm__expand_t)_exm_hook_instance[EXM_HOOK_FCT__EXPAND].fct_proc_old;
    data = ea(memblock, size);

    /* if data is NULL, nothing is done */
    if (data)
        _exm_hook_realloc_manage(memblock, data, size,
                                 _exm_hook_malloc_free_mismatch);

    return data;
}

static void
_exm_hook_free(void *memblock)
{
    typedef void (*exm_free_t)(void *memblock);
    exm_free_t fr;

    EXM_LOG_WARN("free !!!");

    if (_exm_hook_free_errors_manage(memblock,
                                     _exm_hook_malloc_free_mismatch))
    {
        fr = (exm_free_t)_exm_hook_instance[EXM_HOOK_FCT_FREE].fct_proc_old;
        fr(memblock);
    }
}

static void *
_exm_hook_memcpy(void *dest, const void *src, size_t count)
{
    typedef void *(*exm_memcpy_t)(void *dest, const void *src, size_t count);
    exm_memcpy_t mcpy;

    EXM_LOG_WARN("memcpy !!!");

    if (_exm_hook_memory_overlap(dest, src, count, count))
    {
        Exm_Hook_Error_Data *err_data;

        err_data = _exm_hook_error_data_memory_overlap_new(exm_stack_frames_get(), dest, src, count, count, EXM_HOOK_FCT_MEMCPY);
        exm_hook_error_disp(err_data);
        exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
    }

    mcpy = (exm_memcpy_t)_exm_hook_instance[EXM_HOOK_FCT_MEMCPY].fct_proc_old;
    return mcpy(dest, src, count);
}

static char *
_exm_hook_strcat(char *strDestination, const char *strSource)
{
    typedef char *(*exm_strcat_t)(char *strDestination, const char *strSource);
    exm_strcat_t cat;
    size_t dst_len;
    size_t src_len;

    EXM_LOG_WARN("strcat !!!");

    dst_len = strlen(strDestination);
    src_len = strlen(strSource);
    if (_exm_hook_memory_overlap(strDestination, strSource, dst_len, src_len))
    {
        Exm_Hook_Error_Data *err_data;

        err_data = _exm_hook_error_data_memory_overlap_new(exm_stack_frames_get(), strDestination, strSource, dst_len, src_len, EXM_HOOK_FCT_STRCAT);
        exm_hook_error_disp(err_data);
        exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
    }

    cat = (exm_strcat_t)_exm_hook_instance[EXM_HOOK_FCT_STRCAT].fct_proc_old;
    return cat(strDestination, strSource);
}

static unsigned char *
_exm_hook__mbscat(unsigned char *strDestination, const unsigned char *strSource)
{
    typedef unsigned char *(*exm__mbscat_t)(unsigned char *strDestination, const unsigned char *strSource);
    exm__mbscat_t cat;
    size_t dst_len;
    size_t src_len;

    EXM_LOG_WARN("_mbscat !!!");

    dst_len = _mbslen(strDestination);
    src_len = _mbslen(strSource);
    if (_exm_hook_memory_overlap(strDestination, strSource, dst_len, src_len))
    {
        Exm_Hook_Error_Data *err_data;

        err_data = _exm_hook_error_data_memory_overlap_new(exm_stack_frames_get(), strDestination, strSource, dst_len, src_len, EXM_HOOK_FCT__MBSCAT);
        exm_hook_error_disp(err_data);
        exm_hook_errors = exm_list_append(exm_hook_errors, err_data);
    }

    cat = (exm__mbscat_t)_exm_hook_instance[EXM_HOOK_FCT__MBSCAT].fct_proc_old;
    return cat(strDestination, strSource);
}

static void
_exm_hook_fct_set(HMODULE module, const char *lib_name, PROC fct_proc_old, PROC fct_proc_new)
{
    PIMAGE_IMPORT_DESCRIPTOR iid;
    PIMAGE_THUNK_DATA        thunk;
    ULONG                    size;

    iid = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    if (!iid)
        return;

    while (iid->Name)
    {
        PSTR module_name;

        module_name = (PSTR)((PBYTE) module + iid->Name);

        if (_stricmp(module_name, lib_name) == 0)
            break;
        iid++;
    }

    if (!iid->Name)
        return;

    thunk = (PIMAGE_THUNK_DATA)((PBYTE)module + iid->FirstThunk );
    while (thunk->u1.Function)
    {
        PROC *func;

        func = (PROC *)&thunk->u1.Function;
        if (*func == fct_proc_old)
        {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD dwOldProtect;

            VirtualQuery(func, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
                return;

            *func = *fct_proc_new;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);
            break;
        }
        thunk++;
    }
}

static void
_exm_hook_set(const char *mod_name, const Exm_List *dep_names, int idx_begin, int idx_end)
{
    const Exm_List *iter_dep;

    iter_dep = dep_names;
    while (iter_dep)
    {
        HMODULE mod_dep;

        mod_dep = GetModuleHandle((char *)iter_dep->data);
        if (mod_dep)
        {
            int i;

            for (i = idx_begin; i < idx_end; i++)
            {
                _exm_hook_fct_set(mod_dep, mod_name,
                                  _exm_hook_instance[i].fct_proc_old,
                                  _exm_hook_instance[i].fct_proc_new);
            }
        }

        iter_dep = iter_dep->next;
    }
}

static void
_exm_unhook_set(const char *mod_name, const Exm_List *dep_names, int idx_begin, int idx_end)
{
    const Exm_List *iter_dep;

    iter_dep = dep_names;
    while (iter_dep)
    {
        HMODULE mod_dep;

        mod_dep = GetModuleHandle((char *)iter_dep->data);
        if (mod_dep)
        {
            int i;

            for (i = idx_begin; i < idx_end; i++)
            {
                _exm_hook_fct_set(mod_dep, mod_name,
                                  _exm_hook_instance[i].fct_proc_new,
                                  _exm_hook_instance[i].fct_proc_old);
            }
        }

        iter_dep = iter_dep->next;
    }
}


/*============================================================================*
 *                                 Global                                     *
 *============================================================================*/


#define EXM_HOOK_FCT_SET(type, mod, sym) \
do \
{ \
    _exm_hook_instance[type].fct = type; \
    _exm_hook_instance[type].fct_proc_old = GetProcAddress(mod, #sym); \
    if (!_exm_hook_instance[type].fct_proc_old) \
    { \
        EXM_LOG_WARN("REDIR: redirection of %s failed", #sym);   \
        _exm_hook_instance[type].fct_proc_new = NULL; \
    } \
    else \
    { \
        char buf[MAX_PATH]; \
        _exm_hook_instance[type].fct_proc_new = (FARPROC)_exm_hook_ ## sym; \
        if (GetModuleFileName(mod, buf, sizeof(buf))) \
            EXM_LOG_INFO("REDIR: 0x%p (%s:%s) redirected to 0x%p (%s%s)", \
                         _exm_hook_instance[type].fct_proc_old, \
                         strrchr(buf, '\\') + 1, #sym, \
                         _exm_hook_instance[type].fct_proc_new, \
                         "_exm_hook_", #sym); \
        else \
            EXM_LOG_INFO("REDIR: 0x%p (%s) redirected to 0x%p (%s)", \
                         _exm_hook_instance[type].fct_proc_old, #sym, \
                         _exm_hook_instance[type].fct_proc_new, \
                         "_exm_hook_", #sym); \
    } \
} while (0)


Exm_List *exm_hook_allocations;
Exm_List *exm_hook_errors;
Exm_List *exm_hook_gdi_handles;
Exm_Hook_Summary exm_hook_summary;

unsigned char
exm_hook_init(const Exm_List *crt_names, const Exm_List *dep_names)
{
    const Exm_List *iter_crt;
    char *mod_name;
    HMODULE mod;

    mod_name = "ntdll.dll";

    mod = LoadLibrary(mod_name);
    if (mod)
    {
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_RTLALLOCATEHEAP, mod, RtlAllocateHeap);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_RTLFREEHEAP, mod, RtlFreeHeap);

        EXM_LOG_DBG("Hooking %s", mod_name);
        _exm_hook_set(mod_name, dep_names,
                      EXM_HOOK_FCT_NTDLL_BEGIN, EXM_HOOK_FCT_NTDLL_END);

        FreeLibrary(mod);
    }

    mod_name = "kernel32.dll";

    mod = LoadLibrary(mod_name);
    if (mod)
    {
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_HEAPALLOC, mod, HeapAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_HEAPREALLOC, mod, HeapReAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_HEAPFREE, mod, HeapFree);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_GLOBALALLOC, mod, GlobalAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_GLOBALREALLOC, mod, GlobalReAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_GLOBALFREE, mod, GlobalFree);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_LOCALALLOC, mod, LocalAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_LOCALREALLOC, mod, LocalReAlloc);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_LOCALFREE, mod, LocalFree);

        EXM_LOG_DBG("Hooking %s", mod_name);
        _exm_hook_set(mod_name, dep_names,
                      EXM_HOOK_FCT_KERNEL32_BEGIN, EXM_HOOK_FCT_KERNEL32_END);

        FreeLibrary(mod);
    }

    mod_name = "gdi32.dll";

    mod = LoadLibrary(mod_name);
    if (mod)
    {
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CREATEBITMAP, mod, CreateBitmap);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CREATEBITMAPINDIRECT, mod, CreateBitmapIndirect);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CREATECOMPATIBLEBITMAP, mod, CreateCompatibleBitmap);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CREATEDIBITMAP, mod, CreateDIBitmap);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CREATEDIBSECTION, mod, CreateDIBSection);
        EXM_HOOK_FCT_SET(EXM_HOOK_FCT_DELETEOBJECT, mod, DeleteObject);

        EXM_LOG_DBG("Hooking %s", mod_name);
        _exm_hook_set(mod_name, dep_names,
                      EXM_HOOK_FCT_GDI32_BEGIN, EXM_HOOK_FCT_GDI32_END);

        FreeLibrary(mod);
    }

    iter_crt = crt_names;
    while (iter_crt)
    {
        mod_name = (char *)iter_crt->data;

        mod = LoadLibrary(mod_name);
        if (mod)
        {
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_MALLOC, mod, malloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT__ALIGNED_MALLOC, mod, _aligned_malloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT__STRDUP, mod, _strdup);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_CALLOC, mod, calloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_REALLOC, mod, realloc);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT__EXPAND, mod, _expand);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_FREE, mod, free);

            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_MEMCPY, mod, memcpy);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT_STRCAT, mod, strcat);
            EXM_HOOK_FCT_SET(EXM_HOOK_FCT__MBSCAT, mod, _mbscat);

            EXM_LOG_DBG("Hooking %s", strrchr(mod_name, '\\') + 1);
            mod_name = strrchr(mod_name, '\\') + 1;
            _exm_hook_set(mod_name, dep_names,
                          EXM_HOOK_FCT_LIBC_BEGIN, EXM_HOOK_FCT_LIBC_END);

            FreeLibrary(mod);
        }
        iter_crt = iter_crt->next;
    }

    exm_stack_init();

    exm_hook_allocations = NULL;
    exm_hook_errors = NULL;
    memset(&exm_hook_summary, 0, sizeof(Exm_Hook_Summary));

    return 1;
}

void
exm_hook_shutdown(const Exm_List *crt_names, const Exm_List *dep_names)
{
    const Exm_List *iter_crt;
    char *mod_name;

    exm_list_free(exm_hook_errors, _exm_hook_error_data_del);
    exm_list_free(exm_hook_allocations, _exm_hook_data_alloc_del);

    exm_stack_shutdown();

    mod_name = "ntdll.dll";

    EXM_LOG_DBG("Unhooking %s", mod_name);
    _exm_unhook_set(mod_name, dep_names,
                    EXM_HOOK_FCT_NTDLL_BEGIN, EXM_HOOK_FCT_NTDLL_END);

    mod_name = "kernel32.dll";

    EXM_LOG_DBG("Unhooking %s", mod_name);
    _exm_unhook_set(mod_name, dep_names,
                    EXM_HOOK_FCT_KERNEL32_BEGIN, EXM_HOOK_FCT_KERNEL32_END);

    mod_name = "gdi32.dll";

    EXM_LOG_DBG("Unhooking %s", mod_name);
    _exm_unhook_set(mod_name, dep_names,
                    EXM_HOOK_FCT_GDI32_BEGIN, EXM_HOOK_FCT_GDI32_END);

    iter_crt = crt_names;
    while (iter_crt)
    {
        mod_name = (char *)iter_crt->data;

        EXM_LOG_DBG("Unhooking %s", strrchr(mod_name, '\\') + 1);
        mod_name = strrchr(mod_name, '\\') + 1;
        _exm_unhook_set(mod_name, dep_names,
                        EXM_HOOK_FCT_LIBC_BEGIN, EXM_HOOK_FCT_LIBC_END);

        iter_crt = iter_crt->next;
    }
}

void
exm_hook_error_disp(Exm_Hook_Error_Data *data)
{
    if (!data)
        return;

    switch (data->error_type)
    {
        case EXM_HOOK_ERROR_FREE_WITHOUT_ALLOC:
            EXM_LOG_INFO("Invalid memory free without allocation");
            exm_stack_disp(data->error.free_without_alloc.stack);
            break;
        case EXM_HOOK_ERROR_MULTIPLE_FREES:
            EXM_LOG_INFO("Multiple frees");
            exm_stack_disp(data->error.multiple_frees.stack_free);
            EXM_LOG_INFO("Address 0x%p is 0 bytes inside a block of size %Iu free'd",
                         data->error.multiple_frees.address_alloc,
                         data->error.multiple_frees.size_alloc);
            exm_stack_disp(data->error.multiple_frees.stack_alloc);
            EXM_LOG_INFO("First free");
            exm_stack_disp(data->error.multiple_frees.stack_first_free);
            break;
        case EXM_HOOK_ERROR_MISMATCHED_FREE:
            EXM_LOG_INFO("Mismatched free / allocation");
            exm_stack_disp(data->error.mismatched_free.stack_free);
            EXM_LOG_INFO("Address 0x%p is 0 bytes inside a block of size %Iu free'd",
                         data->error.mismatched_free.address_alloc,
                         data->error.mismatched_free.size_alloc);
            exm_stack_disp(data->error.mismatched_free.stack_alloc);
            break;
        case EXM_HOOK_ERROR_MEMORY_OVERLAP:
        {
            switch (data->error.memory_overlap.fct)
            {
                case EXM_HOOK_FCT_MEMCPY:
                    EXM_LOG_INFO("Source and destination overlap in memcpy(0x%0p, 0x%p, %Iu)",
                                 data->error.memory_overlap.dst,
                                 data->error.memory_overlap.src,
                                 data->error.memory_overlap.dst_len);
                    break;
                case EXM_HOOK_FCT_STRCAT:
                    EXM_LOG_INFO("Source and destination overlap in strcat(0x%0p [%s], 0x%p [%s])",
                                 data->error.memory_overlap.dst,
                                 (char *)data->error.memory_overlap.dst,
                                 data->error.memory_overlap.src,
                                 (char *)data->error.memory_overlap.src);
                    break;
                case EXM_HOOK_FCT__MBSCAT:
                    EXM_LOG_INFO("Source and destination overlap in _mbscat(0x%0p [%s], 0x%p [%s])",
                                 data->error.memory_overlap.dst,
                                 (char *)data->error.memory_overlap.dst,
                                 data->error.memory_overlap.src,
                                 (char *)data->error.memory_overlap.src);
                    break;
                default:
                    /* should never reach this */
                    break;
            }
            exm_stack_disp(data->error.memory_overlap.stack);
            break;
        }
        default:
            break;
    }

    EXM_LOG_INFO("");
}
