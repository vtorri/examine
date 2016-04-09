/*
 * Examine - a set of tools for memory leak detection on Windows and
 * PE file reader
 *
 * Copyright (C) 2016 Vincent Torri.
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

#ifndef EXM_DWARF_H
#define EXM_DWARF_H

typedef union
{
    signed char sint8;
    signed short sint16;
    signed int sint32;
    signed __int64 sint64;
    unsigned char uint8;
    unsigned short uint16;
    unsigned int uint32;
    unsigned __int64 uint64;
} Exm_Dw_Val_Type;

static __inline__ unsigned char
exm_dwarf_read_uint8(const unsigned char *ptr)
{
    return *ptr;
}

static __inline__ unsigned short
exm_dwarf_read_uint16(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (unsigned short)((ptr[0] << 8) | ptr[1]);
#else
    return (unsigned short)((ptr[1] << 8) | ptr[0]);
#endif
}

static __inline__ unsigned int
exm_dwarf_read_uint24(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (unsigned int)((ptr[0] << 16) | (ptr[1] << 8) | ptr[2]);
#else
    return (unsigned int)((ptr[2] << 16) | (ptr[1] << 8) | ptr[0]);
#endif
}

static __inline__ unsigned int
exm_dwarf_read_uint32(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (unsigned int)((ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
#else
    return (unsigned int)((ptr[3] << 24) | (ptr[2] << 16) | (ptr[1] << 8) | ptr[0]);
#endif
}

static __inline__ signed char
exm_dwarf_read_sint8(const unsigned char *ptr)
{
    return (signed char)*ptr;
}

static __inline__ signed short
exm_dwarf_read_sint16(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (signed short)((ptr[0] << 8) | ptr[1]);
#else
    return (signed short)((ptr[1] << 8) | ptr[0]);
#endif
}

static __inline__ signed int
exm_dwarf_read_sint24(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (signed int)((ptr[0] << 16) | (ptr[1] << 8) | ptr[2]);
#else
    return (signed int)((ptr[2] << 16) | (ptr[1] << 8) | ptr[0]);
#endif
}

static __inline__ signed int
exm_dwarf_read_sint32(const unsigned char *ptr)
{
#ifdef WORDS_BIGENDIAN
    return (signed int)((ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
#else
    return (signed int)((ptr[3] << 24) | (ptr[2] << 16) | (ptr[1] << 8) | ptr[0]);
#endif
}

#endif /* EXM_DWARF_H */
