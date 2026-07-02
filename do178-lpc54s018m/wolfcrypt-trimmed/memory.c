/* memory.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* inhibit "#undef current" in linuxkm_wc_port.h, included from wc_port.h,
 * because needed in linuxkm_memory.c, included below.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

/*
Possible memory options:
 * NO_WOLFSSL_MEMORY:               Disables wolf memory callback support. When not defined settings.h defines USE_WOLFSSL_MEMORY.
 * WOLFSSL_STATIC_MEMORY:           Turns on the use of static memory buffers and functions.
                                        This allows for using static memory instead of dynamic.
 * WOLFSSL_STATIC_MEMORY_LEAN:      Requires WOLFSSL_STATIC_MEMORY be defined.
 *                                  Uses smaller type sizes for structs
 *                                  requiring that memory pool sizes be less
 *                                  then 65k and limits features available like
 *                                  IO buffers to reduce footprint size.
 * WOLFSSL_STATIC_MEMORY_DEBUG_CALLBACK:
 *                                  Enables option to register a debugging
 *                                  callback function, useful for
 *                                  WOLFSSL_STATIC_MEMORY builds where XMALLOC
 *                                  and XFREE are not user defined.
 * WOLFSSL_STATIC_ALIGN:            Define defaults to 16 to indicate static memory alignment.
 * HAVE_IO_POOL:                    Enables use of static thread safe memory pool for input/output buffers.
 * XMALLOC_OVERRIDE:                Allows override of the XMALLOC, XFREE and XREALLOC macros.
 * XMALLOC_USER:                    Allows custom XMALLOC, XFREE and XREALLOC functions to be defined.
 * WOLFSSL_NO_MALLOC:               Disables the fall-back case to use STDIO malloc/free when no callbacks are set.
 * WOLFSSL_TRACK_MEMORY:            Enables memory tracking for total stats and list of allocated memory.
 * WOLFSSL_DEBUG_MEMORY:            Enables extra function and line number args for memory callbacks.
 * WOLFSSL_DEBUG_MEMORY_PRINT:      Enables printing of each malloc/free.
 * WOLFSSL_MALLOC_CHECK:            Reports malloc or alignment failure using WOLFSSL_STATIC_ALIGN
 * WOLFSSL_FORCE_MALLOC_FAIL_TEST:  Used for internal testing to induce random malloc failures.
 * WOLFSSL_HEAP_TEST:               Used for internal testing of heap hint
 * WOLFSSL_MEM_FAIL_COUNT:          Fail memory allocation at a count from
 *                                  environment variable: MEM_FAIL_CNT.
 */







/* Exported version of ForceZero(). */




