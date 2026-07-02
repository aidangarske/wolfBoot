/* wolfmath.c
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

/* common functions between all math libraries */

/* HAVE_WOLF_BIGINT: Used with asynchronous crypto hardware where "raw" math
 *                   buffers are required.
 * NO_BIG_INT: Disable support for all multi-precision math libraries
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/wolfmath.h>


    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>



    /* all off / all on pointer addresses for constant calculations */
    /* ecc.c uses same table */
    const wc_ptr_t wc_off_on_addr[2] =
    {
        /* 32 bit */
        0x00000000U,
        0xffffffffU
    };


/* reverse an array, used for radix code */



/* Conditionally copy a into b. Performed in constant time.
 *
 * a     MP integer to copy.
 * copy  On 1, copy a into b. on 0 leave b unchanged.
 * b     MP integer to copy into.
 * returns BAD_FUNC_ARG when a or b is NULL, MEMORY_E when growing b fails and
 *         MP_OKAY otherwise.
 */



/* export an mp_int as unsigned char or hex string
 * encType is WC_TYPE_UNSIGNED_BIN or WC_TYPE_HEX_STR
 * return MP_OKAY on success */



