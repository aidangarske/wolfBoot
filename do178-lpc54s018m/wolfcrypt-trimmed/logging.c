/* logging.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>








/* allow this to be set to NULL, so logs can be redirected to default output */

/* allow this to be set to NULL, so logs can be redirected to default output */







    /* !(DEBUG_WOLFSSL || (WOLFSSL_DEBUG_CERTS && !NO_WOLFSSL_DEBUG_CERTS)) */
    /*
     * Create some no-op functions for compilers without variadic macros,
     * other than Open Watcom V2.
     */
        /* see logging.h for variadic macros */

/* Final catch for no-op WOLFSSL_MSG_EX needing implementation */
            /* See macro in header */




/*
 * When using OPENSSL_EXTRA or DEBUG_WOLFSSL_VERBOSE macro then WOLFSSL_ERROR is
 * mapped to new function WOLFSSL_ERROR_LINE which gets the line # and function
 * name where WOLFSSL_ERROR is called at.
 */


