/* hash.c
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


#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>







/* Get Hash digest size */


/* Get Hash block size */

/* Generic Hashing Wrapper */
















#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && !defined(HAVE_SELFTEST)
#endif /* (!HAVE_FIPS || FIPS v7+) && !HAVE_SELFTEST */

#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && !defined(HAVE_SELFTEST)
#endif /* (!HAVE_FIPS || FIPS v7+) && !HAVE_SELFTEST */







