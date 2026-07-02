/* sha256.c
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

/* For more info on the algorithm, see https://tools.ietf.org/html/rfc6234
 *
 * For more information on NIST FIPS PUB 180-4, see
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

/*

DESCRIPTION
This library provides the interface to SHA-256 secure hash algorithms.
SHA-256 performs processing on message blocks to produce a final hash digest
output. It can be used to hash a message, M, having a length of L bits,
where 0 <= L < 2^64.

Note that in some cases, hardware acceleration may be enabled, depending
on the specific device platform.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

/*
 * SHA256 Build Options:
 * USE_SLOW_SHA256:            Reduces code size by not partially unrolling
                                (~2KB smaller and ~25% slower) (default OFF)
 * WOLFSSL_SHA256_BY_SPEC:     Uses the Ch/Maj based on SHA256 specification
                                (default ON)
 * WOLFSSL_SHA256_ALT_CH_MAJ:  Alternate Ch/Maj that is easier for compilers to
                                optimize and recognize as SHA256 (default OFF)
 * SHA256_MANY_REGISTERS:      A SHA256 version that keeps all data in registers
                                and partial unrolled (default OFF)
 */

/* Default SHA256 to use Ch/Maj based on specification */
#if !defined(WOLFSSL_SHA256_BY_SPEC) && !defined(WOLFSSL_SHA256_ALT_CH_MAJ)
    #define WOLFSSL_SHA256_BY_SPEC
#endif


