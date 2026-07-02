/* sp.c
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

/* Implementation by Sean Parkinson. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>


#include <wolfssl/wolfcrypt/cpuid.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>



#include <wolfssl/wolfcrypt/sp.h>


#ifdef WOLFSSL_SP_SMALL_STACK
    #define SP_DECL_VAR(TYPE, NAME, CNT)                                 TYPE* NAME = NULL
    #define SP_ALLOC_VAR(TYPE, NAME, CNT, HEAP, DT)                      if (err == MP_OKAY) {                                            (NAME) = (TYPE*)XMALLOC(sizeof(TYPE) * (CNT), (HEAP), DT);   if ((NAME) == NULL) {                                        err = MEMORY_E;                                          }                                                            }

    #define SP_VAR_OK(NAME)          ((NAME) != NULL)

    #define SP_FREE_VAR(NAME, HEAP, DT)                                  XFREE(NAME, (HEAP), DT)
    #define SP_ZEROFREE_VAR(TYPE, NAME, CNT, HEAP, DT)                   do {                                                             if ((NAME) != NULL) {                                        ForceZero(NAME, sizeof(TYPE) * (CNT));                   }                                                            SP_FREE_VAR(NAME, HEAP, DT);                                 } while (0)
    #define SP_ZEROFREE_VAR_ALT(TYPE, NAME, FZ_NAME, CNT, HEAP, DT)      do {                                                             if ((FZ_NAME) != NULL) {                                     ForceZero(FZ_NAME, sizeof(TYPE) * (CNT));                }                                                            SP_FREE_VAR(NAME, HEAP, DT);                                 } while (0)
#else
    #define SP_DECL_VAR(TYPE, NAME, CNT)                                 TYPE NAME[CNT]
    #define SP_ALLOC_VAR(TYPE, NAME, CNT, HEAP, DT)                      WC_DO_NOTHING
    #define SP_VAR_OK(NAME)          (1)
    #define SP_FREE_VAR(NAME, HEAP, DT)                                  WC_DO_NOTHING
    #define SP_ZEROFREE_VAR(TYPE, NAME, CNT, HEAP, DT)                   do {                                                             if ((NAME) != NULL) {                                        ForceZero(NAME, sizeof(TYPE) * (CNT));                   }                                                            } while (0)
    #define SP_ZEROFREE_VAR_ALT(TYPE, NAME, FZ_NAME, CNT, HEAP, DT)      do {                                                             if ((FZ_NAME) != NULL) {                                     ForceZero(FZ_NAME, sizeof(TYPE) * (CNT));                }                                                            } while (0)
#endif

#define SP_PRINT_NUM(var, name, total, words, bits)    do {                                               int ii;                                        byte nb[((bits) + 7) / 8];                     sp_digit _s[words];                            XMEMCPY(_s, var, sizeof(_s));                  sp_##total##_norm_##words(_s);                 sp_##total##_to_bin_##words(_s, nb);           fprintf(stderr, name "=0x");                   for (ii=0; ii<((bits) + 7) / 8; ii++)          fprintf(stderr, "%02x", nb[ii]);           fprintf(stderr, "\n");                         } while (0)

#define SP_PRINT_VAL(var, name)                        fprintf(stderr, name "=0x" SP_PRINT_FMT "\n", var)

#define SP_PRINT_INT(var, name)                        fprintf(stderr, name "=%d\n", var)

#if defined(WOLFSSL_SP_SMALL) &&  defined(WOLFSSL_HAVE_SP_ECC) && (!defined(WOLFSSL_SP_NO_256) ||  defined(WOLFSSL_SP_384) || defined(WOLFSSL_SP_521) ||  defined(WOLFSSL_SP_1024))
    #define NEED_ADDR_MASK
#endif

/* Mask for address to obfuscate which of the two address will be used. */
static const size_t addr_mask[2] = { 0, (size_t)-1 };



/* Point structure to use. */
typedef struct sp_point_384 {
    /* X ordinate of point. */
    sp_digit x[2 * 15];
    /* Y ordinate of point. */
    sp_digit y[2 * 15];
    /* Z ordinate of point. */
    sp_digit z[2 * 15];
    /* Indicates point is at infinity. */
    int infinity;
} sp_point_384;

/* The modulus (prime) of the curve P384. */
static const sp_digit p384_mod[15] = {
    0x3ffffff,0x000003f,0x0000000,0x3fc0000,0x2ffffff,0x3ffffff,0x3ffffff,
    0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,
    0x00fffff
};
/* The Montgomery normalizer for modulus of the curve P384. */
static const sp_digit p384_norm_mod[15] = {
    0x0000001,0x3ffffc0,0x3ffffff,0x003ffff,0x1000000,0x0000000,0x0000000,
    0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,
    0x0000000
};
/* The Montgomery multiplier for modulus of the curve P384. */
static const sp_digit p384_mp_mod = 0x000001;
/* The order of the curve P384. */
static const sp_digit p384_order[15] = {
    0x0c52973,0x3065ab3,0x277aece,0x2c922c2,0x3581a0d,0x10dcb77,0x234d81f,
    0x3ffff1d,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,0x3ffffff,
    0x00fffff
};
/* The Montgomery normalizer for order of the curve P384. */
static const sp_digit p384_norm_order[15] = {
    0x33ad68d,0x0f9a54c,0x1885131,0x136dd3d,0x0a7e5f2,0x2f23488,0x1cb27e0,
    0x00000e2,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,
    0x0000000
};
/* The Montgomery multiplier for order of the curve P384. */
static const sp_digit p384_mp_order = 0x8fdc45;
/* The base point of curve P384. */
static const sp_point_384 p384_base = {
    /* X ordinate */
    {
        0x2760ab7,0x1178e1c,0x296c3a5,0x176fd54,0x05502f2,0x0950a8e,0x3741e08,
        0x26e6167,0x3628ba7,0x11b874e,0x3320ad7,0x2c71c7b,0x305378e,0x288afa2,
        0x00aa87c,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Y ordinate */
    {
        0x0ea0e5f,0x0c75f24,0x019d7a4,0x33875fa,0x00a60b1,0x17c2e30,0x1a3113b,
        0x051f3a7,0x1bd289a,0x27e3d07,0x1292dc2,0x27a62fe,0x22c6f5d,0x392a589,
        0x003617d,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* Z ordinate */
    {
        0x0000001,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,
        0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,0x0000000,
        0x0000000,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0,
        (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0, (sp_digit)0
    },
    /* infinity */
    0
};
static const sp_digit p384_b[15] = {
    0x3ec2aef,0x1723b74,0x119d2a8,0x23628bb,0x2c65639,0x004e1d6,0x14088f5,
    0x104480c,0x06efe81,0x2460767,0x23f82d1,0x23815af,0x2e7e498,0x3e9f88f,
    0x00b3312
};

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_384_mul_15(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 lo;

    c = ((sp_uint64)a[14]) * b[14];
    r[29] = (sp_digit)(c >> 26);
    c &= 0x3ffffff;
    for (k = 27; k >= 0; k--) {
        if (k >= 15) {
            i = k - 14;
            imax = 14;
        }
        else {
            i = 0;
            imax = k;
        }
        lo = 0;
        for (; i <= imax; i++) {
            lo += ((sp_uint64)a[i]) * b[k - i];
        }
        c += lo >> 26;
        r[k + 2] += (sp_digit)(c >> 26);
        r[k + 1]  = (sp_digit)(c & 0x3ffffff);
        c = lo & 0x3ffffff;
    }
    r[0] = (sp_digit)c;
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_384_mul_15(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_int64 t0;
    sp_int64 t1;
    sp_digit t[15];

    t0 = ((sp_int64)a[ 0]) * b[ 0];
    t1 = ((sp_int64)a[ 0]) * b[ 1]
       + ((sp_int64)a[ 1]) * b[ 0];
    t[ 0] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[ 2]
       + ((sp_int64)a[ 1]) * b[ 1]
       + ((sp_int64)a[ 2]) * b[ 0];
    t[ 1] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[ 3]
       + ((sp_int64)a[ 1]) * b[ 2]
       + ((sp_int64)a[ 2]) * b[ 1]
       + ((sp_int64)a[ 3]) * b[ 0];
    t[ 2] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[ 4]
       + ((sp_int64)a[ 1]) * b[ 3]
       + ((sp_int64)a[ 2]) * b[ 2]
       + ((sp_int64)a[ 3]) * b[ 1]
       + ((sp_int64)a[ 4]) * b[ 0];
    t[ 3] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[ 5]
       + ((sp_int64)a[ 1]) * b[ 4]
       + ((sp_int64)a[ 2]) * b[ 3]
       + ((sp_int64)a[ 3]) * b[ 2]
       + ((sp_int64)a[ 4]) * b[ 1]
       + ((sp_int64)a[ 5]) * b[ 0];
    t[ 4] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[ 6]
       + ((sp_int64)a[ 1]) * b[ 5]
       + ((sp_int64)a[ 2]) * b[ 4]
       + ((sp_int64)a[ 3]) * b[ 3]
       + ((sp_int64)a[ 4]) * b[ 2]
       + ((sp_int64)a[ 5]) * b[ 1]
       + ((sp_int64)a[ 6]) * b[ 0];
    t[ 5] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[ 7]
       + ((sp_int64)a[ 1]) * b[ 6]
       + ((sp_int64)a[ 2]) * b[ 5]
       + ((sp_int64)a[ 3]) * b[ 4]
       + ((sp_int64)a[ 4]) * b[ 3]
       + ((sp_int64)a[ 5]) * b[ 2]
       + ((sp_int64)a[ 6]) * b[ 1]
       + ((sp_int64)a[ 7]) * b[ 0];
    t[ 6] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[ 8]
       + ((sp_int64)a[ 1]) * b[ 7]
       + ((sp_int64)a[ 2]) * b[ 6]
       + ((sp_int64)a[ 3]) * b[ 5]
       + ((sp_int64)a[ 4]) * b[ 4]
       + ((sp_int64)a[ 5]) * b[ 3]
       + ((sp_int64)a[ 6]) * b[ 2]
       + ((sp_int64)a[ 7]) * b[ 1]
       + ((sp_int64)a[ 8]) * b[ 0];
    t[ 7] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[ 9]
       + ((sp_int64)a[ 1]) * b[ 8]
       + ((sp_int64)a[ 2]) * b[ 7]
       + ((sp_int64)a[ 3]) * b[ 6]
       + ((sp_int64)a[ 4]) * b[ 5]
       + ((sp_int64)a[ 5]) * b[ 4]
       + ((sp_int64)a[ 6]) * b[ 3]
       + ((sp_int64)a[ 7]) * b[ 2]
       + ((sp_int64)a[ 8]) * b[ 1]
       + ((sp_int64)a[ 9]) * b[ 0];
    t[ 8] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[10]
       + ((sp_int64)a[ 1]) * b[ 9]
       + ((sp_int64)a[ 2]) * b[ 8]
       + ((sp_int64)a[ 3]) * b[ 7]
       + ((sp_int64)a[ 4]) * b[ 6]
       + ((sp_int64)a[ 5]) * b[ 5]
       + ((sp_int64)a[ 6]) * b[ 4]
       + ((sp_int64)a[ 7]) * b[ 3]
       + ((sp_int64)a[ 8]) * b[ 2]
       + ((sp_int64)a[ 9]) * b[ 1]
       + ((sp_int64)a[10]) * b[ 0];
    t[ 9] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[11]
       + ((sp_int64)a[ 1]) * b[10]
       + ((sp_int64)a[ 2]) * b[ 9]
       + ((sp_int64)a[ 3]) * b[ 8]
       + ((sp_int64)a[ 4]) * b[ 7]
       + ((sp_int64)a[ 5]) * b[ 6]
       + ((sp_int64)a[ 6]) * b[ 5]
       + ((sp_int64)a[ 7]) * b[ 4]
       + ((sp_int64)a[ 8]) * b[ 3]
       + ((sp_int64)a[ 9]) * b[ 2]
       + ((sp_int64)a[10]) * b[ 1]
       + ((sp_int64)a[11]) * b[ 0];
    t[10] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[12]
       + ((sp_int64)a[ 1]) * b[11]
       + ((sp_int64)a[ 2]) * b[10]
       + ((sp_int64)a[ 3]) * b[ 9]
       + ((sp_int64)a[ 4]) * b[ 8]
       + ((sp_int64)a[ 5]) * b[ 7]
       + ((sp_int64)a[ 6]) * b[ 6]
       + ((sp_int64)a[ 7]) * b[ 5]
       + ((sp_int64)a[ 8]) * b[ 4]
       + ((sp_int64)a[ 9]) * b[ 3]
       + ((sp_int64)a[10]) * b[ 2]
       + ((sp_int64)a[11]) * b[ 1]
       + ((sp_int64)a[12]) * b[ 0];
    t[11] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 0]) * b[13]
       + ((sp_int64)a[ 1]) * b[12]
       + ((sp_int64)a[ 2]) * b[11]
       + ((sp_int64)a[ 3]) * b[10]
       + ((sp_int64)a[ 4]) * b[ 9]
       + ((sp_int64)a[ 5]) * b[ 8]
       + ((sp_int64)a[ 6]) * b[ 7]
       + ((sp_int64)a[ 7]) * b[ 6]
       + ((sp_int64)a[ 8]) * b[ 5]
       + ((sp_int64)a[ 9]) * b[ 4]
       + ((sp_int64)a[10]) * b[ 3]
       + ((sp_int64)a[11]) * b[ 2]
       + ((sp_int64)a[12]) * b[ 1]
       + ((sp_int64)a[13]) * b[ 0];
    t[12] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 0]) * b[14]
       + ((sp_int64)a[ 1]) * b[13]
       + ((sp_int64)a[ 2]) * b[12]
       + ((sp_int64)a[ 3]) * b[11]
       + ((sp_int64)a[ 4]) * b[10]
       + ((sp_int64)a[ 5]) * b[ 9]
       + ((sp_int64)a[ 6]) * b[ 8]
       + ((sp_int64)a[ 7]) * b[ 7]
       + ((sp_int64)a[ 8]) * b[ 6]
       + ((sp_int64)a[ 9]) * b[ 5]
       + ((sp_int64)a[10]) * b[ 4]
       + ((sp_int64)a[11]) * b[ 3]
       + ((sp_int64)a[12]) * b[ 2]
       + ((sp_int64)a[13]) * b[ 1]
       + ((sp_int64)a[14]) * b[ 0];
    t[13] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 1]) * b[14]
       + ((sp_int64)a[ 2]) * b[13]
       + ((sp_int64)a[ 3]) * b[12]
       + ((sp_int64)a[ 4]) * b[11]
       + ((sp_int64)a[ 5]) * b[10]
       + ((sp_int64)a[ 6]) * b[ 9]
       + ((sp_int64)a[ 7]) * b[ 8]
       + ((sp_int64)a[ 8]) * b[ 7]
       + ((sp_int64)a[ 9]) * b[ 6]
       + ((sp_int64)a[10]) * b[ 5]
       + ((sp_int64)a[11]) * b[ 4]
       + ((sp_int64)a[12]) * b[ 3]
       + ((sp_int64)a[13]) * b[ 2]
       + ((sp_int64)a[14]) * b[ 1];
    t[14] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 2]) * b[14]
       + ((sp_int64)a[ 3]) * b[13]
       + ((sp_int64)a[ 4]) * b[12]
       + ((sp_int64)a[ 5]) * b[11]
       + ((sp_int64)a[ 6]) * b[10]
       + ((sp_int64)a[ 7]) * b[ 9]
       + ((sp_int64)a[ 8]) * b[ 8]
       + ((sp_int64)a[ 9]) * b[ 7]
       + ((sp_int64)a[10]) * b[ 6]
       + ((sp_int64)a[11]) * b[ 5]
       + ((sp_int64)a[12]) * b[ 4]
       + ((sp_int64)a[13]) * b[ 3]
       + ((sp_int64)a[14]) * b[ 2];
    r[15] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 3]) * b[14]
       + ((sp_int64)a[ 4]) * b[13]
       + ((sp_int64)a[ 5]) * b[12]
       + ((sp_int64)a[ 6]) * b[11]
       + ((sp_int64)a[ 7]) * b[10]
       + ((sp_int64)a[ 8]) * b[ 9]
       + ((sp_int64)a[ 9]) * b[ 8]
       + ((sp_int64)a[10]) * b[ 7]
       + ((sp_int64)a[11]) * b[ 6]
       + ((sp_int64)a[12]) * b[ 5]
       + ((sp_int64)a[13]) * b[ 4]
       + ((sp_int64)a[14]) * b[ 3];
    r[16] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 4]) * b[14]
       + ((sp_int64)a[ 5]) * b[13]
       + ((sp_int64)a[ 6]) * b[12]
       + ((sp_int64)a[ 7]) * b[11]
       + ((sp_int64)a[ 8]) * b[10]
       + ((sp_int64)a[ 9]) * b[ 9]
       + ((sp_int64)a[10]) * b[ 8]
       + ((sp_int64)a[11]) * b[ 7]
       + ((sp_int64)a[12]) * b[ 6]
       + ((sp_int64)a[13]) * b[ 5]
       + ((sp_int64)a[14]) * b[ 4];
    r[17] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 5]) * b[14]
       + ((sp_int64)a[ 6]) * b[13]
       + ((sp_int64)a[ 7]) * b[12]
       + ((sp_int64)a[ 8]) * b[11]
       + ((sp_int64)a[ 9]) * b[10]
       + ((sp_int64)a[10]) * b[ 9]
       + ((sp_int64)a[11]) * b[ 8]
       + ((sp_int64)a[12]) * b[ 7]
       + ((sp_int64)a[13]) * b[ 6]
       + ((sp_int64)a[14]) * b[ 5];
    r[18] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 6]) * b[14]
       + ((sp_int64)a[ 7]) * b[13]
       + ((sp_int64)a[ 8]) * b[12]
       + ((sp_int64)a[ 9]) * b[11]
       + ((sp_int64)a[10]) * b[10]
       + ((sp_int64)a[11]) * b[ 9]
       + ((sp_int64)a[12]) * b[ 8]
       + ((sp_int64)a[13]) * b[ 7]
       + ((sp_int64)a[14]) * b[ 6];
    r[19] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 7]) * b[14]
       + ((sp_int64)a[ 8]) * b[13]
       + ((sp_int64)a[ 9]) * b[12]
       + ((sp_int64)a[10]) * b[11]
       + ((sp_int64)a[11]) * b[10]
       + ((sp_int64)a[12]) * b[ 9]
       + ((sp_int64)a[13]) * b[ 8]
       + ((sp_int64)a[14]) * b[ 7];
    r[20] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[ 8]) * b[14]
       + ((sp_int64)a[ 9]) * b[13]
       + ((sp_int64)a[10]) * b[12]
       + ((sp_int64)a[11]) * b[11]
       + ((sp_int64)a[12]) * b[10]
       + ((sp_int64)a[13]) * b[ 9]
       + ((sp_int64)a[14]) * b[ 8];
    r[21] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[ 9]) * b[14]
       + ((sp_int64)a[10]) * b[13]
       + ((sp_int64)a[11]) * b[12]
       + ((sp_int64)a[12]) * b[11]
       + ((sp_int64)a[13]) * b[10]
       + ((sp_int64)a[14]) * b[ 9];
    r[22] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[10]) * b[14]
       + ((sp_int64)a[11]) * b[13]
       + ((sp_int64)a[12]) * b[12]
       + ((sp_int64)a[13]) * b[11]
       + ((sp_int64)a[14]) * b[10];
    r[23] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[11]) * b[14]
       + ((sp_int64)a[12]) * b[13]
       + ((sp_int64)a[13]) * b[12]
       + ((sp_int64)a[14]) * b[11];
    r[24] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[12]) * b[14]
       + ((sp_int64)a[13]) * b[13]
       + ((sp_int64)a[14]) * b[12];
    r[25] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = ((sp_int64)a[13]) * b[14]
       + ((sp_int64)a[14]) * b[13];
    r[26] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = ((sp_int64)a[14]) * b[14];
    r[27] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    r[28] = (sp_digit)(t0 & 0x3ffffff);
    r[29] = (sp_digit)(t0 >> 26);
    XMEMCPY(r, t, sizeof(t));
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_384_sqr_15(sp_digit* r, const sp_digit* a)
{
    int i;
    int imax;
    int k;
    sp_uint64 c;
    sp_uint64 t;

    c = ((sp_uint64)a[14]) * a[14];
    r[29] = (sp_digit)(c >> 26);
    c = (c & 0x3ffffff) << 26;
    for (k = 27; k >= 0; k--) {
        i = (k + 1) / 2;
        if ((k & 1) == 0) {
           c += ((sp_uint64)a[i]) * a[i];
           i++;
        }
        if (k < 14) {
            imax = k;
        }
        else {
            imax = 14;
        }
        t = 0;
        for (; i <= imax; i++) {
            t += ((sp_uint64)a[i]) * a[k - i];
        }
        c += t * 2;

        r[k + 2] += (sp_digit) (c >> 52);
        r[k + 1]  = (sp_digit)((c >> 26) & 0x3ffffff);
        c = (c & 0x3ffffff) << 26;
    }
    r[0] = (sp_digit)(c >> 26);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_384_sqr_15(sp_digit* r, const sp_digit* a)
{
    sp_int64 t0;
    sp_int64 t1;
    sp_digit t[15];

    t0 =  ((sp_int64)a[ 0]) * a[ 0];
    t1 = (((sp_int64)a[ 0]) * a[ 1]) * 2;
    t[ 0] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[ 2]) * 2
       +  ((sp_int64)a[ 1]) * a[ 1];
    t[ 1] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[ 3]
       +  ((sp_int64)a[ 1]) * a[ 2]) * 2;
    t[ 2] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[ 4]
       +  ((sp_int64)a[ 1]) * a[ 3]) * 2
       +  ((sp_int64)a[ 2]) * a[ 2];
    t[ 3] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[ 5]
       +  ((sp_int64)a[ 1]) * a[ 4]
       +  ((sp_int64)a[ 2]) * a[ 3]) * 2;
    t[ 4] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[ 6]
       +  ((sp_int64)a[ 1]) * a[ 5]
       +  ((sp_int64)a[ 2]) * a[ 4]) * 2
       +  ((sp_int64)a[ 3]) * a[ 3];
    t[ 5] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[ 7]
       +  ((sp_int64)a[ 1]) * a[ 6]
       +  ((sp_int64)a[ 2]) * a[ 5]
       +  ((sp_int64)a[ 3]) * a[ 4]) * 2;
    t[ 6] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[ 8]
       +  ((sp_int64)a[ 1]) * a[ 7]
       +  ((sp_int64)a[ 2]) * a[ 6]
       +  ((sp_int64)a[ 3]) * a[ 5]) * 2
       +  ((sp_int64)a[ 4]) * a[ 4];
    t[ 7] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[ 9]
       +  ((sp_int64)a[ 1]) * a[ 8]
       +  ((sp_int64)a[ 2]) * a[ 7]
       +  ((sp_int64)a[ 3]) * a[ 6]
       +  ((sp_int64)a[ 4]) * a[ 5]) * 2;
    t[ 8] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[10]
       +  ((sp_int64)a[ 1]) * a[ 9]
       +  ((sp_int64)a[ 2]) * a[ 8]
       +  ((sp_int64)a[ 3]) * a[ 7]
       +  ((sp_int64)a[ 4]) * a[ 6]) * 2
       +  ((sp_int64)a[ 5]) * a[ 5];
    t[ 9] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[11]
       +  ((sp_int64)a[ 1]) * a[10]
       +  ((sp_int64)a[ 2]) * a[ 9]
       +  ((sp_int64)a[ 3]) * a[ 8]
       +  ((sp_int64)a[ 4]) * a[ 7]
       +  ((sp_int64)a[ 5]) * a[ 6]) * 2;
    t[10] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[12]
       +  ((sp_int64)a[ 1]) * a[11]
       +  ((sp_int64)a[ 2]) * a[10]
       +  ((sp_int64)a[ 3]) * a[ 9]
       +  ((sp_int64)a[ 4]) * a[ 8]
       +  ((sp_int64)a[ 5]) * a[ 7]) * 2
       +  ((sp_int64)a[ 6]) * a[ 6];
    t[11] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 0]) * a[13]
       +  ((sp_int64)a[ 1]) * a[12]
       +  ((sp_int64)a[ 2]) * a[11]
       +  ((sp_int64)a[ 3]) * a[10]
       +  ((sp_int64)a[ 4]) * a[ 9]
       +  ((sp_int64)a[ 5]) * a[ 8]
       +  ((sp_int64)a[ 6]) * a[ 7]) * 2;
    t[12] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 0]) * a[14]
       +  ((sp_int64)a[ 1]) * a[13]
       +  ((sp_int64)a[ 2]) * a[12]
       +  ((sp_int64)a[ 3]) * a[11]
       +  ((sp_int64)a[ 4]) * a[10]
       +  ((sp_int64)a[ 5]) * a[ 9]
       +  ((sp_int64)a[ 6]) * a[ 8]) * 2
       +  ((sp_int64)a[ 7]) * a[ 7];
    t[13] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 1]) * a[14]
       +  ((sp_int64)a[ 2]) * a[13]
       +  ((sp_int64)a[ 3]) * a[12]
       +  ((sp_int64)a[ 4]) * a[11]
       +  ((sp_int64)a[ 5]) * a[10]
       +  ((sp_int64)a[ 6]) * a[ 9]
       +  ((sp_int64)a[ 7]) * a[ 8]) * 2;
    t[14] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 2]) * a[14]
       +  ((sp_int64)a[ 3]) * a[13]
       +  ((sp_int64)a[ 4]) * a[12]
       +  ((sp_int64)a[ 5]) * a[11]
       +  ((sp_int64)a[ 6]) * a[10]
       +  ((sp_int64)a[ 7]) * a[ 9]) * 2
       +  ((sp_int64)a[ 8]) * a[ 8];
    r[15] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 3]) * a[14]
       +  ((sp_int64)a[ 4]) * a[13]
       +  ((sp_int64)a[ 5]) * a[12]
       +  ((sp_int64)a[ 6]) * a[11]
       +  ((sp_int64)a[ 7]) * a[10]
       +  ((sp_int64)a[ 8]) * a[ 9]) * 2;
    r[16] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 4]) * a[14]
       +  ((sp_int64)a[ 5]) * a[13]
       +  ((sp_int64)a[ 6]) * a[12]
       +  ((sp_int64)a[ 7]) * a[11]
       +  ((sp_int64)a[ 8]) * a[10]) * 2
       +  ((sp_int64)a[ 9]) * a[ 9];
    r[17] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 5]) * a[14]
       +  ((sp_int64)a[ 6]) * a[13]
       +  ((sp_int64)a[ 7]) * a[12]
       +  ((sp_int64)a[ 8]) * a[11]
       +  ((sp_int64)a[ 9]) * a[10]) * 2;
    r[18] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 6]) * a[14]
       +  ((sp_int64)a[ 7]) * a[13]
       +  ((sp_int64)a[ 8]) * a[12]
       +  ((sp_int64)a[ 9]) * a[11]) * 2
       +  ((sp_int64)a[10]) * a[10];
    r[19] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 7]) * a[14]
       +  ((sp_int64)a[ 8]) * a[13]
       +  ((sp_int64)a[ 9]) * a[12]
       +  ((sp_int64)a[10]) * a[11]) * 2;
    r[20] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[ 8]) * a[14]
       +  ((sp_int64)a[ 9]) * a[13]
       +  ((sp_int64)a[10]) * a[12]) * 2
       +  ((sp_int64)a[11]) * a[11];
    r[21] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[ 9]) * a[14]
       +  ((sp_int64)a[10]) * a[13]
       +  ((sp_int64)a[11]) * a[12]) * 2;
    r[22] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[10]) * a[14]
       +  ((sp_int64)a[11]) * a[13]) * 2
       +  ((sp_int64)a[12]) * a[12];
    r[23] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[11]) * a[14]
       +  ((sp_int64)a[12]) * a[13]) * 2;
    r[24] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 = (((sp_int64)a[12]) * a[14]) * 2
       +  ((sp_int64)a[13]) * a[13];
    r[25] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    t1 = (((sp_int64)a[13]) * a[14]) * 2;
    r[26] = (sp_digit)(t0 & 0x3ffffff); t1 += t0 >> 26;
    t0 =  ((sp_int64)a[14]) * a[14];
    r[27] = (sp_digit)(t1 & 0x3ffffff); t0 += t1 >> 26;
    r[28] = (sp_digit)(t0 & 0x3ffffff);
    r[29] = (sp_digit)(t0 >> 26);
    XMEMCPY(r, t, sizeof(t));
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 15; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];
    r[ 9] = a[ 9] + b[ 9];
    r[10] = a[10] + b[10];
    r[11] = a[11] + b[11];
    r[12] = a[12] + b[12];
    r[13] = a[13] + b[13];
    r[14] = a[14] + b[14];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_sub_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 15; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_sub_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] - b[ 0];
    r[ 1] = a[ 1] - b[ 1];
    r[ 2] = a[ 2] - b[ 2];
    r[ 3] = a[ 3] - b[ 3];
    r[ 4] = a[ 4] - b[ 4];
    r[ 5] = a[ 5] - b[ 5];
    r[ 6] = a[ 6] - b[ 6];
    r[ 7] = a[ 7] - b[ 7];
    r[ 8] = a[ 8] - b[ 8];
    r[ 9] = a[ 9] - b[ 9];
    r[10] = a[10] - b[10];
    r[11] = a[11] - b[11];
    r[12] = a[12] - b[12];
    r[13] = a[13] - b[13];
    r[14] = a[14] - b[14];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_384_from_mp(sp_digit* r, int size, const mp_int* a)
{
    unsigned int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < (unsigned int)a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x3ffffff;
        s = 26U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 26U) <= (word32)DIGIT_BIT) {
            s += 26U;
            r[j] &= 0x3ffffff;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = (sp_digit)0;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert a point of type ecc_point to type sp_point_384.
 *
 * p   Point of type sp_point_384 (result).
 * pm  Point of type ecc_point.
 */

/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_384_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (384 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
        int i;
        int j = 0;
        int s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 15; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 26 >= DIGIT_BIT) {
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 26 - s;
            }
            else {
                s += 26;
            }
        }
        r->used = (384 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
    }

    return err;
}

/* Convert a point of type sp_point_384 to type ecc_point.
 *
 * p   Point of type sp_point_384.
 * pm  Point of type ecc_point (result).
 * returns MEMORY_E when allocation of memory in ecc_point fails otherwise
 * MP_OKAY.
 */
static int sp_384_point_to_ecc_point_15(const sp_point_384* p, ecc_point* pm)
{
    int err;

    err = sp_384_to_mp(p->x, pm->x);
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->y, pm->y);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->z, pm->z);
    }

    return err;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_384_cmp_15(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=14; i>=0; i--) {
        r |= (a[i] - b[i]) & ~(((sp_digit)0 - r) >> 25);
    }
#else
    r |= (a[14] - b[14]) & (0 - (sp_digit)1);
    r |= (a[13] - b[13]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[12] - b[12]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[11] - b[11]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[10] - b[10]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 9] - b[ 9]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 8] - b[ 8]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 7] - b[ 7]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 6] - b[ 6]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 5] - b[ 5]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 4] - b[ 4]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 3] - b[ 3]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 2] - b[ 2]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 1] - b[ 1]) & ~(((sp_digit)0 - r) >> 25);
    r |= (a[ 0] - b[ 0]) & ~(((sp_digit)0 - r) >> 25);
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_384_cond_sub_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 15; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    r[ 0] = a[ 0] - (b[ 0] & m);
    r[ 1] = a[ 1] - (b[ 1] & m);
    r[ 2] = a[ 2] - (b[ 2] & m);
    r[ 3] = a[ 3] - (b[ 3] & m);
    r[ 4] = a[ 4] - (b[ 4] & m);
    r[ 5] = a[ 5] - (b[ 5] & m);
    r[ 6] = a[ 6] - (b[ 6] & m);
    r[ 7] = a[ 7] - (b[ 7] & m);
    r[ 8] = a[ 8] - (b[ 8] & m);
    r[ 9] = a[ 9] - (b[ 9] & m);
    r[10] = a[10] - (b[10] & m);
    r[11] = a[11] - (b[11] & m);
    r[12] = a[12] - (b[12] & m);
    r[13] = a[13] - (b[13] & m);
    r[14] = a[14] - (b[14] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_384_mul_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t[4];
    int i;

    t[0] = 0;
    for (i = 0; i < 12; i += 4) {
        t[0] += (tb * a[i+0]) + r[i+0];
        t[1]  = (tb * a[i+1]) + r[i+1];
        t[2]  = (tb * a[i+2]) + r[i+2];
        t[3]  = (tb * a[i+3]) + r[i+3];
        r[i+0] = (sp_digit)(t[0] & 0x3ffffff);
        t[1] += t[0] >> 26;
        r[i+1] = (sp_digit)(t[1] & 0x3ffffff);
        t[2] += t[1] >> 26;
        r[i+2] = (sp_digit)(t[2] & 0x3ffffff);
        t[3] += t[2] >> 26;
        r[i+3] = (sp_digit)(t[3] & 0x3ffffff);
        t[0]  = t[3] >> 26;
    }
    t[0] += (tb * a[12]) + r[12];
    t[1]  = (tb * a[13]) + r[13];
    t[2]  = (tb * a[14]) + r[14];
    r[12] = (sp_digit)(t[0] & 0x3ffffff);
    t[1] += t[0] >> 26;
    r[13] = (sp_digit)(t[1] & 0x3ffffff);
    t[2] += t[1] >> 26;
    r[14] = (sp_digit)(t[2] & 0x3ffffff);
    r[15] +=  (sp_digit)(t[2] >> 26);
#else
    sp_int64 tb = b;
    sp_int64 t[15];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    t[ 7] = tb * a[ 7];
    t[ 8] = tb * a[ 8];
    t[ 9] = tb * a[ 9];
    t[10] = tb * a[10];
    t[11] = tb * a[11];
    t[12] = tb * a[12];
    t[13] = tb * a[13];
    t[14] = tb * a[14];
    r[ 0] += (sp_digit)                 (t[ 0] & 0x3ffffff);
    r[ 1] += (sp_digit)((t[ 0] >> 26) + (t[ 1] & 0x3ffffff));
    r[ 2] += (sp_digit)((t[ 1] >> 26) + (t[ 2] & 0x3ffffff));
    r[ 3] += (sp_digit)((t[ 2] >> 26) + (t[ 3] & 0x3ffffff));
    r[ 4] += (sp_digit)((t[ 3] >> 26) + (t[ 4] & 0x3ffffff));
    r[ 5] += (sp_digit)((t[ 4] >> 26) + (t[ 5] & 0x3ffffff));
    r[ 6] += (sp_digit)((t[ 5] >> 26) + (t[ 6] & 0x3ffffff));
    r[ 7] += (sp_digit)((t[ 6] >> 26) + (t[ 7] & 0x3ffffff));
    r[ 8] += (sp_digit)((t[ 7] >> 26) + (t[ 8] & 0x3ffffff));
    r[ 9] += (sp_digit)((t[ 8] >> 26) + (t[ 9] & 0x3ffffff));
    r[10] += (sp_digit)((t[ 9] >> 26) + (t[10] & 0x3ffffff));
    r[11] += (sp_digit)((t[10] >> 26) + (t[11] & 0x3ffffff));
    r[12] += (sp_digit)((t[11] >> 26) + (t[12] & 0x3ffffff));
    r[13] += (sp_digit)((t[12] >> 26) + (t[13] & 0x3ffffff));
    r[14] += (sp_digit)((t[13] >> 26) + (t[14] & 0x3ffffff));
    r[15] += (sp_digit) (t[14] >> 26);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 26 bits.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_384_norm_15(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 14; i++) {
        a[i+1] += a[i] >> 26;
        a[i] &= 0x3ffffff;
    }
#else
    a[1] += a[0] >> 26; a[0] &= 0x3ffffff;
    a[2] += a[1] >> 26; a[1] &= 0x3ffffff;
    a[3] += a[2] >> 26; a[2] &= 0x3ffffff;
    a[4] += a[3] >> 26; a[3] &= 0x3ffffff;
    a[5] += a[4] >> 26; a[4] &= 0x3ffffff;
    a[6] += a[5] >> 26; a[5] &= 0x3ffffff;
    a[7] += a[6] >> 26; a[6] &= 0x3ffffff;
    a[8] += a[7] >> 26; a[7] &= 0x3ffffff;
    a[9] += a[8] >> 26; a[8] &= 0x3ffffff;
    a[10] += a[9] >> 26; a[9] &= 0x3ffffff;
    a[11] += a[10] >> 26; a[10] &= 0x3ffffff;
    a[12] += a[11] >> 26; a[11] &= 0x3ffffff;
    a[13] += a[12] >> 26; a[12] &= 0x3ffffff;
    a[14] += a[13] >> 26; a[13] &= 0x3ffffff;
#endif /* WOLFSSL_SP_SMALL */
}

/* Shift the result in the high 384 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_384_mont_shift_15(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_int64 n = a[14] >> 20;
    n += ((sp_int64)a[15]) << 6;

    for (i = 0; i < 14; i++) {
        r[i] = (sp_digit)(n & 0x3ffffff);
        n >>= 26;
        n += ((sp_int64)a[16 + i]) << 6;
    }
    r[14] = (sp_digit)n;
#else
    sp_int64 n = a[14] >> 20;
    n += ((sp_int64)a[15]) << 6;
    r[ 0] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[16]) << 6;
    r[ 1] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[17]) << 6;
    r[ 2] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[18]) << 6;
    r[ 3] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[19]) << 6;
    r[ 4] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[20]) << 6;
    r[ 5] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[21]) << 6;
    r[ 6] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[22]) << 6;
    r[ 7] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[23]) << 6;
    r[ 8] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[24]) << 6;
    r[ 9] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[25]) << 6;
    r[10] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[26]) << 6;
    r[11] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[27]) << 6;
    r[12] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[28]) << 6;
    r[13] = (sp_digit)(n & 0x3ffffff); n >>= 26; n += ((sp_int64)a[29]) << 6;
    r[14] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[15], 0, sizeof(*r) * 15U);
}

/* Reduce the number back to 384 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_384_mont_reduce_order_15(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;
    sp_digit over;

    sp_384_norm_15(a + 15);

    for (i=0; i<14; i++) {
        mu = (sp_digit)(((sp_uint32)a[i] * (sp_uint32)mp) & 0x3ffffff);
        sp_384_mul_add_15(a+i, m, mu);
        a[i+1] += a[i] >> 26;
    }
    mu = (sp_digit)(((sp_uint32)a[i] * (sp_uint32)mp) & 0xfffffL);
    sp_384_mul_add_15(a+i, m, mu);
    a[i+1] += a[i] >> 26;
    a[i] &= 0x3ffffff;
    sp_384_mont_shift_15(a, a);
    over = a[14] >> 20;
    sp_384_cond_sub_15(a, a, m, ~((over - 1) >> 31));
    sp_384_norm_15(a);
}

/* Reduce the number back to 384 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_384_mont_reduce_15(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit am;

    (void)m;
    (void)mp;

    for (i = 0; i < 14; i++) {
        am = (sp_digit)((a[i] * 0x1) & 0x3ffffff);
        a[i +  1] += (sp_digit)((am << 6) & 0x3ffffff);
        a[i +  2] += am >> 20;
        a[i +  3] -= (sp_digit)((am << 18) & 0x3ffffff);
        a[i +  4] -= am >> 8;
        a[i +  4] -= (sp_digit)((am << 24) & 0x3ffffff);
        a[i +  5] -= am >> 2;
        a[i + 14] += (sp_digit)((am << 20) & 0x3ffffff);
        a[i + 15] += am >> 6;

        a[i +  1] += a[i] >> 26;
    }
    am = (sp_digit)((a[14] * 0x1) & 0xfffff);
    a[14 +  1] += (sp_digit)((am << 6) & 0x3ffffff);
    a[14 +  2] += am >> 20;
    a[14 +  3] -= (sp_digit)((am << 18) & 0x3ffffff);
    a[14 +  4] -= am >> 8;
    a[14 +  4] -= (sp_digit)((am << 24) & 0x3ffffff);
    a[14 +  5] -= am >> 2;
    a[14 + 14] += (sp_digit)((am << 20) & 0x3ffffff);
    a[14 + 15] += am >> 6;

    a[0] = (a[14] >> 20) + (sp_digit)((a[15] << 6) & 0x3ffffff);
    a[1] = (a[15] >> 20) + (sp_digit)((a[16] << 6) & 0x3ffffff);
    a[2] = (a[16] >> 20) + (sp_digit)((a[17] << 6) & 0x3ffffff);
    a[3] = (a[17] >> 20) + (sp_digit)((a[18] << 6) & 0x3ffffff);
    a[4] = (a[18] >> 20) + (sp_digit)((a[19] << 6) & 0x3ffffff);
    a[5] = (a[19] >> 20) + (sp_digit)((a[20] << 6) & 0x3ffffff);
    a[6] = (a[20] >> 20) + (sp_digit)((a[21] << 6) & 0x3ffffff);
    a[7] = (a[21] >> 20) + (sp_digit)((a[22] << 6) & 0x3ffffff);
    a[8] = (a[22] >> 20) + (sp_digit)((a[23] << 6) & 0x3ffffff);
    a[9] = (a[23] >> 20) + (sp_digit)((a[24] << 6) & 0x3ffffff);
    a[10] = (a[24] >> 20) + (sp_digit)((a[25] << 6) & 0x3ffffff);
    a[11] = (a[25] >> 20) + (sp_digit)((a[26] << 6) & 0x3ffffff);
    a[12] = (a[26] >> 20) + (sp_digit)((a[27] << 6) & 0x3ffffff);
    a[13] = (a[27] >> 20) + (sp_digit)((a[28] << 6) & 0x3ffffff);
    a[14] = (a[14 + 14] >> 20) +  (a[29] << 6);

    a[1] += a[0] >> 26; a[0] &= 0x3ffffff;
    a[2] += a[1] >> 26; a[1] &= 0x3ffffff;
    a[3] += a[2] >> 26; a[2] &= 0x3ffffff;
    a[4] += a[3] >> 26; a[3] &= 0x3ffffff;
    a[5] += a[4] >> 26; a[4] &= 0x3ffffff;
    a[6] += a[5] >> 26; a[5] &= 0x3ffffff;
    a[7] += a[6] >> 26; a[6] &= 0x3ffffff;
    a[8] += a[7] >> 26; a[7] &= 0x3ffffff;
    a[9] += a[8] >> 26; a[8] &= 0x3ffffff;
    a[10] += a[9] >> 26; a[9] &= 0x3ffffff;
    a[11] += a[10] >> 26; a[10] &= 0x3ffffff;
    a[12] += a[11] >> 26; a[11] &= 0x3ffffff;
    a[13] += a[12] >> 26; a[12] &= 0x3ffffff;
    a[14] += a[13] >> 26; a[13] &= 0x3ffffff;

    /* Get the bit over, if any. */
    am = a[14] >> 20;
    /* Create mask. */
    am = 0 - am;

    a[0] -= (sp_digit)(0x03ffffff & am);
    a[1] -= (sp_digit)(0x0000003f & am);
    /* p384_mod[2] is zero */
    a[3] -= (sp_digit)(0x03fc0000 & am);
    a[4] -= (sp_digit)(0x02ffffff & am);
    a[5] -= (sp_digit)(0x03ffffff & am);
    a[6] -= (sp_digit)(0x03ffffff & am);
    a[7] -= (sp_digit)(0x03ffffff & am);
    a[8] -= (sp_digit)(0x03ffffff & am);
    a[9] -= (sp_digit)(0x03ffffff & am);
    a[10] -= (sp_digit)(0x03ffffff & am);
    a[11] -= (sp_digit)(0x03ffffff & am);
    a[12] -= (sp_digit)(0x03ffffff & am);
    a[13] -= (sp_digit)(0x03ffffff & am);
    a[14] -= (sp_digit)(0x000fffff & am);

    a[1] += a[0] >> 26; a[0] &= 0x3ffffff;
    a[2] += a[1] >> 26; a[1] &= 0x3ffffff;
    a[3] += a[2] >> 26; a[2] &= 0x3ffffff;
    a[4] += a[3] >> 26; a[3] &= 0x3ffffff;
    a[5] += a[4] >> 26; a[4] &= 0x3ffffff;
    a[6] += a[5] >> 26; a[5] &= 0x3ffffff;
    a[7] += a[6] >> 26; a[6] &= 0x3ffffff;
    a[8] += a[7] >> 26; a[7] &= 0x3ffffff;
    a[9] += a[8] >> 26; a[8] &= 0x3ffffff;
    a[10] += a[9] >> 26; a[9] &= 0x3ffffff;
    a[11] += a[10] >> 26; a[10] &= 0x3ffffff;
    a[12] += a[11] >> 26; a[11] &= 0x3ffffff;
    a[13] += a[12] >> 26; a[12] &= 0x3ffffff;
    a[14] += a[13] >> 26; a[13] &= 0x3ffffff;
}

/* Multiply two Montgomery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montgomery form.
 * b   Second number to multiply in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_384_mont_mul_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit* m, sp_digit mp)
{
    sp_384_mul_15(r, a, b);
    sp_384_mont_reduce_15(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_384_mont_sqr_15(sp_digit* r, const sp_digit* a,
        const sp_digit* m, sp_digit mp)
{
    sp_384_sqr_15(r, a);
    sp_384_mont_reduce_15(r, m, mp);
}

#if !defined(WOLFSSL_SP_SMALL) || defined(HAVE_COMP_KEY)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montgomery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montgomery multiplier.
 */
SP_NOINLINE static void sp_384_mont_sqr_n_15(sp_digit* r,
    const sp_digit* a, int n, const sp_digit* m, sp_digit mp)
{
    sp_384_mont_sqr_15(r, a, m, mp);
    for (; n > 1; n--) {
        sp_384_mont_sqr_15(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL || HAVE_COMP_KEY */
#ifdef WOLFSSL_SP_SMALL
/* Mod-2 for the P384 curve. */
static const word32 p384_mod_minus_2[12] = {
    0xfffffffdU,0x00000000U,0x00000000U,0xffffffffU,0xfffffffeU,0xffffffffU,
    0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU
};
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P384 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_384_mont_inv_15(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 15);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_15(t, t, p384_mod, p384_mp_mod);
        if (p384_mod_minus_2[i / 32] & ((sp_digit)1 << (i % 32)))
            sp_384_mont_mul_15(t, t, a, p384_mod, p384_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 15);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 15;
    sp_digit* t3 = td + 4 * 15;
    sp_digit* t4 = td + 6 * 15;
    sp_digit* t5 = td + 8 * 15;

    /* 0x2 */
    sp_384_mont_sqr_15(t1, a, p384_mod, p384_mp_mod);
    /* 0x3 */
    sp_384_mont_mul_15(t5, t1, a, p384_mod, p384_mp_mod);
    /* 0xc */
    sp_384_mont_sqr_n_15(t1, t5, 2, p384_mod, p384_mp_mod);
    /* 0xf */
    sp_384_mont_mul_15(t2, t5, t1, p384_mod, p384_mp_mod);
    /* 0x1e */
    sp_384_mont_sqr_15(t1, t2, p384_mod, p384_mp_mod);
    /* 0x1f */
    sp_384_mont_mul_15(t4, t1, a, p384_mod, p384_mp_mod);
    /* 0x3e0 */
    sp_384_mont_sqr_n_15(t1, t4, 5, p384_mod, p384_mp_mod);
    /* 0x3ff */
    sp_384_mont_mul_15(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0x7fe0 */
    sp_384_mont_sqr_n_15(t1, t2, 5, p384_mod, p384_mp_mod);
    /* 0x7fff */
    sp_384_mont_mul_15(t4, t4, t1, p384_mod, p384_mp_mod);
    /* 0x3fff8000 */
    sp_384_mont_sqr_n_15(t1, t4, 15, p384_mod, p384_mp_mod);
    /* 0x3fffffff */
    sp_384_mont_mul_15(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffc */
    sp_384_mont_sqr_n_15(t3, t2, 2, p384_mod, p384_mp_mod);
    /* 0xfffffffd */
    sp_384_mont_mul_15(r, t3, a, p384_mod, p384_mp_mod);
    /* 0xffffffff */
    sp_384_mont_mul_15(t3, t5, t3, p384_mod, p384_mp_mod);
    /* 0xfffffffc0000000 */
    sp_384_mont_sqr_n_15(t1, t2, 30, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff */
    sp_384_mont_mul_15(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff000000000000000 */
    sp_384_mont_sqr_n_15(t1, t2, 60, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff */
    sp_384_mont_mul_15(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff000000000000000000000000000000 */
    sp_384_mont_sqr_n_15(t1, t2, 120, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_15(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000 */
    sp_384_mont_sqr_n_15(t1, t2, 15, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_15(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000 */
    sp_384_mont_sqr_n_15(t1, t2, 33, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff */
    sp_384_mont_mul_15(t2, t3, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_15(t1, t2, 96, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd */
    sp_384_mont_mul_15(r, r, t1, p384_mod, p384_mp_mod);

#endif /* WOLFSSL_SP_SMALL */
}

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_384_map_15(sp_point_384* r, const sp_point_384* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*15;
    sp_int32 n;

    sp_384_mont_inv_15(t1, p->z, t + 2*15);

    sp_384_mont_sqr_15(t2, t1, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t1, t2, t1, p384_mod, p384_mp_mod);

    /* x /= z^2 */
    sp_384_mont_mul_15(r->x, p->x, t2, p384_mod, p384_mp_mod);
    XMEMSET(r->x + 15, 0, sizeof(sp_digit) * 15U);
    sp_384_mont_reduce_15(r->x, p384_mod, p384_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_384_cmp_15(r->x, p384_mod);
    sp_384_cond_sub_15(r->x, r->x, p384_mod, (sp_digit)~(n >> 25));
    sp_384_norm_15(r->x);

    /* y /= z^3 */
    sp_384_mont_mul_15(r->y, p->y, t1, p384_mod, p384_mp_mod);
    XMEMSET(r->y + 15, 0, sizeof(sp_digit) * 15U);
    sp_384_mont_reduce_15(r->y, p384_mod, p384_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_384_cmp_15(r->y, p384_mod);
    sp_384_cond_sub_15(r->y, r->y, p384_mod, (sp_digit)~(n >> 25));
    sp_384_norm_15(r->y);

    XMEMSET(r->z, 0, sizeof(r->z) / 2);
    r->z[0] = 1;
}

/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montgomery form.
 * b   Second number to add in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_add_15(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    sp_digit over;
    (void)sp_384_add_15(r, a, b);
    sp_384_norm_15(r);
    over = r[14] >> 20;
    sp_384_cond_sub_15(r, r, m, ~((over - 1) >> 31));
    sp_384_norm_15(r);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_dbl_15(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_384_add_15(r, a, a);
    sp_384_norm_15(r);
    over = r[14] >> 20;
    sp_384_cond_sub_15(r, r, m, ~((over - 1) >> 31));
    sp_384_norm_15(r);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_tpl_15(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit over;
    (void)sp_384_add_15(r, a, a);
    sp_384_norm_15(r);
    over = r[14] >> 20;
    sp_384_cond_sub_15(r, r, m, ~((over - 1) >> 31));
    sp_384_norm_15(r);
    (void)sp_384_add_15(r, r, a);
    sp_384_norm_15(r);
    over = r[14] >> 20;
    sp_384_cond_sub_15(r, r, m, ~((over - 1) >> 31));
    sp_384_norm_15(r);
}

#ifdef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_384_cond_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    int i;

    for (i = 0; i < 15; i++) {
        r[i] = a[i] + (b[i] & m);
    }
}
#endif /* WOLFSSL_SP_SMALL */

#ifndef WOLFSSL_SP_SMALL
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_384_cond_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
    r[ 0] = a[ 0] + (b[ 0] & m);
    r[ 1] = a[ 1] + (b[ 1] & m);
    r[ 2] = a[ 2] + (b[ 2] & m);
    r[ 3] = a[ 3] + (b[ 3] & m);
    r[ 4] = a[ 4] + (b[ 4] & m);
    r[ 5] = a[ 5] + (b[ 5] & m);
    r[ 6] = a[ 6] + (b[ 6] & m);
    r[ 7] = a[ 7] + (b[ 7] & m);
    r[ 8] = a[ 8] + (b[ 8] & m);
    r[ 9] = a[ 9] + (b[ 9] & m);
    r[10] = a[10] + (b[10] & m);
    r[11] = a[11] + (b[11] & m);
    r[12] = a[12] + (b[12] & m);
    r[13] = a[13] + (b[13] & m);
    r[14] = a[14] + (b[14] & m);
}
#endif /* !WOLFSSL_SP_SMALL */

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montgomery form.
 * b   Number to subtract with in Montgomery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_sub_15(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_384_sub_15(r, a, b);
    sp_384_norm_15(r);
    sp_384_cond_add_15(r, r, m, r[14] >> 20);
    sp_384_norm_15(r);
}

/* Shift number left one bit.
 * Bottom bit is lost.
 *
 * r  Result of shift.
 * a  Number to shift.
 */
SP_NOINLINE static void sp_384_rshift1_15(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<14; i++) {
        r[i] = (a[i] >> 1) + (sp_digit)((a[i + 1] << 25) & 0x3ffffff);
    }
#else
    r[0] = (a[0] >> 1) + (sp_digit)((a[1] << 25) & 0x3ffffff);
    r[1] = (a[1] >> 1) + (sp_digit)((a[2] << 25) & 0x3ffffff);
    r[2] = (a[2] >> 1) + (sp_digit)((a[3] << 25) & 0x3ffffff);
    r[3] = (a[3] >> 1) + (sp_digit)((a[4] << 25) & 0x3ffffff);
    r[4] = (a[4] >> 1) + (sp_digit)((a[5] << 25) & 0x3ffffff);
    r[5] = (a[5] >> 1) + (sp_digit)((a[6] << 25) & 0x3ffffff);
    r[6] = (a[6] >> 1) + (sp_digit)((a[7] << 25) & 0x3ffffff);
    r[7] = (a[7] >> 1) + (sp_digit)((a[8] << 25) & 0x3ffffff);
    r[8] = (a[8] >> 1) + (sp_digit)((a[9] << 25) & 0x3ffffff);
    r[9] = (a[9] >> 1) + (sp_digit)((a[10] << 25) & 0x3ffffff);
    r[10] = (a[10] >> 1) + (sp_digit)((a[11] << 25) & 0x3ffffff);
    r[11] = (a[11] >> 1) + (sp_digit)((a[12] << 25) & 0x3ffffff);
    r[12] = (a[12] >> 1) + (sp_digit)((a[13] << 25) & 0x3ffffff);
    r[13] = (a[13] >> 1) + (sp_digit)((a[14] << 25) & 0x3ffffff);
#endif
    r[14] = a[14] >> 1;
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_384_mont_div2_15(sp_digit* r, const sp_digit* a,
        const sp_digit* m)
{
    sp_384_cond_add_15(r, a, m, 0 - (a[0] & 1));
    sp_384_norm_15(r);
    sp_384_rshift1_15(r, r);
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_15(sp_point_384* r, const sp_point_384* p,
    sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*15;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;

    x = r->x;
    y = r->y;
    z = r->z;
    /* Put infinity into result. */
    if (r != p) {
        r->infinity = p->infinity;
    }

    /* T1 = Z * Z */
    sp_384_mont_sqr_15(t1, p->z, p384_mod, p384_mp_mod);
    /* Z = Y * Z */
    sp_384_mont_mul_15(z, p->y, p->z, p384_mod, p384_mp_mod);
    /* Z = 2Z */
    sp_384_mont_dbl_15(z, z, p384_mod);
    /* T2 = X - T1 */
    sp_384_mont_sub_15(t2, p->x, t1, p384_mod);
    /* T1 = X + T1 */
    sp_384_mont_add_15(t1, p->x, t1, p384_mod);
    /* T2 = T1 * T2 */
    sp_384_mont_mul_15(t2, t1, t2, p384_mod, p384_mp_mod);
    /* T1 = 3T2 */
    sp_384_mont_tpl_15(t1, t2, p384_mod);
    /* Y = 2Y */
    sp_384_mont_dbl_15(y, p->y, p384_mod);
    /* Y = Y * Y */
    sp_384_mont_sqr_15(y, y, p384_mod, p384_mp_mod);
    /* T2 = Y * Y */
    sp_384_mont_sqr_15(t2, y, p384_mod, p384_mp_mod);
    /* T2 = T2/2 */
    sp_384_mont_div2_15(t2, t2, p384_mod);
    /* Y = Y * X */
    sp_384_mont_mul_15(y, y, p->x, p384_mod, p384_mp_mod);
    /* X = T1 * T1 */
    sp_384_mont_sqr_15(x, t1, p384_mod, p384_mp_mod);
    /* X = X - Y */
    sp_384_mont_sub_15(x, x, y, p384_mod);
    /* X = X - Y */
    sp_384_mont_sub_15(x, x, y, p384_mod);
    /* Y = Y - X */
    sp_384_mont_sub_15(y, y, x, p384_mod);
    /* Y = Y * T1 */
    sp_384_mont_mul_15(y, y, t1, p384_mod, p384_mp_mod);
    /* Y = Y - T2 */
    sp_384_mont_sub_15(y, y, t2, p384_mod);
}

/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_384_cmp_equal_15(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) |
            (a[3] ^ b[3]) | (a[4] ^ b[4]) | (a[5] ^ b[5]) |
            (a[6] ^ b[6]) | (a[7] ^ b[7]) | (a[8] ^ b[8]) |
            (a[9] ^ b[9]) | (a[10] ^ b[10]) | (a[11] ^ b[11]) |
            (a[12] ^ b[12]) | (a[13] ^ b[13]) | (a[14] ^ b[14])) == 0;
}

/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_384_iszero_15(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7] |
            a[8] | a[9] | a[10] | a[11] | a[12] | a[13] | a[14]) == 0;
}


/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_add_15(sp_point_384* r,
        const sp_point_384* p, const sp_point_384* q, sp_digit* t)
{
    sp_digit* t6 = t;
    sp_digit* t1 = t + 2*15;
    sp_digit* t2 = t + 4*15;
    sp_digit* t3 = t + 6*15;
    sp_digit* t4 = t + 8*15;
    sp_digit* t5 = t + 10*15;

    /* U1 = X1*Z2^2 */
    sp_384_mont_sqr_15(t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t3, t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t1, t1, p->x, p384_mod, p384_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_384_mont_sqr_15(t2, p->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t4, t2, p->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t2, t2, q->x, p384_mod, p384_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_384_mont_mul_15(t3, t3, p->y, p384_mod, p384_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_384_mont_mul_15(t4, t4, q->y, p384_mod, p384_mp_mod);

    /* Check double */
    if ((~p->infinity) & (~q->infinity) &
            sp_384_cmp_equal_15(t2, t1) &
            sp_384_cmp_equal_15(t4, t3)) {
        sp_384_proj_point_dbl_15(r, p, t);
    }
    else {
        sp_digit* x = t6;
        sp_digit* y = t1;
        sp_digit* z = t2;

        /* H = U2 - U1 */
        sp_384_mont_sub_15(t2, t2, t1, p384_mod);
        /* R = S2 - S1 */
        sp_384_mont_sub_15(t4, t4, t3, p384_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_384_mont_sqr_15(t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(y, t1, t5, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(t5, t5, t2, p384_mod, p384_mp_mod);
        /* Z3 = H*Z1*Z2 */
        sp_384_mont_mul_15(z, p->z, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(z, z, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_15(x, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(x, x, t5, p384_mod);
        sp_384_mont_mul_15(t5, t5, t3, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_15(t3, y, p384_mod);
        sp_384_mont_sub_15(x, x, t3, p384_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_384_mont_sub_15(y, y, x, p384_mod);
        sp_384_mont_mul_15(y, y, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(y, y, t5, p384_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 15; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 15; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 15; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}


/* Multiply a number by Montgomery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_384_mod_mul_norm_15(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    SP_DECL_VAR(int64_t, t, 2 * 12);
    int64_t* a32 = NULL;
    int64_t o;
    int err = MP_OKAY;

    (void)m;

    SP_ALLOC_VAR(int64_t, t, 2 * 12, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        a32 = t + 12;

        a32[0] = a[0];
        a32[0] |= (int64_t)a[1] << 26U;
        a32[0] &= 0xffffffffL;
        a32[1] = (a[1] >> 6);
        a32[1] |= (int64_t)a[2] << 20U;
        a32[1] &= 0xffffffffL;
        a32[2] = (a[2] >> 12);
        a32[2] |= (int64_t)a[3] << 14U;
        a32[2] &= 0xffffffffL;
        a32[3] = (a[3] >> 18);
        a32[3] |= (int64_t)a[4] << 8U;
        a32[3] &= 0xffffffffL;
        a32[4] = (a[4] >> 24);
        a32[4] |= (int64_t)a[5] << 2U;
        a32[4] |= (int64_t)a[6] << 28U;
        a32[4] &= 0xffffffffL;
        a32[5] = (a[6] >> 4);
        a32[5] |= (int64_t)a[7] << 22U;
        a32[5] &= 0xffffffffL;
        a32[6] = (a[7] >> 10);
        a32[6] |= (int64_t)a[8] << 16U;
        a32[6] &= 0xffffffffL;
        a32[7] = (a[8] >> 16);
        a32[7] |= (int64_t)a[9] << 10U;
        a32[7] &= 0xffffffffL;
        a32[8] = (a[9] >> 22);
        a32[8] |= (int64_t)a[10] << 4U;
        a32[8] |= (int64_t)a[11] << 30U;
        a32[8] &= 0xffffffffL;
        a32[9] = (a[11] >> 2);
        a32[9] |= (int64_t)a[12] << 24U;
        a32[9] &= 0xffffffffL;
        a32[10] = (a[12] >> 8);
        a32[10] |= (int64_t)a[13] << 18U;
        a32[10] &= 0xffffffffL;
        a32[11] = (a[13] >> 14);
        a32[11] |= (int64_t)a[14] << 12U;
        a32[11] &= 0xffffffffL;

        /*  1  0  0  0  0  0  0  0  1  1  0 -1 */
        t[0] = 0 + a32[0] + a32[8] + a32[9] - a32[11];
        /* -1  1  0  0  0  0  0  0 -1  0  1  1 */
        t[1] = 0 - a32[0] + a32[1] - a32[8] + a32[10] + a32[11];
        /*  0 -1  1  0  0  0  0  0  0 -1  0  1 */
        t[2] = 0 - a32[1] + a32[2] - a32[9] + a32[11];
        /*  1  0 -1  1  0  0  0  0  1  1 -1 -1 */
        t[3] = 0 + a32[0] - a32[2] + a32[3] + a32[8] + a32[9] - a32[10] - a32[11];
        /*  1  1  0 -1  1  0  0  0  1  2  1 -2 */
        t[4] = 0 + a32[0] + a32[1] - a32[3] + a32[4] + a32[8] + 2 * a32[9] + a32[10] -  2 * a32[11];
        /*  0  1  1  0 -1  1  0  0  0  1  2  1 */
        t[5] = 0 + a32[1] + a32[2] - a32[4] + a32[5] + a32[9] + 2 * a32[10] + a32[11];
        /*  0  0  1  1  0 -1  1  0  0  0  1  2 */
        t[6] = 0 + a32[2] + a32[3] - a32[5] + a32[6] + a32[10] + 2 * a32[11];
        /*  0  0  0  1  1  0 -1  1  0  0  0  1 */
        t[7] = 0 + a32[3] + a32[4] - a32[6] + a32[7] + a32[11];
        /*  0  0  0  0  1  1  0 -1  1  0  0  0 */
        t[8] = 0 + a32[4] + a32[5] - a32[7] + a32[8];
        /*  0  0  0  0  0  1  1  0 -1  1  0  0 */
        t[9] = 0 + a32[5] + a32[6] - a32[8] + a32[9];
        /*  0  0  0  0  0  0  1  1  0 -1  1  0 */
        t[10] = 0 + a32[6] + a32[7] - a32[9] + a32[10];
        /*  0  0  0  0  0  0  0  1  1  0 -1  1 */
        t[11] = 0 + a32[7] + a32[8] - a32[10] + a32[11];

        t[1] += t[0] >> 32; t[0] &= 0xffffffff;
        t[2] += t[1] >> 32; t[1] &= 0xffffffff;
        t[3] += t[2] >> 32; t[2] &= 0xffffffff;
        t[4] += t[3] >> 32; t[3] &= 0xffffffff;
        t[5] += t[4] >> 32; t[4] &= 0xffffffff;
        t[6] += t[5] >> 32; t[5] &= 0xffffffff;
        t[7] += t[6] >> 32; t[6] &= 0xffffffff;
        t[8] += t[7] >> 32; t[7] &= 0xffffffff;
        t[9] += t[8] >> 32; t[8] &= 0xffffffff;
        t[10] += t[9] >> 32; t[9] &= 0xffffffff;
        t[11] += t[10] >> 32; t[10] &= 0xffffffff;
        o     = t[11] >> 32; t[11] &= 0xffffffff;
        t[0] += o;
        t[1] -= o;
        t[3] += o;
        t[4] += o;
        t[1] += t[0] >> 32; t[0] &= 0xffffffff;
        t[2] += t[1] >> 32; t[1] &= 0xffffffff;
        t[3] += t[2] >> 32; t[2] &= 0xffffffff;
        t[4] += t[3] >> 32; t[3] &= 0xffffffff;
        t[5] += t[4] >> 32; t[4] &= 0xffffffff;
        t[6] += t[5] >> 32; t[5] &= 0xffffffff;
        t[7] += t[6] >> 32; t[6] &= 0xffffffff;
        t[8] += t[7] >> 32; t[7] &= 0xffffffff;
        t[9] += t[8] >> 32; t[8] &= 0xffffffff;
        t[10] += t[9] >> 32; t[9] &= 0xffffffff;
        t[11] += t[10] >> 32; t[10] &= 0xffffffff;

        r[0] = (sp_digit)(t[0]) & 0x3ffffffL;
        r[1] = (sp_digit)(t[0] >> 26U);
        r[1] |= (sp_digit)(t[1] << 6U);
        r[1] &= 0x3ffffffL;
        r[2] = (sp_digit)(t[1] >> 20U);
        r[2] |= (sp_digit)(t[2] << 12U);
        r[2] &= 0x3ffffffL;
        r[3] = (sp_digit)(t[2] >> 14U);
        r[3] |= (sp_digit)(t[3] << 18U);
        r[3] &= 0x3ffffffL;
        r[4] = (sp_digit)(t[3] >> 8U);
        r[4] |= (sp_digit)(t[4] << 24U);
        r[4] &= 0x3ffffffL;
        r[5] = (sp_digit)(t[4] >> 2U) & 0x3ffffffL;
        r[6] = (sp_digit)(t[4] >> 28U);
        r[6] |= (sp_digit)(t[5] << 4U);
        r[6] &= 0x3ffffffL;
        r[7] = (sp_digit)(t[5] >> 22U);
        r[7] |= (sp_digit)(t[6] << 10U);
        r[7] &= 0x3ffffffL;
        r[8] = (sp_digit)(t[6] >> 16U);
        r[8] |= (sp_digit)(t[7] << 16U);
        r[8] &= 0x3ffffffL;
        r[9] = (sp_digit)(t[7] >> 10U);
        r[9] |= (sp_digit)(t[8] << 22U);
        r[9] &= 0x3ffffffL;
        r[10] = (sp_digit)(t[8] >> 4U) & 0x3ffffffL;
        r[11] = (sp_digit)(t[8] >> 30U);
        r[11] |= (sp_digit)(t[9] << 2U);
        r[11] &= 0x3ffffffL;
        r[12] = (sp_digit)(t[9] >> 24U);
        r[12] |= (sp_digit)(t[10] << 8U);
        r[12] &= 0x3ffffffL;
        r[13] = (sp_digit)(t[10] >> 18U);
        r[13] |= (sp_digit)(t[11] << 14U);
        r[13] &= 0x3ffffffL;
        r[14] = (sp_digit)(t[11] >> 12U);
    }

    SP_FREE_VAR(t, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Small implementation using add and double that is cache attack resistant but
 * allocates memory rather than use large stacks.
 * 384 adds and doubles.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_15(sp_point_384* r, const sp_point_384* g,
        const sp_digit* k, int map, int ct, void* heap)
{
    SP_DECL_VAR(sp_point_384, t, 3);
    SP_DECL_VAR(sp_digit, tmp, 2 * 15 * 6);
    sp_digit n;
    int i;
    int c;
    int y;
    int err = MP_OKAY;

    /* Implementation is constant time. */
    (void)ct;
    (void)heap;

    SP_ALLOC_VAR(sp_point_384, t, 3, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, tmp, 2 * 15 * 6, heap, DYNAMIC_TYPE_ECC);

    if (err == MP_OKAY) {
        XMEMSET(t, 0, sizeof(sp_point_384) * 3);

        /* t[0] = {0, 0, 1} * norm */
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_384_mod_mul_norm_15(t[1].x, g->x, p384_mod);
    }
    if (err == MP_OKAY)
        err = sp_384_mod_mul_norm_15(t[1].y, g->y, p384_mod);
    if (err == MP_OKAY)
        err = sp_384_mod_mul_norm_15(t[1].z, g->z, p384_mod);

    if (err == MP_OKAY) {
        i = 14;
        c = 20;
        n = k[i--] << (26 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 26;
            }

            y = (n >> 25) & 1;
            n <<= 1;

            sp_384_proj_point_add_15(&t[y^1], &t[0], &t[1], tmp);

            XMEMCPY(&t[2], (void*)(((size_t)&t[0] & addr_mask[y^1]) +
                                   ((size_t)&t[1] & addr_mask[y])),
                    sizeof(sp_point_384));
            sp_384_proj_point_dbl_15(&t[2], &t[2], tmp);
            XMEMCPY((void*)(((size_t)&t[0] & addr_mask[y^1]) +
                            ((size_t)&t[1] & addr_mask[y])), &t[2],
                    sizeof(sp_point_384));
        }

        if (map != 0) {
            sp_384_map_15(r, &t[0], tmp);
        }
        else {
            XMEMCPY(r, &t[0], sizeof(sp_point_384));
        }
    }

    SP_ZEROFREE_VAR(sp_digit, tmp, 2 * 15 * 6, heap, DYNAMIC_TYPE_ECC);
    SP_ZEROFREE_VAR(sp_point_384, t, 3, heap, DYNAMIC_TYPE_ECC);

    return err;
}


#else
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_384 {
    sp_digit x[15];
    sp_digit y[15];
} sp_table_entry_384;

/* Conditionally copy a into r using the mask m.
 * m is -1 to copy and 0 when not.
 *
 * r  A single precision number to copy over.
 * a  A single precision number to copy.
 * m  Mask value to apply.
 */
static void sp_384_cond_copy_15(sp_digit* r, const sp_digit* a, const sp_digit m)
{
    sp_digit t[15];
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 15; i++) {
        t[i] = r[i] ^ a[i];
    }
    for (i = 0; i < 15; i++) {
        r[i] ^= t[i] & m;
    }
#else
    t[ 0] = r[ 0] ^ a[ 0];
    t[ 1] = r[ 1] ^ a[ 1];
    t[ 2] = r[ 2] ^ a[ 2];
    t[ 3] = r[ 3] ^ a[ 3];
    t[ 4] = r[ 4] ^ a[ 4];
    t[ 5] = r[ 5] ^ a[ 5];
    t[ 6] = r[ 6] ^ a[ 6];
    t[ 7] = r[ 7] ^ a[ 7];
    t[ 8] = r[ 8] ^ a[ 8];
    t[ 9] = r[ 9] ^ a[ 9];
    t[10] = r[10] ^ a[10];
    t[11] = r[11] ^ a[11];
    t[12] = r[12] ^ a[12];
    t[13] = r[13] ^ a[13];
    t[14] = r[14] ^ a[14];
    r[ 0] ^= t[ 0] & m;
    r[ 1] ^= t[ 1] & m;
    r[ 2] ^= t[ 2] & m;
    r[ 3] ^= t[ 3] & m;
    r[ 4] ^= t[ 4] & m;
    r[ 5] ^= t[ 5] & m;
    r[ 6] ^= t[ 6] & m;
    r[ 7] ^= t[ 7] & m;
    r[ 8] ^= t[ 8] & m;
    r[ 9] ^= t[ 9] & m;
    r[10] ^= t[10] & m;
    r[11] ^= t[11] & m;
    r[12] ^= t[12] & m;
    r[13] ^= t[13] & m;
    r[14] ^= t[14] & m;
#endif /* WOLFSSL_SP_SMALL */
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_15(sp_point_384* p, int i,
    sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*15;
    sp_digit* b = t + 4*15;
    sp_digit* t1 = t + 6*15;
    sp_digit* t2 = t + 8*15;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    volatile int n = i - 1;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_384_mont_dbl_15(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_15(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_15(w, w, p384_mod, p384_mp_mod);
#ifndef WOLFSSL_SP_SMALL
    while (n > 0)
#else
    while (n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_15(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(t1, t1, w, p384_mod);
        sp_384_mont_tpl_15(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_15(t1, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(b, t1, x, p384_mod, p384_mp_mod);
        /* X = A^2 - 2B */
        sp_384_mont_sqr_15(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_15(t2, b, p384_mod);
        sp_384_mont_sub_15(x, x, t2, p384_mod);
        /* B = 2.(B - X) */
        sp_384_mont_sub_15(t2, b, x, p384_mod);
        sp_384_mont_dbl_15(b, t2, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_15(z, z, y, p384_mod, p384_mp_mod);
        /* t1 = Y^4 */
        sp_384_mont_sqr_15(t1, t1, p384_mod, p384_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_384_mont_mul_15(w, w, t1, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_mul_15(y, b, a, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(y, y, t1, p384_mod);
        n = n - 1;
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_384_mont_sqr_15(t1, x, p384_mod, p384_mp_mod);
    sp_384_mont_sub_15(t1, t1, w, p384_mod);
    sp_384_mont_tpl_15(a, t1, p384_mod);
    /* B = X*Y^2 */
    sp_384_mont_sqr_15(t1, y, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(b, t1, x, p384_mod, p384_mp_mod);
    /* X = A^2 - 2B */
    sp_384_mont_sqr_15(x, a, p384_mod, p384_mp_mod);
    sp_384_mont_dbl_15(t2, b, p384_mod);
    sp_384_mont_sub_15(x, x, t2, p384_mod);
    /* B = 2.(B - X) */
    sp_384_mont_sub_15(t2, b, x, p384_mod);
    sp_384_mont_dbl_15(b, t2, p384_mod);
    /* Z = Z*Y */
    sp_384_mont_mul_15(z, z, y, p384_mod, p384_mp_mod);
    /* t1 = Y^4 */
    sp_384_mont_sqr_15(t1, t1, p384_mod, p384_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_384_mont_mul_15(y, b, a, p384_mod, p384_mp_mod);
    sp_384_mont_sub_15(y, y, t1, p384_mod);
#endif /* WOLFSSL_SP_SMALL */
    /* Y = Y/2 */
    sp_384_mont_div2_15(y, y, p384_mod);
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_store_15(sp_point_384* r,
        const sp_point_384* p, int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*15;
    sp_digit* b = t + 4*15;
    sp_digit* t1 = t + 6*15;
    sp_digit* t2 = t + 8*15;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;
    int j;

    for (i=0; i<15; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<15; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<15; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_384_mont_dbl_15(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_15(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_15(w, w, p384_mod, p384_mp_mod);
    j = m;
    for (i=1; i<=n; i++) {
        j *= 2;

        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_15(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(t1, t1, w, p384_mod);
        sp_384_mont_tpl_15(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_15(t1, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(b, t1, x, p384_mod, p384_mp_mod);
        x = r[j].x;
        /* X = A^2 - 2B */
        sp_384_mont_sqr_15(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_15(t2, b, p384_mod);
        sp_384_mont_sub_15(x, x, t2, p384_mod);
        /* B = 2.(B - X) */
        sp_384_mont_sub_15(t2, b, x, p384_mod);
        sp_384_mont_dbl_15(b, t2, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_15(r[j].z, z, y, p384_mod, p384_mp_mod);
        z = r[j].z;
        /* t1 = Y^4 */
        sp_384_mont_sqr_15(t1, t1, p384_mod, p384_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_384_mont_mul_15(w, w, t1, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_mul_15(y, b, a, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(y, y, t1, p384_mod);
        /* Y = Y/2 */
        sp_384_mont_div2_15(r[j].y, y, p384_mod);
        r[j].infinity = 0;
    }
}

/* Add two Montgomery form projective points.
 *
 * ra  Result of addition.
 * rs  Result of subtraction.
 * p   First point to add.
 * q   Second point to add.
 * t   Temporary ordinate data.
 */
static void sp_384_proj_point_add_sub_15(sp_point_384* ra,
        sp_point_384* rs, const sp_point_384* p, const sp_point_384* q,
        sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*15;
    sp_digit* t3 = t + 4*15;
    sp_digit* t4 = t + 6*15;
    sp_digit* t5 = t + 8*15;
    sp_digit* t6 = t + 10*15;
    sp_digit* xa = ra->x;
    sp_digit* ya = ra->y;
    sp_digit* za = ra->z;
    sp_digit* xs = rs->x;
    sp_digit* ys = rs->y;
    sp_digit* zs = rs->z;


    XMEMCPY(xa, p->x, sizeof(p->x) / 2);
    XMEMCPY(ya, p->y, sizeof(p->y) / 2);
    XMEMCPY(za, p->z, sizeof(p->z) / 2);
    ra->infinity = 0;
    rs->infinity = 0;

    /* U1 = X1*Z2^2 */
    sp_384_mont_sqr_15(t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t3, t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t1, t1, xa, p384_mod, p384_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_384_mont_sqr_15(t2, za, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t4, t2, za, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t2, t2, q->x, p384_mod, p384_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_384_mont_mul_15(t3, t3, ya, p384_mod, p384_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_384_mont_mul_15(t4, t4, q->y, p384_mod, p384_mp_mod);
    /* H = U2 - U1 */
    sp_384_mont_sub_15(t2, t2, t1, p384_mod);
    /* RS = S2 + S1 */
    sp_384_mont_add_15(t6, t4, t3, p384_mod);
    /* R = S2 - S1 */
    sp_384_mont_sub_15(t4, t4, t3, p384_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_384_mont_mul_15(za, za, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(za, za, t2, p384_mod, p384_mp_mod);
    XMEMCPY(zs, za, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_384_mont_sqr_15(xa, t4, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_15(xs, t6, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_15(t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(ya, t1, t5, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t5, t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_sub_15(xa, xa, t5, p384_mod);
    sp_384_mont_sub_15(xs, xs, t5, p384_mod);
    sp_384_mont_dbl_15(t1, ya, p384_mod);
    sp_384_mont_sub_15(xa, xa, t1, p384_mod);
    sp_384_mont_sub_15(xs, xs, t1, p384_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_384_mont_sub_15(ys, ya, xs, p384_mod);
    sp_384_mont_sub_15(ya, ya, xa, p384_mod);
    sp_384_mont_mul_15(ya, ya, t4, p384_mod, p384_mp_mod);
    sp_384_sub_15(t6, p384_mod, t6);
    sp_384_mont_mul_15(ys, ys, t6, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t5, t5, t3, p384_mod, p384_mp_mod);
    sp_384_mont_sub_15(ya, ya, t5, p384_mod);
    sp_384_mont_sub_15(ys, ys, t5, p384_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_384 {
    /* Index into pre-computation table. */
    word8 i;
    /* Use the negative of the point. */
    word8 neg;
} ecc_recode_384;

/* The index into pre-computation table to use. */
static const word8 recode_index_15_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const word8 recode_neg_15_6[66] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     0,  0,
};

/* Recode the scalar for multiplication using pre-computed values and
 * subtraction.
 *
 * k  Scalar to multiply by.
 * v  Vector of operations to perform.
 */
static void sp_384_ecc_recode_6_15(const sp_digit* k, ecc_recode_384* v)
{
    int i;
    int j;
    word8 y;
    int carry = 0;
    int o;
    sp_digit n;

    j = 0;
    n = k[j];
    o = 0;
    for (i=0; i<65; i++) {
        y = (word8)(int8_t)n;
        if (o + 6 < 26) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 26) {
            n >>= 6;
            if (++j < 15)
                n = k[j];
            o = 0;
        }
        else if (++j < 15) {
            n = k[j];
            y |= (word8)((n << (26 - o)) & 0x3f);
            o -= 20;
            n >>= o;
        }

        y = (word8)(y + carry);
        v[i].i = recode_index_15_6[y];
        v[i].neg = recode_neg_15_6[y];
        carry = (y >> 6) + v[i].neg;
    }
}

/* Touch each possible point that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entries to access
 * idx    Index of entry to retrieve.
 */
static void sp_384_get_point_33_15(sp_point_384* r, const sp_point_384* table,
    int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->x[7] = 0;
    r->x[8] = 0;
    r->x[9] = 0;
    r->x[10] = 0;
    r->x[11] = 0;
    r->x[12] = 0;
    r->x[13] = 0;
    r->x[14] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    r->y[8] = 0;
    r->y[9] = 0;
    r->y[10] = 0;
    r->y[11] = 0;
    r->y[12] = 0;
    r->y[13] = 0;
    r->y[14] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    r->z[5] = 0;
    r->z[6] = 0;
    r->z[7] = 0;
    r->z[8] = 0;
    r->z[9] = 0;
    r->z[10] = 0;
    r->z[11] = 0;
    r->z[12] = 0;
    r->z[13] = 0;
    r->z[14] = 0;
    for (i = 1; i < 33; i++) {
        mask = (sp_digit)0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->x[8] |= mask & table[i].x[8];
        r->x[9] |= mask & table[i].x[9];
        r->x[10] |= mask & table[i].x[10];
        r->x[11] |= mask & table[i].x[11];
        r->x[12] |= mask & table[i].x[12];
        r->x[13] |= mask & table[i].x[13];
        r->x[14] |= mask & table[i].x[14];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
        r->y[8] |= mask & table[i].y[8];
        r->y[9] |= mask & table[i].y[9];
        r->y[10] |= mask & table[i].y[10];
        r->y[11] |= mask & table[i].y[11];
        r->y[12] |= mask & table[i].y[12];
        r->y[13] |= mask & table[i].y[13];
        r->y[14] |= mask & table[i].y[14];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
        r->z[5] |= mask & table[i].z[5];
        r->z[6] |= mask & table[i].z[6];
        r->z[7] |= mask & table[i].z[7];
        r->z[8] |= mask & table[i].z[8];
        r->z[9] |= mask & table[i].z[9];
        r->z[10] |= mask & table[i].z[10];
        r->z[11] |= mask & table[i].z[11];
        r->z[12] |= mask & table[i].z[12];
        r->z[13] |= mask & table[i].z[13];
        r->z[14] |= mask & table[i].z[14];
    }
}
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Window technique of 6 bits. (Add-Sub variation.)
 * Calculate 0..32 times the point. Use function that adds and
 * subtracts the same two points.
 * Recode to add or subtract one of the computed points.
 * Double to push up.
 * NOT a sliding window.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_win_add_sub_15(sp_point_384* r, const sp_point_384* g,
        const sp_digit* k, int map, int ct, void* heap)
{
    SP_DECL_VAR(sp_point_384, t, 33+2);
    SP_DECL_VAR(sp_digit, tmp, 2 * 15 * 6);
    sp_point_384* rt = NULL;
    sp_point_384* p = NULL;
    sp_digit* negy;
    int i;
    ecc_recode_384 v[65];
    int err = MP_OKAY;

    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;

    SP_ALLOC_VAR(sp_point_384, t, 33+2, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, tmp, 2 * 15 * 6, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        rt = t + 33;
        p  = t + 33+1;

        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_384_mod_mul_norm_15(t[1].x, g->x, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_15(t[1].y, g->y, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_15(t[1].z, g->z, p384_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_384_proj_point_dbl_n_store_15(t, &t[ 1], 5, 1, tmp);
        sp_384_proj_point_add_15(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[ 6], &t[ 3], tmp);
        sp_384_proj_point_add_sub_15(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[10], &t[ 5], tmp);
        sp_384_proj_point_add_sub_15(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[12], &t[ 6], tmp);
        sp_384_proj_point_dbl_15(&t[14], &t[ 7], tmp);
        sp_384_proj_point_add_sub_15(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[18], &t[ 9], tmp);
        sp_384_proj_point_add_sub_15(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[20], &t[10], tmp);
        sp_384_proj_point_dbl_15(&t[22], &t[11], tmp);
        sp_384_proj_point_add_sub_15(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[24], &t[12], tmp);
        sp_384_proj_point_dbl_15(&t[26], &t[13], tmp);
        sp_384_proj_point_add_sub_15(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_384_proj_point_dbl_15(&t[28], &t[14], tmp);
        sp_384_proj_point_dbl_15(&t[30], &t[15], tmp);
        sp_384_proj_point_add_sub_15(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_384_ecc_recode_6_15(k, v);

        i = 64;
        if (ct) {
            sp_384_get_point_33_15(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_384));
        }
        for (--i; i>=0; i--) {
            sp_384_proj_point_dbl_n_15(rt, 6, tmp);

            if (ct) {
                sp_384_get_point_33_15(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_384));
            }
            sp_384_sub_15(negy, p384_mod, p->y);
            sp_384_norm_15(negy);
            sp_384_cond_copy_15(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_384_proj_point_add_15(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_384_map_15(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_384));
        }
    }

    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(tmp, heap, DYNAMIC_TYPE_ECC);

    return err;
}

/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_add_qz1_15(sp_point_384* r,
    const sp_point_384* p, const sp_point_384* q, sp_digit* t)
{
    sp_digit* t2 = t;
    sp_digit* t3 = t + 2*15;
    sp_digit* t6 = t + 4*15;
    sp_digit* t1 = t + 6*15;
    sp_digit* t4 = t + 8*15;
    sp_digit* t5 = t + 10*15;

    /* Calculate values to subtract from P->x and P->y. */
    /* U2 = X2*Z1^2 */
    sp_384_mont_sqr_15(t2, p->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t4, t2, p->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_15(t2, t2, q->x, p384_mod, p384_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_384_mont_mul_15(t4, t4, q->y, p384_mod, p384_mp_mod);

    if ((~p->infinity) & (~q->infinity) &
            sp_384_cmp_equal_15(p->x, t2) &
            sp_384_cmp_equal_15(p->y, t4)) {
        sp_384_proj_point_dbl_15(r, p, t);
    }
    else {
        sp_digit* x = t2;
        sp_digit* y = t3;
        sp_digit* z = t6;

        /* H = U2 - X1 */
        sp_384_mont_sub_15(t2, t2, p->x, p384_mod);
        /* R = S2 - Y1 */
        sp_384_mont_sub_15(t4, t4, p->y, p384_mod);
        /* Z3 = H*Z1 */
        sp_384_mont_mul_15(z, p->z, t2, p384_mod, p384_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_384_mont_sqr_15(t1, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(t3, p->x, t1, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(t1, t1, t2, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_15(t2, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(t2, t2, t1, p384_mod);
        sp_384_mont_dbl_15(t5, t3, p384_mod);
        sp_384_mont_sub_15(x, t2, t5, p384_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_384_mont_sub_15(t3, t3, x, p384_mod);
        sp_384_mont_mul_15(t3, t3, t4, p384_mod, p384_mp_mod);
        sp_384_mont_mul_15(t1, t1, p->y, p384_mod, p384_mp_mod);
        sp_384_mont_sub_15(y, t3, t1, p384_mod);
        {
            int i;
            sp_digit maskp = (sp_digit)(0 - (q->infinity & (!p->infinity)));
            sp_digit maskq = (sp_digit)(0 - (p->infinity & (!q->infinity)));
            sp_digit maskt = ~(maskp | maskq);
            sp_digit inf = (sp_digit)(p->infinity & q->infinity);

            for (i = 0; i < 15; i++) {
                r->x[i] = (p->x[i] & maskp) | (q->x[i] & maskq) |
                          (x[i] & maskt);
            }
            for (i = 0; i < 15; i++) {
                r->y[i] = (p->y[i] & maskp) | (q->y[i] & maskq) |
                          (y[i] & maskt);
            }
            for (i = 0; i < 15; i++) {
                r->z[i] = (p->z[i] & maskp) | (q->z[i] & maskq) |
                          (z[i] & maskt);
            }
            r->z[0] |= inf;
            r->infinity = (int)inf;
        }
    }
}

/* Touch each possible entry that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entries to access
 * idx    Index of entry to retrieve.
 */
static void sp_384_get_entry_256_15(sp_point_384* r,
    const sp_table_entry_384* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->x[7] = 0;
    r->x[8] = 0;
    r->x[9] = 0;
    r->x[10] = 0;
    r->x[11] = 0;
    r->x[12] = 0;
    r->x[13] = 0;
    r->x[14] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->y[7] = 0;
    r->y[8] = 0;
    r->y[9] = 0;
    r->y[10] = 0;
    r->y[11] = 0;
    r->y[12] = 0;
    r->y[13] = 0;
    r->y[14] = 0;
    for (i = 1; i < 256; i++) {
        sp_digit gte = (sp_digit)((((sp_uint32)i - (sp_uint32)idx) >> 31) - 1);
        sp_digit lte = (sp_digit)((((sp_uint32)idx - (sp_uint32)i) >> 31) - 1);
        mask = gte & lte;
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->x[7] |= mask & table[i].x[7];
        r->x[8] |= mask & table[i].x[8];
        r->x[9] |= mask & table[i].x[9];
        r->x[10] |= mask & table[i].x[10];
        r->x[11] |= mask & table[i].x[11];
        r->x[12] |= mask & table[i].x[12];
        r->x[13] |= mask & table[i].x[13];
        r->x[14] |= mask & table[i].x[14];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->y[7] |= mask & table[i].y[7];
        r->y[8] |= mask & table[i].y[8];
        r->y[9] |= mask & table[i].y[9];
        r->y[10] |= mask & table[i].y[10];
        r->y[11] |= mask & table[i].y[11];
        r->y[12] |= mask & table[i].y[12];
        r->y[13] |= mask & table[i].y[13];
        r->y[14] |= mask & table[i].y[14];
    }
}
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^48, ...
 * Pre-generated: products of all combinations of above.
 * 8 doubles and adds (with qz=1)
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_stripe_15(sp_point_384* r, const sp_point_384* g,
        const sp_table_entry_384* table, const sp_digit* k, int map,
        int ct, void* heap)
{
    SP_DECL_VAR(sp_point_384, rt, 2);
    SP_DECL_VAR(sp_digit, t, 2 * 15 * 6);
    sp_point_384* p = NULL;
    int i;
    int j;
    int y;
    int x;
    int err = MP_OKAY;

    (void)g;
    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;


    SP_ALLOC_VAR(sp_point_384, rt, 2, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, t, 2 * 15 * 6, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        p = rt + 1;

        XMEMCPY(p->z, p384_norm_mod, sizeof(p384_norm_mod));
        XMEMCPY(rt->z, p384_norm_mod, sizeof(p384_norm_mod));

        y = 0;
        x = 47;
        for (j=0; j<8; j++) {
            y |= (int)(((k[x / 26] >> (x % 26)) & 1) << j);
            x += 48;
        }
        if (ct) {
            sp_384_get_entry_256_15(rt, table, y);
        } else
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=46; i>=0; i--) {
            y = 0;
            x = i;
            for (j=0; j<8; j++) {
                y |= (int)(((k[x / 26] >> (x % 26)) & 1) << j);
                x += 48;
            }

            sp_384_proj_point_dbl_15(rt, rt, t);
            if (ct) {
                sp_384_get_entry_256_15(p, table, y);
            }
            else
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_384_proj_point_add_qz1_15(rt, rt, p, t);
        }

        if (map != 0) {
            sp_384_map_15(r, rt, t);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_384));
        }
    }

    SP_FREE_VAR(rt, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(t, heap, DYNAMIC_TYPE_ECC);

    return err;
}


/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_15(sp_point_384* r, const sp_point_384* g,
        const sp_digit* k, int map, int ct, void* heap)
{
    return sp_384_ecc_mulmod_win_add_sub_15(r, g, k, map, ct, heap);
}

#endif
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * p     Point to multiply.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */

/* Multiply the point by the scalar, add point a and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km      Scalar to multiply by.
 * p       Point to multiply.
 * am      Point to add to scalar multiply result.
 * inMont  Point to add is in montgomery form.
 * r       Resulting point.
 * map     Indicates whether to convert result to affine.
 * heap    Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */

#ifdef WOLFSSL_SP_SMALL
/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_base_15(sp_point_384* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_384_ecc_mulmod_15(r, &p384_base, k, map, ct, heap);
}



#else
/* Striping precomputation table.
 * 8 points combined into a table of 256 points.
 * Distance of 48 between points.
 */
static const sp_table_entry_384 p384_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x1c0b528,0x01d5992,0x0e383dd,0x38a835b,0x220e378,0x106d35b,
        0x1c3afc5,0x03bfe1e,0x28459a3,0x2d91521,0x214ede2,0x0bfdc8d,
        0x2151381,0x3708a67,0x004d3aa },
      { 0x303a4fe,0x10f6b52,0x29ac230,0x2fdeed2,0x0a1bfa8,0x3a0ec14,
        0x2de7562,0x3ff662e,0x21968f4,0x031b0d4,0x3969a84,0x2000898,
        0x1c5e9dd,0x2f09685,0x002b78a } },
    /* 2 */
    { { 0x30c535b,0x191d4ca,0x2296298,0x14dc141,0x090dd69,0x05aae6b,
        0x0cd6b42,0x35da80e,0x3b7be12,0x2cf7e6d,0x1f347bd,0x3d365e1,
        0x1448913,0x32704fa,0x00222c5 },
      { 0x280dc64,0x39e5bc9,0x24175f8,0x2dd60d4,0x0120e7c,0x041d02e,
        0x0b5d8ad,0x37b9895,0x2fb5337,0x1f0e2e3,0x14f0224,0x2230b86,
        0x1bc4cf6,0x17cdb09,0x007b5c7 } },
    /* 3 */
    { { 0x2dffea5,0x28f30e7,0x29fce26,0x070df5f,0x235bbfd,0x2f78fbd,
        0x27700d9,0x23d6bc3,0x3471a53,0x0c0e03a,0x05bf9eb,0x276a2ec,
        0x20c3e2e,0x31cc691,0x00dbb93 },
      { 0x126b605,0x2e8983d,0x153737d,0x23bf5e1,0x295d497,0x35ca812,
        0x2d793ae,0x16c6893,0x3777600,0x089a520,0x1e681f8,0x3d55ee6,
        0x154ef99,0x155f592,0x00ae5f9 } },
    /* 4 */
    { { 0x26feef9,0x20315fc,0x1240244,0x250e838,0x3c31a26,0x1cf8af1,
        0x1002c32,0x3b531cd,0x1c53ef1,0x22310ba,0x3f4948e,0x22eafd9,
        0x3863202,0x3d0e2a5,0x006a502 },
      { 0x34536fe,0x04e91ad,0x30ebf5f,0x2af62a7,0x01d218b,0x1c8c9da,
        0x336bcc3,0x23060c3,0x331576e,0x1b14c5e,0x1bbcb76,0x0755e9a,
        0x3d4dcef,0x24c2cf8,0x00917c4 } },
    /* 5 */
    { { 0x349ddd0,0x09b8bb8,0x0250114,0x3e66cbf,0x29f117e,0x3005d29,
        0x36b480e,0x2119bfc,0x2761845,0x253d2f7,0x0580604,0x0bb6db4,
        0x3ca922f,0x1744677,0x008adc7 },
      { 0x3d5a7ce,0x27425ed,0x11e9a61,0x3968d10,0x3874275,0x3692d3b,
        0x03e0470,0x0763d50,0x3d97790,0x3cbaeab,0x2747170,0x18faf3a,
        0x180365e,0x2511fe7,0x0012a36 } },
    /* 6 */
    { { 0x3c52870,0x2701e93,0x296128f,0x120694e,0x1ce0b37,0x3860a36,
        0x10fa180,0x0896b55,0x2f76adb,0x22892ae,0x2e58a34,0x07b4295,
        0x2cb62d1,0x079a522,0x00f3d81 },
      { 0x061ed22,0x2375dd3,0x3c9d861,0x3e602d1,0x10bb747,0x39ae156,
        0x3f796fd,0x087a48a,0x06d680a,0x37f7f47,0x2af2c9d,0x36c55dc,
        0x10f3dc0,0x279b07a,0x00a0937 } },
    /* 7 */
    { { 0x085c629,0x319bbf8,0x089a386,0x184256f,0x15fc2a4,0x00fd2d0,
        0x13d6312,0x363d44d,0x32b7e4b,0x25f2865,0x27df8ce,0x1dce02a,
        0x24ea3b0,0x0e27b9f,0x00d8a90 },
      { 0x3b14461,0x1d371f9,0x0f781bc,0x0503271,0x0dc2cb0,0x13bc284,
        0x34b3a68,0x1ff894a,0x25d2032,0x16f79ba,0x260f961,0x07b10d5,
        0x18173b7,0x2812e2b,0x00eede5 } },
    /* 8 */
    { { 0x13b9a2d,0x132ece2,0x0c5d558,0x02c0214,0x1820c66,0x37cb50f,
        0x26d8267,0x3a00504,0x3f00109,0x33756ee,0x38172f1,0x2e4bb8c,
        0x030d985,0x3e4fcc5,0x00609d4 },
      { 0x2daf9d6,0x16681fa,0x1fb01e0,0x1b03c49,0x370e653,0x183c839,
        0x2207515,0x0ea6b58,0x1ae7aaf,0x3a96522,0x24bae14,0x1c38bd9,
        0x082497b,0x1c05db4,0x000dd03 } },
    /* 9 */
    { { 0x110521f,0x04efa21,0x0c174cc,0x2a7dc93,0x387315b,0x14f7098,
        0x1d83bb3,0x2495ed2,0x2fe0c27,0x1e2d9df,0x093c953,0x0287073,
        0x02c9951,0x336291c,0x0033e30 },
      { 0x208353f,0x3f22748,0x2b2bf0f,0x2373b50,0x10170fa,0x1b8a97d,
        0x0851ed2,0x0b25824,0x055ecb5,0x12049d9,0x3fe1adf,0x11b1385,
        0x28eab06,0x11fac21,0x00513f0 } },
    /* 10 */
    { { 0x35bdf53,0x1847d37,0x1a6dc07,0x29d62c4,0x045d331,0x313b8e5,
        0x165daf1,0x1e34562,0x3e75a58,0x16ea2fa,0x02dd302,0x3302862,
        0x3eb8bae,0x2266a48,0x00cf2a3 },
      { 0x24fd048,0x324a074,0x025df98,0x1662eec,0x3841bfb,0x26ae754,
        0x1df8cec,0x0113ae3,0x0b67fef,0x094e293,0x2323666,0x0ab087c,
        0x2f06509,0x0e142d9,0x00a919d } },
    /* 11 */
    { { 0x1d480d8,0x00ed021,0x3a7d3db,0x1e46ca1,0x28cd9f4,0x2a3ceeb,
        0x24dc754,0x0624a3c,0x0003db4,0x1520bae,0x1c56e0f,0x2fe7ace,
        0x1dc6f38,0x0c826a4,0x008b977 },
      { 0x209cfc2,0x2c16c9c,0x1b70a31,0x21416cb,0x34c49bf,0x186549e,
        0x062498d,0x146e959,0x0391fac,0x08ff944,0x2b4b834,0x013d57a,
        0x2eabffb,0x0370131,0x00c07c1 } },
    /* 12 */
    { { 0x332f048,0x0bf9336,0x16dfad2,0x2451d7b,0x35f23bf,0x299adb2,
        0x0ce0c0a,0x0170294,0x289f034,0x2b7d89e,0x395e2d6,0x1d20df7,
        0x2e64e36,0x16dae90,0x00081c9 },
      { 0x31d6ceb,0x0f80db9,0x0271eba,0x33db1ac,0x1b45bcc,0x1a11c07,
        0x347e630,0x148fd9e,0x142e712,0x3183e3e,0x1cd47ad,0x108d1c9,
        0x09cbb82,0x35e61d9,0x0083027 } },
    /* 13 */
    { { 0x215b0b8,0x0a7a98d,0x2c41b39,0x3f69536,0x0b41441,0x16da8da,
        0x15d556b,0x3c17a26,0x129167e,0x3ea0351,0x2d25a27,0x2f2d285,
        0x15b68f6,0x2931ef5,0x00210d6 },
      { 0x1351130,0x012aec9,0x37ebf38,0x26640f8,0x01d2df6,0x2130972,
        0x201efc0,0x23a457c,0x087a1c6,0x14c68a3,0x163f62a,0x36b494d,
        0x015d481,0x39c35b1,0x005dd6d } },
    /* 14 */
    { { 0x06612ce,0x11c3f61,0x199729f,0x3b36863,0x2986f3e,0x3cd2be1,
        0x04c1612,0x2be2dae,0x00846dd,0x3d7bc29,0x249e795,0x1016803,
        0x37a3714,0x2c5aa8b,0x005f491 },
      { 0x341b38d,0x01eb936,0x3caac7f,0x27863ef,0x1ef7d11,0x1110ec6,
        0x18e0761,0x26498e8,0x01a79a1,0x390d5a1,0x22226fb,0x3d2a473,
        0x0872191,0x1230f32,0x00dc772 } },
    /* 15 */
    { { 0x0b1ec9d,0x03fc6b9,0x3706d57,0x03b9fbb,0x221d23e,0x2867821,
        0x1e40f4c,0x2c9c0f3,0x3c4cd4b,0x31f5948,0x3f13aa6,0x307c1b2,
        0x04b6016,0x116b453,0x005aa72 },
      { 0x0b74de8,0x20519d1,0x134e37f,0x05d882a,0x1839e7a,0x3a2c6a8,
        0x0d14e8d,0x1d78bdd,0x251f30d,0x3a1e27e,0x081c261,0x2c9014b,
        0x165ee09,0x19e0cf1,0x00654e2 } },
    /* 16 */
    { { 0x39fbe67,0x081778b,0x0e44378,0x20dfdca,0x1c4afcb,0x20b803c,
        0x0ec06c6,0x1508f6f,0x1c3114d,0x3bca851,0x3a52463,0x07661d1,
        0x17b0aa0,0x16c5f5c,0x00fc093 },
      { 0x0d01f95,0x0ef13f5,0x2d34965,0x2a25582,0x39aa83e,0x3e38fcf,
        0x3943dca,0x385bbdd,0x210e86f,0x3dc1dd2,0x3f9ffdc,0x18b9bc6,
        0x345c96b,0x0e79621,0x008a72f } },
    /* 17 */
    { { 0x341c342,0x3793688,0x042273a,0x153a9c1,0x3dd326e,0x1d073bc,
        0x2c7d983,0x05524cd,0x00d59e6,0x347abe8,0x3d9a3ef,0x0fb624a,
        0x2c7e4cd,0x09b3171,0x0003faf },
      { 0x045f8ac,0x38bf3cc,0x1e73087,0x0c85d3c,0x314a655,0x382be69,
        0x384f28f,0x24d6cb3,0x2842cdc,0x1777f5e,0x2929c89,0x03c45ed,
        0x3cfcc4c,0x0b59322,0x0035657 } },
    /* 18 */
    { { 0x18c1bba,0x2eb005f,0x33d57ec,0x30e42c3,0x36058f9,0x1865f43,
        0x2116e3f,0x2c4a2bb,0x0684033,0x0f1375c,0x0209b98,0x2136e9b,
        0x1bc4af0,0x0b3e0c7,0x0097c7c },
      { 0x16010e8,0x398777e,0x2a172f4,0x0814a7e,0x0d97e4e,0x274dfc8,
        0x2666606,0x1b5c93b,0x1ed3d36,0x3f3304e,0x13488e0,0x02dbb88,
        0x2d53369,0x3717ce9,0x007cad1 } },
    /* 19 */
    { { 0x257a41f,0x2a6a076,0x39b6660,0x04bb000,0x1e74a04,0x3876b45,
        0x343c6b5,0x0753108,0x3f54668,0x24a13cf,0x23749e8,0x0421fc5,
        0x32f13b5,0x0f31be7,0x00070f2 },
      { 0x1186e14,0x0847697,0x0dff542,0x0dff76c,0x084748f,0x2c7d060,
        0x23aab4d,0x0b43906,0x27ba640,0x1497b59,0x02f5835,0x0a492a4,
        0x0a6892f,0x39f3e91,0x005844e } },
    /* 20 */
    { { 0x33b236f,0x02181cf,0x21dafab,0x0760788,0x019e9d4,0x249ed0a,
        0x36571e3,0x3c7dbcf,0x1337550,0x010d22a,0x285e62f,0x19ee65a,
        0x052bf71,0x1d65fd5,0x0062d43 },
      { 0x2955926,0x3fae7bc,0x0353d85,0x07db7de,0x1440a56,0x328dad6,
        0x1668ec9,0x28058e2,0x1a1a22d,0x1014afc,0x3609325,0x3effdcb,
        0x209f3bd,0x3ca3888,0x0094e50 } },
    /* 21 */
    { { 0x062e8af,0x0b96ccc,0x136990b,0x1d7a28f,0x1a85723,0x0076dec,
        0x21b00b2,0x06a88ff,0x2f0ee65,0x1fa49b7,0x39b10ad,0x10b26fa,
        0x0be7465,0x026e8bf,0x00098e3 },
      { 0x3f1d63f,0x37bacff,0x1374779,0x02882ff,0x323d0e8,0x1da3de5,
        0x12bb3b8,0x0a15a11,0x34d1f95,0x2b3dd6e,0x29ea3fa,0x39ad000,
        0x33a538f,0x390204d,0x0012bd3 } },
    /* 22 */
    { { 0x04cbba5,0x0de0344,0x1d4cc02,0x11fe8d7,0x36207e7,0x32a6da8,
        0x0239281,0x1ec40d7,0x3e89798,0x213fc66,0x0022eee,0x11daefe,
        0x3e74db8,0x28534ee,0x00aa0a4 },
      { 0x07d4543,0x250cc46,0x206620f,0x1c1e7db,0x1321538,0x31fa0b8,
        0x30f74ea,0x01aae0e,0x3a2828f,0x3e9dd22,0x026ef35,0x3c0a62b,
        0x27dbdc5,0x01c23a6,0x000f0c5 } },
    /* 23 */
    { { 0x2f029dd,0x3091337,0x21b80c5,0x21e1419,0x13dabc6,0x3847660,
        0x12b865f,0x36eb666,0x38f6274,0x0ba6006,0x098da24,0x1398c64,
        0x13d08e5,0x246a469,0x009929a },
      { 0x1285887,0x3ff5c8d,0x010237b,0x097c506,0x0bc7594,0x34b9b88,
        0x00cc35f,0x0bb964a,0x00cfbc4,0x29cd718,0x0837619,0x2b4a192,
        0x0c57bb7,0x08c69de,0x00a3627 } },
    /* 24 */
    { { 0x1361ed8,0x266d724,0x366cae7,0x1d5b18c,0x247d71b,0x2c9969a,
        0x0dd5211,0x1edd153,0x25998d7,0x0380856,0x3ab29db,0x09366de,
        0x1e53644,0x2b31ff6,0x008b0ff },
      { 0x3b5d9ef,0x217448d,0x174746d,0x18afea4,0x15b106d,0x3e66e8b,
        0x0479f85,0x13793b4,0x1231d10,0x3c39bce,0x25e8983,0x2a13210,
        0x05a7083,0x382be04,0x00a9507 } },
    /* 25 */
    { { 0x0cf381c,0x1a29b85,0x31ccf6c,0x2f708b8,0x3af9d27,0x2a29732,
        0x168d4da,0x393488d,0x2c0e338,0x3f90c7b,0x0f52ad1,0x2a0a3fa,
        0x2cd80f1,0x15e7a1a,0x00db6a0 },
      { 0x107832a,0x159cb91,0x1289288,0x17e21f9,0x073fc27,0x1584342,
        0x3802780,0x3d6c197,0x154075f,0x16366d1,0x09f712b,0x23a3ec4,
        0x29cf23a,0x3218baf,0x0039f0a } },
    /* 26 */
    { { 0x052edf5,0x2afde13,0x2e53d8f,0x3969626,0x3dcd737,0x1e46ac5,
        0x118bf0d,0x01b2652,0x156bcff,0x16d7ef6,0x1ca46d4,0x34c0cbb,
        0x3e486f6,0x1f85068,0x002cdff },
      { 0x1f47ec8,0x12cee98,0x0608667,0x18fbbe1,0x08a8821,0x31a1fe4,
        0x17c7054,0x3c89e89,0x2edf6cd,0x1b8c32c,0x3f6ea84,0x1319329,
        0x3cd3c2c,0x05f331a,0x00186fa } },
    /* 27 */
    { { 0x1fcb91e,0x0fd4d87,0x358a48a,0x04d91b4,0x083595e,0x044a1e6,
        0x15827b9,0x1d5eaf4,0x2b82187,0x08f3984,0x21bd737,0x0c54285,
        0x2f56887,0x14c2d98,0x00f4684 },
      { 0x01896f6,0x0e542d0,0x2090883,0x269dfcf,0x1e11cb8,0x239fd29,
        0x312cac4,0x19dfacb,0x369f606,0x0cc4f75,0x16579f9,0x33c22cc,
        0x0f22bfd,0x3b251ae,0x006429c } },
    /* 28 */
    { { 0x375f9a4,0x137552e,0x3570498,0x2e4a74e,0x24aef06,0x35b9307,
        0x384ca23,0x3bcd6d7,0x011b083,0x3c93187,0x392ca9f,0x129ce48,
        0x0a800ce,0x145d9cc,0x00865d6 },
      { 0x22b4a2b,0x37f9d9c,0x3e0eca3,0x3e5ec20,0x112c04b,0x2e1ae29,
        0x3ce5b51,0x0f83200,0x32d6a7e,0x10ff1d8,0x081adbe,0x265c30b,
        0x216b1c8,0x0eb4483,0x003cbcd } },
    /* 29 */
    { { 0x030ce93,0x2d331fb,0x20a2fbf,0x1f6dc9c,0x010ed6c,0x1ed5540,
        0x275bf74,0x3df0fb1,0x103333f,0x0241c96,0x1075bfc,0x30e5cf9,
        0x0f31bc7,0x32c01eb,0x00b049e },
      { 0x358839c,0x1dbabd3,0x1e4fb40,0x36a8ac1,0x2101896,0x2d0319b,
        0x2033b0a,0x192e8fd,0x2ebc8d8,0x2867ba7,0x07bf6d2,0x1b3c555,
        0x2477deb,0x198fe09,0x008e5a9 } },
    /* 30 */
    { { 0x3fbd5e1,0x18bf77d,0x2b1d69e,0x151da44,0x338ecfe,0x0768efe,
        0x1a3d56d,0x3c35211,0x10e1c86,0x2012525,0x3bc36ce,0x32b6fe4,
        0x0c8d183,0x15c93f3,0x0041fce },
      { 0x332c144,0x24e70a0,0x246e05f,0x22c21c7,0x2b17f24,0x1ba2bfd,
        0x0534e26,0x318a4f6,0x1dc3b85,0x0c741bc,0x23131b7,0x01a8cba,
        0x364e5db,0x21362cf,0x00f2951 } },
    /* 31 */
    { { 0x2ddc103,0x14ffdcd,0x206fd96,0x0de57bd,0x025f43e,0x381b73a,
        0x2301fcf,0x3bafc27,0x34130b6,0x0216bc8,0x0ff56b2,0x2c4ad4c,
        0x23c6b79,0x1267fa6,0x009b4fb },
      { 0x1d27ac2,0x13e2494,0x1389015,0x38d5b29,0x2d33167,0x3f01969,
        0x28ec1fa,0x1b26de0,0x2587f74,0x1c25668,0x0c44f83,0x23c6f8c,
        0x32fdbb1,0x045f104,0x00a7946 } },
    /* 32 */
    { { 0x23c647b,0x09addd7,0x1348c04,0x0e633c1,0x1bfcbd9,0x1cb034f,
        0x1312e31,0x11cdcc7,0x1e6ee75,0x057d27f,0x2da7ee6,0x154c3c1,
        0x3a5fb89,0x2c2ba2c,0x00cf281 },
      { 0x1b8a543,0x125cd50,0x1d30fd1,0x29cc203,0x341a625,0x14e4233,
        0x3aae076,0x289e38a,0x036ba02,0x230f405,0x3b21b8f,0x34088b9,
        0x01297a0,0x03a75fb,0x00fdc27 } },
    /* 33 */
    { { 0x07f41d6,0x1cf032f,0x1641008,0x0f86deb,0x3d97611,0x0e110fe,
        0x136ff42,0x0b914a9,0x0e241e6,0x180c340,0x1f545fc,0x0ba619d,
        0x1208c53,0x04223a4,0x00cd033 },
      { 0x397612c,0x0132665,0x34e2d1a,0x00bba99,0x1d4393e,0x065d0a8,
        0x2fa69ee,0x1643b55,0x08085f0,0x3774aad,0x08a2243,0x33bf149,
        0x03f41a5,0x1ed950e,0x0048cc6 } },
    /* 34 */
    { { 0x014ab48,0x010c3bf,0x2a744e5,0x13c99c1,0x2195b7f,0x32207fd,
        0x28a228c,0x004f4bf,0x0e2d945,0x2ec6e5a,0x0b92162,0x1aa95e5,
        0x2754a93,0x1adcd93,0x004fb76 },
      { 0x1e1ff7f,0x24ef28c,0x269113f,0x32b393c,0x2696eb5,0x0ac2780,
        0x354bf8a,0x0ffe3fd,0x09ce58e,0x0163c4f,0x1678c0b,0x15cd1bc,
        0x292b3b7,0x036ea19,0x00d5420 } },
    /* 35 */
    { { 0x1da1265,0x0c2ef5b,0x18dd9a0,0x3f3a25c,0x0f7b4f3,0x0d8196e,
        0x24931f9,0x090729a,0x1875f72,0x1ef39cb,0x2577585,0x2ed472d,
        0x136756c,0x20553a6,0x00c7161 },
      { 0x2e32189,0x283de4b,0x00b2e81,0x0989df7,0x3ef2fab,0x1c7d1a7,
        0x24f6feb,0x3e16679,0x233dfda,0x06d1233,0x3e6b5df,0x1707132,
        0x05f7b3f,0x2c00779,0x00fb8df } },
    /* 36 */
    { { 0x15bb921,0x117e9d3,0x267ec73,0x2f934ad,0x25c7e04,0x20b5e8f,
        0x2d3a802,0x2ca911f,0x3f87e47,0x39709dd,0x08488e2,0x2cec400,
        0x35b4589,0x1f0acba,0x009aad7 },
      { 0x2ac34ae,0x06f29f6,0x3326d68,0x3949abe,0x02452e4,0x0687b85,
        0x0879244,0x1eb7832,0x0d4c240,0x31d0ec1,0x3c17a2a,0x17a666f,
        0x01a06cb,0x3e0929c,0x004dca2 } },
    /* 37 */
    { { 0x127bc1a,0x0c72984,0x13be68e,0x26c5fab,0x1a3edd5,0x097d685,
        0x36b645e,0x385799e,0x394a420,0x39d8885,0x0b1e872,0x13f60ed,
        0x2ce1b79,0x3c0ecb7,0x007cab3 },
      { 0x29b3586,0x26fc572,0x0bd7711,0x0913494,0x0a55459,0x31af3c9,
        0x3633eac,0x3e2105c,0x0c2b1b6,0x0e6f4c2,0x047d38c,0x2b81bd5,
        0x1fe1c3b,0x04d7cd0,0x0054dcc } },
    /* 38 */
    { { 0x03caf0d,0x0d66365,0x313356d,0x2a4897f,0x2ce044e,0x18feb7a,
        0x1f6a7c5,0x3709e7b,0x14473e8,0x2d8cbae,0x3190dca,0x12d19f8,
        0x31e3181,0x3cc5b6e,0x002d4f4 },
      { 0x143b7ca,0x2604728,0x39508d6,0x0cb79f3,0x24ec1ac,0x1ed7fa0,
        0x3ab5fd3,0x3c76488,0x2e49390,0x03a0985,0x3580461,0x3fd2c81,
        0x308f0ab,0x38561d6,0x0011b9b } },
    /* 39 */
    { { 0x3be682c,0x0c68f4e,0x32dd4ae,0x099d3bb,0x0bc7c5d,0x311f750,
        0x2fd10a3,0x2e7864a,0x23bc14a,0x13b1f82,0x32e495e,0x1b0f746,
        0x3cd856a,0x17a4c26,0x00085ee },
      { 0x02e67fd,0x06a4223,0x2af2f38,0x2038987,0x132083a,0x1b7bb85,
        0x0d6a499,0x131e43f,0x3035e52,0x278ee3e,0x1d5b08b,0x30d8364,
        0x2719f8d,0x0b21fc9,0x003a06e } },
    /* 40 */
    { { 0x237cac0,0x27d6a1c,0x27945cd,0x2750d61,0x293f0b5,0x253db13,
        0x04a764e,0x20b4d0e,0x12bb627,0x160c13b,0x0de0601,0x236e2cf,
        0x2190f0b,0x354d76f,0x004336d },
      { 0x2ab473a,0x10d54e4,0x1046574,0x1d6f97b,0x0031c72,0x06426a9,
        0x38678c2,0x0b76cf9,0x04f9920,0x152adf8,0x2977e63,0x1234819,
        0x198be26,0x061024c,0x00d427d } },
    /* 41 */
    { { 0x39b5a31,0x2123d43,0x362a822,0x1a2eab6,0x0bb0034,0x0d5d567,
        0x3a04723,0x3a10c8c,0x08079ae,0x0d27bda,0x2eb9e1e,0x2619e82,
        0x39a55a8,0x0c6c7db,0x00c1519 },
      { 0x174251e,0x13ac2eb,0x295ed26,0x18d2afc,0x037b9b2,0x1258344,
        0x00921b0,0x1f702d8,0x1bc4da7,0x1c3794f,0x12b1869,0x366eacf,
        0x16ddf01,0x31ebdc5,0x00ad54e } },
    /* 42 */
    { { 0x1efdc58,0x1370d5e,0x0ddb8e7,0x1a53fda,0x1456bd3,0x0c825a9,
        0x0e74ccd,0x20f41c9,0x3423867,0x139073f,0x3c70d8a,0x131fc85,
        0x219a2a0,0x34bf986,0x0041199 },
      { 0x1c05dd2,0x268f80a,0x3da9d38,0x1af9f8f,0x0535f2a,0x30ad37e,
        0x2cf72d7,0x14a509b,0x1f4fe74,0x259e09d,0x1d23f51,0x0672732,
        0x08fc463,0x00b6201,0x001e05a } },
    /* 43 */
    { { 0x0d5ffe8,0x3238bb5,0x17f275c,0x25b6fa8,0x2f8bb48,0x3b8f2d2,
        0x059790c,0x18594d4,0x285a47c,0x3d301bb,0x12935d2,0x23ffc96,
        0x3d7c7f9,0x15c8cbf,0x0034c4a },
      { 0x20376a2,0x05201ba,0x1e02c4b,0x1413c45,0x02ea5e7,0x39575f0,
        0x2d76e21,0x113694c,0x011f310,0x0da3725,0x31b7799,0x1cb9195,
        0x0cfd592,0x22ee4ea,0x00adaa3 } },
    /* 44 */
    { { 0x14ed72a,0x031c49f,0x39a34bf,0x192e87d,0x0da0e92,0x130e7a9,
        0x00258bf,0x144e123,0x2d82a71,0x0294e53,0x3f06c66,0x3d4473a,
        0x037cd4a,0x3bbfb17,0x00fcebc },
      { 0x39ae8c1,0x2dd6a9d,0x206ef23,0x332b479,0x2deff59,0x09d5720,
        0x3526fd2,0x33bf7cf,0x344bb32,0x359316a,0x115bdef,0x1b8468a,
        0x3813ea9,0x11a8450,0x00ab197 } },
    /* 45 */
    { { 0x0837d7d,0x1e1617b,0x0ba443c,0x2f2e3b8,0x2ca5b6f,0x176ed7b,
        0x2924d9d,0x07294d3,0x104bb4f,0x1cfd3e8,0x398640f,0x1162dc8,
        0x007ea15,0x2aa75fd,0x004231f },
      { 0x16e6896,0x01987be,0x0f9d53e,0x1a740ec,0x1554e4c,0x31e1634,
        0x3cb07b9,0x013eb53,0x39352cb,0x1dfa549,0x0974e7f,0x17c55d2,
        0x157c85f,0x1561adb,0x002e3fa } },
    /* 46 */
    { { 0x29951a8,0x35200da,0x2ad042c,0x22109e4,0x3a8b15b,0x2eca69c,
        0x28bcf9a,0x0cfa063,0x0924099,0x12ff668,0x2fb88dc,0x028d653,
        0x2445876,0x218d01c,0x0014418 },
      { 0x1caedc7,0x295bba6,0x01c9162,0x3364744,0x28fb12e,0x24c80b6,
        0x2719673,0x35e5ba9,0x04aa4cc,0x206ab23,0x1cf185a,0x2c140d8,
        0x1095a7d,0x1b3633f,0x000c9f8 } },
    /* 47 */
    { { 0x0b2a556,0x0a051c4,0x30b29a7,0x190c9ed,0x3767ca9,0x38de66d,
        0x2d9e125,0x3aca813,0x2dc22a3,0x319e074,0x0d9450a,0x3445bac,
        0x3e08a5b,0x07f29fa,0x00eccac },
      { 0x02d6e94,0x21113f7,0x321bde6,0x0a4d7b3,0x03621f4,0x2780e8b,
        0x22d5432,0x1fc2853,0x0d57d3e,0x254f90b,0x33ed00b,0x289b025,
        0x12272bb,0x30e715f,0x0000297 } },
    /* 48 */
    { { 0x0243a7d,0x2aac42e,0x0c5b3aa,0x0fa3e96,0x06eeef9,0x2b9fdd9,
        0x26fca39,0x0134fe1,0x22661ab,0x1990416,0x03945d6,0x15e3628,
        0x3848ca3,0x0f91e46,0x00b08cd },
      { 0x16d2411,0x3717e1d,0x128c45e,0x3669d54,0x0d4a790,0x2797da8,
        0x0f09634,0x2faab0b,0x27df649,0x3b19b49,0x0467039,0x39b65a2,
        0x3816f3c,0x31ad0bd,0x0050046 } },
    /* 49 */
    { { 0x2425043,0x3858099,0x389092a,0x3f7c236,0x11ff66a,0x3c58b39,
        0x2f5a7f8,0x1663ce1,0x2a0fcf5,0x38634b7,0x1a8ca18,0x0dcace8,
        0x0e6f778,0x03ae334,0x00df0d2 },
      { 0x1bb4045,0x357875d,0x14b77ed,0x33ae5b6,0x2252a47,0x31899dd,
        0x3293582,0x040c6f6,0x14340dd,0x3614f0e,0x3d5f47f,0x326fb3d,
        0x0044a9d,0x00beeb9,0x0027c23 } },
    /* 50 */
    { { 0x32d49ce,0x34822a3,0x30a22d1,0x00858b7,0x10d91aa,0x2681fd9,
        0x1cce870,0x2404a71,0x38b8433,0x377c1c8,0x019442c,0x0a38b21,
        0x22aba50,0x0d61c81,0x002dcbd },
      { 0x0680967,0x2f0f2f9,0x172cb5f,0x1167e4b,0x12a7bc6,0x05b0da7,
        0x2c76e11,0x3a36201,0x37a3177,0x1d71419,0x0569df5,0x0dce7ad,
        0x3f40b75,0x3bd8db0,0x002d481 } },
    /* 51 */
    { { 0x2a1103e,0x34e7f7f,0x1b171a2,0x24a57e0,0x2eaae55,0x166c992,
        0x10aa18f,0x0bb836f,0x01acb59,0x0e430e7,0x1750cca,0x18be036,
        0x3cc6cdf,0x0a0f7e5,0x00da4d8 },
      { 0x2201067,0x374d187,0x1f6b0a6,0x165a7ec,0x31531f8,0x3580487,
        0x15e5521,0x0724522,0x2b04c04,0x202c86a,0x3cc1ccf,0x225b11a,
        0x1bde79d,0x0eccc50,0x00d24da } },
    /* 52 */
    { { 0x3b0a354,0x2814dd4,0x1cd8575,0x3d031b7,0x0392ff2,0x1855ee5,
        0x0e8cff5,0x203442e,0x3bd3b1b,0x141cf95,0x3fedee1,0x1d783c0,
        0x26f192a,0x0392aa3,0x0075238 },
      { 0x158ffe9,0x3889f19,0x14151f4,0x06067b1,0x13a3486,0x1e65c21,
        0x382d5ef,0x1ab0aac,0x2ffddc4,0x3179b7a,0x3c8d094,0x05101e3,
        0x237c6e5,0x3947d83,0x00f674f } },
    /* 53 */
    { { 0x363408f,0x21eb96b,0x27376fb,0x2a735d6,0x1a39c36,0x3d31863,
        0x33313fc,0x32235e0,0x082f034,0x23ef351,0x39b3528,0x1a69d84,
        0x1d9c944,0x07159ad,0x0077a71 },
      { 0x04f8d65,0x25771e5,0x2ba84a6,0x194586a,0x1e6da5f,0x118059a,
        0x14e9c32,0x1d24619,0x3f528ae,0x22f22e4,0x0f5580d,0x0747a0e,
        0x32cc85f,0x286b3a8,0x008ccf9 } },
    /* 54 */
    { { 0x196fee2,0x2c4431c,0x094528a,0x18e1d32,0x175799d,0x26bb6b7,
        0x2293482,0x23fd289,0x07b2be8,0x1a5c533,0x158d60d,0x04a4f3f,
        0x164e9f7,0x32ccca9,0x00da6b6 },
      { 0x1d821c2,0x3f76c4f,0x323df43,0x17e4374,0x0f2f278,0x121227e,
        0x2464190,0x19d2644,0x326d24c,0x3185983,0x0803c15,0x0767a33,
        0x1c4c996,0x0563eab,0x00631c6 } },
    /* 55 */
    { { 0x1752366,0x0baf83f,0x288bacf,0x0384e6f,0x2b93c34,0x3c805e7,
        0x3664850,0x29e1663,0x254ff1d,0x3852080,0x0f85c16,0x1e389d9,
        0x3191352,0x3915eaa,0x00a246e },
      { 0x3763b33,0x187ad14,0x3c0d438,0x3f11702,0x1c49f03,0x35ac7a8,
        0x3f16bca,0x27266bf,0x08b6fd4,0x0f38ce4,0x37fde8c,0x147a6ff,
        0x02c5e5c,0x28e7fc5,0x00076a7 } },
    /* 56 */
    { { 0x2338d10,0x0e77fa7,0x011b046,0x1bfd0ad,0x28ee699,0x21d73bc,
        0x0461d1a,0x342ea58,0x2d695b4,0x30415ed,0x2906e0b,0x18e494a,
        0x20f8a27,0x026b870,0x002c19f },
      { 0x2f4c43d,0x3f0fc3b,0x0aa95b8,0x2a01ea1,0x3e2e1b1,0x0d74af6,
        0x0555288,0x0cb757d,0x24d2071,0x143d2bb,0x3907f67,0x3e0ce30,
        0x131f0e9,0x3724381,0x007a874 } },
    /* 57 */
    { { 0x3c27050,0x08b5165,0x0bf884b,0x3dd679c,0x3bd0b8d,0x25ce2e6,
        0x1674057,0x1f13ed3,0x1f5cd91,0x0d1fd35,0x13ce6e3,0x2671338,
        0x10f8b90,0x34e5487,0x00942bf },
      { 0x03b566d,0x23c3da9,0x37de502,0x1a486ff,0x1af6e86,0x1108cb3,
        0x36f856c,0x01a6a0f,0x179f915,0x1595a01,0x2cfecb8,0x082568b,
        0x1ba16d1,0x1abb6c0,0x00cf7f0 } },
    /* 58 */
    { { 0x2f96c80,0x1b8f123,0x209c0f5,0x2ccf76d,0x1d521f2,0x3705143,
        0x2941027,0x07f88af,0x07102a9,0x38b4868,0x1efa37d,0x1bdd3e8,
        0x028a12e,0x02e055b,0x009a9a9 },
      { 0x1c7dfcb,0x3aa7aa7,0x1d62c54,0x3f0b0b0,0x3c74e66,0x274f819,
        0x23f9674,0x0e2b67c,0x24654dd,0x0c71f0e,0x1946cee,0x0016211,
        0x0045dc7,0x0da1173,0x0089856 } },
    /* 59 */
    { { 0x0e73946,0x29f353f,0x056329d,0x2d48c5a,0x28f697d,0x2ea4bb1,
        0x235e9cc,0x34faa38,0x15f9f91,0x3557519,0x2a50a6c,0x1a27c8e,
        0x2a1a0f3,0x3098879,0x00dcf21 },
      { 0x1b818bf,0x2f20b98,0x2243cff,0x25b691e,0x3c74a2f,0x2f06833,
        0x0e980a8,0x32db48d,0x2b57929,0x33cd7f5,0x2fe17d6,0x11a384b,
        0x2dafb81,0x2b9562c,0x00ddea6 } },
    /* 60 */
    { { 0x2787b2e,0x37a21df,0x310d294,0x07ce6a4,0x1258acc,0x3050997,
        0x19714aa,0x122824b,0x11c708b,0x0462d56,0x21abbf7,0x331aec3,
        0x307b927,0x3e8d5a0,0x00c0581 },
      { 0x24d4d58,0x3d628fc,0x23279e0,0x2e38338,0x2febe9b,0x346f9c0,
        0x3d6a419,0x3264e47,0x245faca,0x3669f62,0x1e50d66,0x3028232,
        0x18201ab,0x0bdc192,0x0002c34 } },
    /* 61 */
    { { 0x17bdbc2,0x1c501c5,0x1605ccd,0x31ab438,0x372fa89,0x24a8057,
        0x13da2bb,0x3f95ac7,0x3cda0a3,0x1e2b679,0x24f0673,0x03b72f4,
        0x35be616,0x2ccd849,0x0079d4d },
      { 0x33497c4,0x0c7f657,0x2fb0d3d,0x3b81064,0x38cafea,0x0e942bc,
        0x3ca7451,0x2ab9784,0x1678c85,0x3c62098,0x1eb556f,0x01b3aa2,
        0x149f3ce,0x2656f6d,0x002eef1 } },
    /* 62 */
    { { 0x0596edc,0x1f4fad4,0x03a28ed,0x18a4149,0x3aa3593,0x12db40a,
        0x12c2c2a,0x3b1a288,0x327c4fb,0x35847f5,0x384f733,0x02e3fde,
        0x1af0e8a,0x2e417c3,0x00d85a6 },
      { 0x0091cf7,0x2267d75,0x276860e,0x19cbbfc,0x04fef2b,0x030ce59,
        0x3195cb1,0x1aa3f07,0x3699362,0x2a09d74,0x0d6c840,0x1e413d0,
        0x28acdc7,0x1ff5ea1,0x0088d8b } },
    /* 63 */
    { { 0x3d98425,0x08dc8de,0x154e85f,0x24b1c2c,0x2d44639,0x19a1e8b,
        0x300ee29,0x053f72e,0x3f7c832,0x12417f6,0x1359368,0x0674a4c,
        0x1218e20,0x0e4fbd4,0x000428c },
      { 0x01e909a,0x1d88fe6,0x12da40c,0x215ef86,0x2925133,0x004241f,
        0x3e480f4,0x2d16523,0x07c3120,0x3375e86,0x21fd8f3,0x35dc0b6,
        0x0efc5c9,0x14ef8d6,0x0066e47 } },
    /* 64 */
    { { 0x2973cf4,0x34d3845,0x34f7070,0x22df93c,0x120aee0,0x3ae2b4a,
        0x1af9b95,0x177689a,0x036a6a4,0x0377828,0x23df41e,0x22d4a39,
        0x0df2aa1,0x06ca898,0x0003cc7 },
      { 0x06b1dd7,0x19dc2a8,0x35d324a,0x0467499,0x25bfa9c,0x1a1110c,
        0x01e2a19,0x1b3c1cf,0x18d131a,0x10d9815,0x2ee7945,0x0a2720c,
        0x0ddcdb0,0x2c071b6,0x00a6aef } },
    /* 65 */
    { { 0x1ab5245,0x1192d00,0x13ffba1,0x1b71236,0x09b8d0b,0x0eb49cb,
        0x1867dc9,0x371de4e,0x05eae9f,0x36faf82,0x094ea8b,0x2b9440e,
        0x022e173,0x2268e6b,0x00740fc },
      { 0x0e23b23,0x22c28ca,0x04d05e2,0x0bb84c4,0x1235272,0x0289903,
        0x267a18b,0x0df0fd1,0x32e49bb,0x2ab1d29,0x281e183,0x3dcd3c3,
        0x1c0eb79,0x2db0ff6,0x00bffe5 } },
    /* 66 */
    { { 0x2a2123f,0x0d63d71,0x1f6db1a,0x257f8a3,0x1927b2d,0x06674be,
        0x302753f,0x20b7225,0x14c1a3f,0x0429cdd,0x377affe,0x0f40a75,
        0x2d34d06,0x05fb6b9,0x0054398 },
      { 0x38b83c4,0x1e7bbda,0x1682f79,0x0527651,0x2615cb2,0x1795fab,
        0x0e4facc,0x11f763c,0x1b81130,0x2010ae2,0x13f3650,0x20d5b72,
        0x1f32f88,0x34617f4,0x00bf008 } },
    /* 67 */
    { { 0x28068db,0x0aa8913,0x1a47801,0x10695ca,0x1c72cc6,0x0fc1a47,
        0x33df2c4,0x0517cf0,0x3471d92,0x1be815c,0x397f794,0x3f03cbe,
        0x121bfae,0x172cbe0,0x00813d7 },
      { 0x383bba6,0x04f1c90,0x0b3f056,0x1c29089,0x2a924ce,0x3c85e69,
        0x1cecbe5,0x0ad8796,0x0aa79f6,0x25e38ba,0x13ad807,0x30b30ed,
        0x0fa963a,0x35c763d,0x0055518 } },
    /* 68 */
    { { 0x0623f3b,0x3ca4880,0x2bff03c,0x0457ca7,0x3095c71,0x02a9a08,
        0x1722478,0x302c10b,0x3a17458,0x001131e,0x0959ec2,0x18bdfbc,
        0x2929fca,0x2adfe32,0x0040ae2 },
      { 0x127b102,0x14ddeaa,0x1771b8c,0x283700c,0x2398a86,0x085a901,
        0x108f9dc,0x0cc0012,0x33a918d,0x26d08e9,0x20b9473,0x12c3fc7,
        0x1f69763,0x1c94b5a,0x00e29de } },
    /* 69 */
    { { 0x035af04,0x3450021,0x12da744,0x077fb06,0x25f255b,0x0db7150,
        0x17dc123,0x1a2a07c,0x2a7636a,0x3972430,0x3704ca1,0x0327add,
        0x3d65a96,0x3c79bec,0x009de8c },
      { 0x11d3d06,0x3fb8354,0x12c7c60,0x04fe7ad,0x0466e23,0x01ac245,
        0x3c0f5f2,0x2a935d0,0x3ac2191,0x090bd56,0x3febdbc,0x3f1f23f,
        0x0ed1cce,0x02079ba,0x00d4fa6 } },
    /* 70 */
    { { 0x0ab9645,0x10174ec,0x3711b5e,0x26357c7,0x2aeec7f,0x2170a9b,
        0x1423115,0x1a5122b,0x39e512c,0x18116b2,0x290db1c,0x041b13a,
        0x26563ae,0x0f56263,0x00b89f3 },
      { 0x3ed2ce4,0x01f365f,0x1b2043b,0x05f7605,0x1f9934e,0x2a068d2,
        0x38d4d50,0x201859d,0x2de5291,0x0a7985a,0x17e6711,0x01b6c1b,
        0x08091fa,0x33c6212,0x001da23 } },
    /* 71 */
    { { 0x2f2c4b5,0x311acd0,0x1e47821,0x3bd9816,0x1931513,0x1bd4334,
        0x30ae436,0x2c49dc0,0x2c943e7,0x010ed4d,0x1fca536,0x189633d,
        0x17abf00,0x39e5ad5,0x00e4e3e },
      { 0x0c8b22f,0x2ce4009,0x1054bb6,0x307f2fc,0x32eb5e2,0x19d24ab,
        0x3b18c95,0x0e55e4d,0x2e4acf5,0x1bc250c,0x1dbf3a5,0x17d6a74,
        0x087cf58,0x07f6f82,0x00f8675 } },
    /* 72 */
    { { 0x110e0b2,0x0e672e7,0x11b7157,0x1598371,0x01c0d59,0x3d60c24,
        0x096b8a1,0x0121075,0x0268859,0x219962f,0x03213f2,0x3022adc,
        0x18de488,0x3dcdeb9,0x008d2e0 },
      { 0x06cfee6,0x26f2552,0x3c579b7,0x31fa796,0x2036a26,0x362ba5e,
        0x103601c,0x012506b,0x387ff3a,0x101a41f,0x2c7eb58,0x23d2efc,
        0x10a5a07,0x2fd5fa3,0x00e3731 } },
    /* 73 */
    { { 0x1cd0abe,0x08a0af8,0x2fa272f,0x17a1fbf,0x1d4f901,0x30e0d2f,
        0x1898066,0x273b674,0x0c1b8a2,0x3272337,0x3ee82eb,0x006e7d3,
        0x2a75606,0x0af1c81,0x0037105 },
      { 0x2f32562,0x2842491,0x1bb476f,0x1305cd4,0x1daad53,0x0d8daed,
        0x164c37b,0x138030f,0x05145d5,0x300e2a3,0x32c09e7,0x0798600,
        0x3515130,0x2b9e55c,0x009764e } },
    /* 74 */
    { { 0x3d5256a,0x06c67f2,0x3a3b879,0x3c9b284,0x04007e0,0x33c1a41,
        0x3794604,0x1d6240e,0x022b6c1,0x22c62a7,0x01d4590,0x32df5f6,
        0x368f1a1,0x2a7486e,0x006e13f },
      { 0x31e6e16,0x20f18a9,0x09ed471,0x23b861d,0x15cf0ef,0x397b502,
        0x1c7f9b2,0x05f84b2,0x2cce6e1,0x3c10bba,0x13fb5a7,0x1b52058,
        0x1feb1b8,0x03b7279,0x00ea1cf } },
    /* 75 */
    { { 0x2a4cc9b,0x15cf273,0x08f36e6,0x076bf3b,0x2541796,0x10e2dbd,
        0x0bf02aa,0x3aa2201,0x03cdcd4,0x3ee252c,0x3799571,0x3e01fa4,
        0x156e8d0,0x1fd6188,0x003466a },
      { 0x2515664,0x166b355,0x2b0b51e,0x0f28f17,0x355b0f9,0x2909e76,
        0x206b026,0x3823a12,0x179c5fa,0x0972141,0x2663a1a,0x01ee36e,
        0x3fc8dcf,0x2ef3d1b,0x0049a36 } },
    /* 76 */
    { { 0x2d93106,0x3d6b311,0x3c9ce47,0x382aa25,0x265b7ad,0x0b5f92f,
        0x0f4c941,0x32aa4df,0x380d4b2,0x0e8aba6,0x260357a,0x1f38273,
        0x0d5f95e,0x199f23b,0x0029f77 },
      { 0x0a0b1c5,0x21a3d6a,0x0ad8df6,0x33d8a5e,0x1240858,0x30000a8,
        0x3ac101d,0x2a8143d,0x1d7ffe9,0x1c74a2a,0x1b962c9,0x1261359,
        0x0c8b274,0x002cf4a,0x00a8a7c } },
    /* 77 */
    { { 0x211a338,0x22a14ab,0x16e77c5,0x3c746be,0x3a78613,0x0d5731c,
        0x1767d25,0x0b799fa,0x009792a,0x09ae8dc,0x124386b,0x183d860,
        0x176747d,0x14c4445,0x00ab09b },
      { 0x0eb9dd0,0x0121066,0x032895a,0x330541c,0x1e6c17a,0x2271b92,
        0x06da454,0x054c2bf,0x20abb21,0x0ead169,0x3d7ea93,0x2359649,
        0x242c6c5,0x3194255,0x00a3ef3 } },
    /* 78 */
    { { 0x3010879,0x1083a77,0x217989d,0x174e55d,0x29d2525,0x0e544ed,
        0x1efd50e,0x30c4e73,0x05bd5d1,0x0793bf9,0x3f7af77,0x052779c,
        0x2b06bc0,0x13d0d02,0x0055a6b },
      { 0x3eaf771,0x094947a,0x0288f13,0x0a21e35,0x22ab441,0x23816bf,
        0x15832e1,0x2d8aff3,0x348cc1f,0x2bbd4a8,0x01c4792,0x34209d3,
        0x06dc72b,0x211a1df,0x00345c5 } },
    /* 79 */
    { { 0x2a65e90,0x173ac2f,0x199cde1,0x0ac905b,0x00987f7,0x3618f7b,
        0x1b578df,0x0d5e113,0x34bac6a,0x27d85ed,0x1b48e99,0x18af5eb,
        0x1a1be9e,0x3987aac,0x00877ca },
      { 0x2358610,0x3776a8e,0x2b0723a,0x344c978,0x22fc4d6,0x1615d53,
        0x3198f51,0x2d61225,0x12cb392,0x07dd061,0x355f7de,0x09e0132,
        0x0efae99,0x13b46aa,0x00e9e6c } },
    /* 80 */
    { { 0x0683186,0x36d8e66,0x0ea9867,0x0937731,0x1fb5cf4,0x13c39ef,
        0x1a7ffed,0x27dfb32,0x31c7a77,0x09f15fd,0x16b25ef,0x1dd01e7,
        0x0168090,0x240ed02,0x0090eae },
      { 0x2e1fceb,0x2ab9783,0x1a1fdf2,0x093a1b0,0x33ff1da,0x2864fb7,
        0x3587d6c,0x275aa03,0x123dc9b,0x0e95a55,0x0592030,0x2102402,
        0x1bdef7b,0x37f2e9b,0x001efa4 } },
    /* 81 */
    { { 0x0540015,0x20e3e78,0x37dcfbd,0x11b0e41,0x02c3239,0x3586449,
        0x1fb9e6a,0x0baa22c,0x00c0ca6,0x3e58491,0x2dbe00f,0x366d4b0,
        0x176439a,0x2a86b86,0x00f52ab },
      { 0x0ac32ad,0x226250b,0x0f91d0e,0x1098aa6,0x3dfb79e,0x1dbd572,
        0x052ecf2,0x0f84995,0x0d27ad2,0x036c6b0,0x1e4986f,0x2317dab,
        0x2327df6,0x0dee0b3,0x00389ac } },
    /* 82 */
    { { 0x0e60f5b,0x0622d3e,0x2ada511,0x05522a8,0x27fe670,0x206af28,
        0x333cb83,0x3f25f6c,0x19ddaf3,0x0ec579b,0x36aabc0,0x093dbac,
        0x348b44b,0x277dca9,0x00c5978 },
      { 0x1cf5279,0x32e294a,0x1a6c26f,0x3f006b6,0x37a3c6b,0x2e2eb26,
        0x2cf88d4,0x3410619,0x1899c80,0x23d3226,0x30add14,0x2810905,
        0x01a41f0,0x11e5176,0x005a02f } },
    /* 83 */
    { { 0x1c90202,0x321df30,0x3570fa5,0x103e2b1,0x3d099d4,0x05e207d,
        0x0a5b1bd,0x0075d0a,0x3db5b25,0x2d87899,0x32e4465,0x226fc13,
        0x24cb8f8,0x3821daa,0x004da3a },
      { 0x3e66861,0x03f89b8,0x386d3ef,0x14ccc62,0x35e7729,0x11ce5b7,
        0x035fbc7,0x3f4df0f,0x29c439f,0x1144568,0x32d7037,0x312f65e,
        0x06b9dbf,0x03a9589,0x0008863 } },
    /* 84 */
    { { 0x0a9e8c9,0x1a19b6e,0x091ecd9,0x2e16ee0,0x2a11963,0x116cf34,
        0x390d530,0x194131f,0x2b580f3,0x31d569c,0x21d3751,0x3e2ce64,
        0x193de46,0x32454f0,0x004bffd },
      { 0x09554e7,0x170126e,0x2be6cd1,0x153de89,0x0353c67,0x350765c,
        0x202370b,0x1db01e5,0x30b12b1,0x3778591,0x00c8809,0x2e845d5,
        0x1fb1e56,0x170f90d,0x00e2db3 } },
    /* 85 */
    { { 0x328e33f,0x392aad8,0x36d1d71,0x0aebe04,0x1548678,0x1b55c8c,
        0x24995f8,0x2a5a01e,0x1bd1651,0x37c7c29,0x36803b6,0x3716c91,
        0x1a935a5,0x32f10b7,0x005c587 },
      { 0x2e8b4c0,0x336ccae,0x11382b6,0x22ec4cc,0x066d159,0x35fa585,
        0x23b2d25,0x3017528,0x2a674a8,0x3a4f900,0x1a7ce82,0x2b2539b,
        0x3d46545,0x0a07918,0x00eb9f8 } },
    /* 86 */
    { { 0x2cf5b9b,0x03e747f,0x166a34e,0x0afc81a,0x0a115b1,0x3aa814d,
        0x11cf3b1,0x163e556,0x3cbfb15,0x157c0a4,0x1bc703a,0x2141e90,
        0x01f811c,0x207218b,0x0092e6b },
      { 0x1af24e3,0x3af19b3,0x3c70cc9,0x335cbf3,0x068917e,0x055ee92,
        0x09a9308,0x2cac9b7,0x008b06a,0x1175097,0x36e929c,0x0be339c,
        0x0932436,0x15f18ba,0x0009f6f } },
    /* 87 */
    { { 0x29375fb,0x35ade34,0x11571c7,0x07b8d74,0x3fabd85,0x090fa91,
        0x362dcd4,0x02c3fdb,0x0608fe3,0x2477649,0x3fc6e70,0x059b7eb,
        0x1e6a708,0x1a4c220,0x00c6c4c },
      { 0x2a53fb0,0x1a3e1f5,0x11f9203,0x27e7ad3,0x038718e,0x3f5f9e4,
        0x308acda,0x0a8700f,0x34472fe,0x3420d7a,0x08076e5,0x014240e,
        0x0e7317e,0x197a98e,0x00538f7 } },
    /* 88 */
    { { 0x2663b4b,0x0927670,0x38dd0e0,0x16d1f34,0x3e700ab,0x3119567,
        0x12559d2,0x399b6c6,0x0a84bcd,0x163e7dd,0x3e2aced,0x058548c,
        0x03a5bad,0x011cf74,0x00c155c },
      { 0x3e454eb,0x2a1e64e,0x1ccd346,0x36e0edf,0x266ee94,0x2e74aaf,
        0x2d8378a,0x3cd547d,0x1d27733,0x0928e5b,0x353553c,0x26f502b,
        0x1d94341,0x2635cc7,0x00d0ead } },
    /* 89 */
    { { 0x0142408,0x382c3bb,0x3310908,0x2e50452,0x398943c,0x1d0ac75,
        0x1bf7d81,0x04bd00f,0x36b6934,0x3349c37,0x0f69e20,0x0195252,
        0x243a1c5,0x030da5f,0x00a76a9 },
      { 0x224825a,0x28ce111,0x34c2e0f,0x02e2b30,0x382e48c,0x26853ca,
        0x24bd14e,0x0200dec,0x1e24db3,0x0d3d775,0x132da0a,0x1dea79e,
        0x253dc0c,0x03c9d31,0x0020db9 } },
    /* 90 */
    { { 0x26c5fd9,0x05e6dc3,0x2eea261,0x08db260,0x2f8bec1,0x1255edf,
        0x283338d,0x3d9a91d,0x2640a72,0x03311f9,0x1bad935,0x152fda8,
        0x0e95abd,0x31abd15,0x00dfbf4 },
      { 0x107f4fa,0x29ebe9a,0x27353f7,0x3821972,0x27311fa,0x2925ab6,
        0x337ab82,0x2de6c91,0x1f115fe,0x044f909,0x21b93c2,0x3a5f142,
        0x13eb5e9,0x3ab1377,0x00b26b6 } },
    /* 91 */
    { { 0x22e5f2b,0x2ae7d4a,0x1ac481c,0x0a6fce1,0x2f93caf,0x242658e,
        0x3f35c3c,0x050f3d2,0x30074c9,0x142079c,0x0281b4c,0x295fea3,
        0x007413e,0x01726cd,0x00e4979 },
      { 0x1ab3cfb,0x1b76295,0x36adf55,0x1ad4636,0x1d444b9,0x3bd2e55,
        0x35425a5,0x1aa8cd3,0x3acecd2,0x1f769e8,0x1a655e9,0x1f6846f,
        0x24c70b5,0x3bff080,0x0002da3 } },
    /* 92 */
    { { 0x081d0d9,0x2c00d99,0x1fe2e24,0x396063f,0x03740db,0x243f680,
        0x3c1f451,0x1ff7b07,0x2803cf2,0x38ca724,0x2934f43,0x0d72d4d,
        0x0e8fe74,0x2975e21,0x002b505 },
      { 0x11adcc9,0x331a99c,0x21e16cf,0x1714c78,0x1f03432,0x2caa2a6,
        0x34a9679,0x2f7fe8b,0x0423c21,0x1a757ce,0x31b57d6,0x171e044,
        0x093b9b2,0x13602e0,0x00db534 } },
    /* 93 */
    { { 0x250a2f5,0x0b999eb,0x21d10d7,0x22b92a1,0x39b7f8d,0x0c37c72,
        0x29f70f3,0x3bf0e84,0x1d7e04f,0x07a42a9,0x272c3ae,0x1587b2f,
        0x155faff,0x10a336e,0x000d8fb },
      { 0x3663784,0x0d7dcf5,0x056ad22,0x319f8b1,0x0c05bae,0x2b6ff33,
        0x0292e42,0x0435797,0x188efb1,0x0d3f45e,0x119d49f,0x395dcd3,
        0x279fe27,0x133a13d,0x00188ac } },
    /* 94 */
    { { 0x396c53e,0x0d133e9,0x009b7ee,0x13421a0,0x1bbf607,0x1d284a5,
        0x1594f74,0x18cb47c,0x2dcac11,0x2999ddb,0x04e2fa5,0x1889e2c,
        0x0a89a18,0x33cb215,0x0052665 },
      { 0x104ab58,0x1d91920,0x3d6d7e3,0x04dc813,0x1167759,0x13a8466,
        0x0a06a54,0x103761b,0x25b1c92,0x26a8fdd,0x2474614,0x21406a4,
        0x251d75f,0x38c3734,0x007b982 } },
    /* 95 */
    { { 0x15f3060,0x3a7bf30,0x3be6e44,0x0baa1fa,0x05ad62f,0x1e54035,
        0x099d41c,0x2a744d9,0x1c0336f,0x3e99b5b,0x1afd3b1,0x2bf1255,
        0x1822bf8,0x2c93972,0x001d8cc },
      { 0x1d7584b,0x0508ade,0x20dd403,0x203a8fc,0x1c54a05,0x1611a31,
        0x037c8f9,0x1dcd4fe,0x110fbea,0x30f60bc,0x3dffe2f,0x26a1de1,
        0x0480367,0x18ec81c,0x0048eba } },
    /* 96 */
    { { 0x346e2f6,0x0435077,0x036789b,0x3e06545,0x313ab57,0x351a721,
        0x3372b91,0x15e6019,0x2fa4f6c,0x3c30656,0x272c9ac,0x10e84a8,
        0x2bdacea,0x232d9e2,0x009dadd },
      { 0x182579a,0x15b1af8,0x02d8cce,0x36cb49b,0x086feba,0x2911d17,
        0x268ee12,0x011e871,0x18698dc,0x35602b3,0x11b9ec2,0x0ade731,
        0x0f6a05a,0x1821015,0x00007da } },
    /* 97 */
    { { 0x3b00dd0,0x328d485,0x27a69e3,0x32c3a06,0x1046779,0x120b61c,
        0x19fef3d,0x0fef2e6,0x134d923,0x039bce0,0x348cd0e,0x0b0c007,
        0x066ae11,0x15d8f1b,0x00934e7 },
      { 0x33234dc,0x353f0f5,0x2fc1b44,0x18a193a,0x2fcae20,0x1afbc86,
        0x3afe252,0x17f7e10,0x107f3b7,0x2d84d54,0x394c2e6,0x19e96a9,
        0x0a37283,0x26c6152,0x003d262 } },
    /* 98 */
    { { 0x37cfaf8,0x01863d0,0x0299623,0x32c80cb,0x25b8742,0x0a4d90e,
        0x1f72472,0x13de652,0x31a0946,0x0ee0103,0x0f25414,0x2518b49,
        0x07e7604,0x1488d9b,0x00abd6b },
      { 0x1338f55,0x2ce4af5,0x1a0c119,0x3380525,0x21a80a9,0x235d4df,
        0x118ca7f,0x2dd8bcc,0x1c26bf4,0x32dc56b,0x28482b6,0x1418596,
        0x3c84d24,0x1f1a5a9,0x00d958d } },
    /* 99 */
    { { 0x1c21f31,0x22aa1ef,0x258c9ad,0x2d2018f,0x0adb3ca,0x01f75ee,
        0x186283b,0x31ad3bf,0x3621be7,0x3b1ee6d,0x015582d,0x3d61d04,
        0x2ddf32e,0x14b8a66,0x00c970c },
      { 0x2f24d66,0x00b8a88,0x100a78f,0x041d330,0x2efec1d,0x24c5b86,
        0x2a6a390,0x37526bc,0x2055849,0x3339f08,0x16bffc4,0x07f9d72,
        0x06ec09c,0x3f49ee8,0x00cad98 } },
    /* 100 */
    { { 0x248b73e,0x1b8b42d,0x285eed7,0x39473f4,0x1a9f92c,0x3b44f78,
        0x086c062,0x06a4ea3,0x34ea519,0x3c74e95,0x1ad1b8b,0x1737e2c,
        0x2cfe338,0x0a291f4,0x00bbecc },
      { 0x1cec548,0x0c9b01a,0x20b298d,0x377c902,0x24f5bc1,0x2415c8d,
        0x1a70622,0x2529090,0x1c5c682,0x283f1ba,0x2319f17,0x0120e2e,
        0x01c6f4d,0x33c67ff,0x008b612 } },
    /* 101 */
    { { 0x03830eb,0x02d4053,0x10c59bb,0x0f23b83,0x13d08f8,0x26ea4e2,
        0x2626427,0x0a45292,0x0449cbc,0x0175750,0x074c46f,0x27ae0f8,
        0x2d7d6ae,0x163dd3a,0x0063bb7 },
      { 0x2bb29e0,0x034bab1,0x341e1c4,0x21d2c0b,0x295aa2d,0x0f2c666,
        0x1891755,0x13db64a,0x2fe5158,0x337646e,0x31a1aae,0x057bee4,
        0x00f9e37,0x396d19e,0x00c1b6a } },
    /* 102 */
    { { 0x2772f41,0x34f92d0,0x39d1cde,0x174ef2d,0x03a700d,0x03fbb98,
        0x30d50e8,0x352ed10,0x1fcf5e5,0x3d113bc,0x26e358f,0x180653f,
        0x1b43cc6,0x3cc9aa4,0x00e68a2 },
      { 0x37fe4d2,0x09dd725,0x01eb584,0x171f8a9,0x278fdef,0x3e37c03,
        0x3bec02f,0x149757c,0x0cd5852,0x37d2e10,0x0e6988b,0x1c120e9,
        0x0b83708,0x38e7319,0x0039499 } },
    /* 103 */
    { { 0x08df5fe,0x177a02c,0x0362fc0,0x1f18ee8,0x00c1295,0x173c50a,
        0x379414d,0x1885ba8,0x32a54ef,0x2315644,0x39e65cf,0x357c4be,
        0x1d66333,0x09e05a5,0x0009c60 },
      { 0x1f7a2fb,0x073b518,0x2eb83ac,0x11353d7,0x1dd8384,0x0c63f2b,
        0x238c6c8,0x2a1920a,0x2e5e9f1,0x1cc56f8,0x042daf4,0x1ed5dc5,
        0x25f9e31,0x012a56a,0x0081b59 } },
    /* 104 */
    { { 0x321d232,0x2c71422,0x3a756b6,0x30230b2,0x387f3db,0x3a7c3eb,
        0x274b46a,0x201e69f,0x185bb7b,0x140da82,0x0d974a2,0x0616e42,
        0x35ec94f,0x3bc366b,0x005aa7c },
      { 0x3dcfffc,0x19a9c15,0x3225e05,0x36ae114,0x16ea311,0x0cda2aa,
        0x2a1a8d2,0x154b5cb,0x08348cd,0x17b66c8,0x080ea43,0x21e59f3,
        0x04173b9,0x31d5b04,0x00ad735 } },
    /* 105 */
    { { 0x2e76ef4,0x216acf3,0x2b93aea,0x112bc74,0x3449974,0x2b2e48f,
        0x11929be,0x2f03021,0x19051e3,0x0ac202d,0x19be68a,0x3b87619,
        0x26cdac4,0x086592c,0x00f00de },
      { 0x2e90d4d,0x3ed703c,0x2c648d7,0x29ddf67,0x000e219,0x3471247,
        0x26febd5,0x1161713,0x3541a8f,0x302038d,0x08d2af9,0x26e1b21,
        0x398514a,0x36dad99,0x002ed70 } },
    /* 106 */
    { { 0x06f25cb,0x1104596,0x370faee,0x07e83f3,0x0f7b686,0x228d43a,
        0x12cd201,0x0a1bd57,0x3e592dc,0x1e186fc,0x2226aba,0x2c63fe9,
        0x17b039a,0x1efaa61,0x00d1582 },
      { 0x2e6acef,0x07d51e4,0x3ac326c,0x322b07e,0x1422c63,0x32ff5c7,
        0x18760df,0x048928b,0x139b251,0x04d7da9,0x048d1a2,0x2a23e84,
        0x199dbba,0x2fa7afe,0x0049f1a } },
    /* 107 */
    { { 0x3492b73,0x27d3d3d,0x2b1a16f,0x07b2ce4,0x0cf28ec,0x2729bff,
        0x3130d46,0x3e96116,0x140b72e,0x14a2ea3,0x1ca066f,0x3a61f1d,
        0x022ebac,0x09192b4,0x003e399 },
      { 0x12555bb,0x0b6139d,0x239463a,0x12a70ab,0x2aaa93b,0x2254e72,
        0x00424ec,0x26a6736,0x26daa11,0x25b5ad6,0x379f262,0x140cd30,
        0x0c7d3bd,0x097bbcf,0x00899e9 } },
    /* 108 */
    { { 0x3825dc4,0x3cd946f,0x0462b7f,0x31102e7,0x30f741c,0x3313ed6,
        0x1ff5a95,0x15bf9dc,0x09b47fd,0x0f2e7a7,0x1626c0d,0x3c14f6d,
        0x14098bd,0x19d7df8,0x00a97ce },
      { 0x0934f5e,0x3f968db,0x046f68a,0x12333bf,0x26cd5e1,0x1ea2161,
        0x358570d,0x235031d,0x35edd55,0x05265e3,0x24ae00c,0x3542229,
        0x25bb2a1,0x1c83c75,0x0058f2a } },
    /* 109 */
    { { 0x24daedb,0x376928f,0x305266f,0x0499746,0x038318c,0x312efd7,
        0x1910a24,0x33450a3,0x1c478a9,0x39d8bf9,0x12cc0ae,0x397aeab,
        0x0654c08,0x095f283,0x00d2cdf },
      { 0x0b717d2,0x1f162c2,0x107a48f,0x128e1b3,0x2380718,0x39f4044,
        0x00f626a,0x05ec0c9,0x21bc439,0x200fa4d,0x20aea01,0x186a1d8,
        0x26372f2,0x1a91f87,0x0053f55 } },
    /* 110 */
    { { 0x3512a90,0x33b958b,0x29f1c84,0x0106c3a,0x224b3c0,0x09b307a,
        0x215d2de,0x3bdf43b,0x22cf0c9,0x176121d,0x1534143,0x09ba717,
        0x16b3110,0x0f73f6c,0x008f5b7 },
      { 0x2c75d95,0x26fbcb4,0x0dda1f6,0x206f819,0x28d33d5,0x1fb4d79,
        0x024c125,0x30a0630,0x1f9c309,0x0fe350d,0x1696019,0x0a54187,
        0x09541fd,0x35e3a79,0x0066618 } },
    /* 111 */
    { { 0x0e382de,0x33f5163,0x0dde571,0x3bb7a40,0x1175806,0x12ae8ed,
        0x0499653,0x3b25586,0x38ade7a,0x3fa265d,0x3f4aa97,0x3c03dbb,
        0x30c6de8,0x32d4042,0x00ae971 },
      { 0x2f788f1,0x1fbaf0e,0x3e2d182,0x3ff904f,0x0d46229,0x1d0726d,
        0x15455b4,0x093ae28,0x290f8e4,0x097c0b9,0x1ae8771,0x28480bb,
        0x04f6d40,0x3689925,0x0049b3b } },
    /* 112 */
    { { 0x35b2d69,0x31819c0,0x11b0d63,0x035afb6,0x2b50715,0x2bece6c,
        0x35f82f7,0x0ad987c,0x0011601,0x02e6f67,0x2d0a5f5,0x365e583,
        0x2f7c900,0x11449c5,0x00ed705 },
      { 0x27abdb4,0x1bbfd04,0x301c157,0x263c079,0x36850d6,0x3f21f8b,
        0x27d7493,0x0f9227e,0x06fb0ce,0x002daf3,0x37d8c1c,0x3ef87d7,
        0x19cc6f4,0x0c3809c,0x00cf752 } },
    /* 113 */
    { { 0x22d94ed,0x075b09c,0x020e676,0x084dc62,0x2d1ec3f,0x17439f1,
        0x240b702,0x33cc596,0x30ebaf3,0x0359fe0,0x393ea43,0x0ece01e,
        0x16c6963,0x03a82f2,0x0017faa },
      { 0x3866b98,0x3cd20b7,0x12d4e6b,0x3a6a76d,0x1205c1e,0x3e6ae1a,
        0x2f9bbdf,0x2e61547,0x2d175ee,0x28e18f6,0x13cf442,0x085b0ef,
        0x0e321ef,0x238fe72,0x003fb22 } },
    /* 114 */
    { { 0x360ac07,0x26dc301,0x3f4d94f,0x2ba75e6,0x1f3c9cc,0x17ff20f,
        0x0ea084c,0x30e39cf,0x143dc49,0x03bd43e,0x3c9e733,0x19e8aba,
        0x27fbaf4,0x12d913a,0x005ee53 },
      { 0x3609e7f,0x2d89c80,0x09f020c,0x1558bf7,0x3098443,0x3c515fd,
        0x1c8e580,0x16506bd,0x26cb4b2,0x1747d42,0x2ec8239,0x32c91f0,
        0x1ca3377,0x079768f,0x00a5f3e } },
    /* 115 */
    { { 0x185fa94,0x122759f,0x0e47023,0x0dcb6e7,0x10ba405,0x3b5eab4,
        0x1f7a1fa,0x32d003f,0x1739a4c,0x3295ec3,0x1b18967,0x3f3b265,
        0x34d2448,0x2dbadc9,0x00f30b5 },
      { 0x01c5338,0x2d1dcf2,0x2bd07cc,0x39a8fb5,0x2b85639,0x355bab6,
        0x1df95f1,0x01eb5f6,0x17f0a16,0x1b895b5,0x157574d,0x29fff72,
        0x3a8c46d,0x0118071,0x0065f84 } },
    /* 116 */
    { { 0x3a1e7f1,0x17432f2,0x1f648d4,0x3000ad5,0x2ef0a08,0x1f86624,
        0x1ca31b1,0x241f9dc,0x2cb4885,0x2b8610f,0x364ce16,0x1e5faf0,
        0x0b33867,0x2cb637d,0x00816d2 },
      { 0x1aa8671,0x02c394e,0x35f5e87,0x393040a,0x39f0db3,0x1c831a5,
        0x2966591,0x034a8d0,0x09e613c,0x042b532,0x018ddd6,0x3e402c9,
        0x2e20e1a,0x29cb4cd,0x00e087c } },
    /* 117 */
    { { 0x3a10079,0x20c7fea,0x3ff2222,0x1edb593,0x00dc5f8,0x3a32ccc,
        0x1479073,0x0cfed11,0x2a2702a,0x17a056a,0x1fba321,0x235acb9,
        0x149c833,0x172de7d,0x000f753 },
      { 0x2e95923,0x3b365cb,0x009f471,0x0df1b47,0x21e868b,0x199bbd3,
        0x07b8ecc,0x12ff0af,0x189808a,0x3bd5059,0x3fbc4d2,0x0fa7b88,
        0x1125bf2,0x0db0b5d,0x0043572 } },
    /* 118 */
    { { 0x29cdb1b,0x1db656e,0x391efe1,0x004be09,0x245a1ca,0x3793328,
        0x254af24,0x2f2e65d,0x10e5cc4,0x2af6fe7,0x2d97ac0,0x29f7d42,
        0x19fd6f6,0x0ac184d,0x00c5211 },
      { 0x305eae3,0x36738d3,0x2c2b696,0x00ba50e,0x3903adc,0x2122f85,
        0x0753470,0x1cf96a4,0x1702a39,0x247883c,0x2feb67e,0x2ab3071,
        0x3c6b9e1,0x30cb85a,0x002ca0a } },
    /* 119 */
    { { 0x3871eb5,0x284b93b,0x0a7affe,0x176a2fc,0x294c2f2,0x204d3aa,
        0x1e4c2a7,0x3ec4134,0x2fb0360,0x3847b45,0x05fc11b,0x0a6db6e,
        0x390fa40,0x2adfd34,0x005e9f7 },
      { 0x0646612,0x1b5cbcc,0x10d8507,0x0777687,0x3a0afed,0x1687440,
        0x0222578,0x1af34a4,0x2174e27,0x372d267,0x11246c3,0x34769c5,
        0x2044316,0x1b4d626,0x00c72d5 } },
    /* 120 */
    { { 0x2e5bb45,0x3ff1d36,0x16dcdf5,0x128986f,0x399068c,0x2a63b1e,
        0x0afa7aa,0x3a5b770,0x200f121,0x33b74bb,0x1414045,0x0f31ef8,
        0x2f50e16,0x2f38cd6,0x00b0b1b },
      { 0x1a06293,0x035e140,0x2644d44,0x1f1954b,0x2cdebab,0x31d5f91,
        0x0b8dbc8,0x38f2d23,0x3783cab,0x2a07e73,0x3123f59,0x3409846,
        0x3784ddd,0x223bbac,0x003dc7b } },
    /* 121 */
    { { 0x0741456,0x234e631,0x2121e1b,0x00980ca,0x3a9dfa9,0x098c916,
        0x3fc86d1,0x1c63072,0x3625244,0x13d0471,0x05b0fc5,0x1487550,
        0x2498596,0x11bb6ea,0x001afab },
      { 0x274b4ad,0x240aea1,0x3d12a75,0x2b56b61,0x1486b43,0x1b83426,
        0x31c7363,0x35b59ca,0x207bb6c,0x38e6243,0x19bace4,0x0a26671,
        0x35e3381,0x0c2ded4,0x00d8da4 } },
    /* 122 */
    { { 0x2b75791,0x19590b1,0x2bfb39f,0x2988601,0x0050947,0x0d8bbe1,
        0x23e3701,0x08e4432,0x2ed8c3d,0x326f182,0x332e1dd,0x12219c5,
        0x2e0779b,0x367aa63,0x0012d10 },
      { 0x251b7dc,0x0a08b4d,0x1138b6f,0x2ea02af,0x06345a5,0x1cb4f21,
        0x0332624,0x1d49d88,0x140acc5,0x2f55287,0x024447c,0x291ace9,
        0x1a4966e,0x015cbec,0x005bc41 } },
    /* 123 */
    { { 0x351cd0e,0x315e8e9,0x07d6e70,0x067ae8f,0x2190d84,0x351f556,
        0x03bee79,0x31b62c7,0x266f912,0x1b6a504,0x007a6ad,0x3a6ab31,
        0x3891112,0x3c45ba0,0x00d6ce5 },
      { 0x0e1f2ce,0x32a5edc,0x1434063,0x1ca084f,0x2a3e47c,0x137e042,
        0x16e2418,0x2069280,0x3b0dfd8,0x35a22b5,0x289bf0a,0x1f667f2,
        0x02d23a3,0x0ce688f,0x00d8e3f } },
    /* 124 */
    { { 0x10bed6f,0x14c58dd,0x0b0abdf,0x0ca0f9a,0x3808abc,0x2ec228c,
        0x2366275,0x12afa16,0x20f6b0e,0x37dca8e,0x3af0c6a,0x1c5b467,
        0x1b25ff7,0x00814de,0x0022dcc },
      { 0x1a56e11,0x02fe37e,0x3f21740,0x35d5a91,0x06cb8ba,0x29bad91,
        0x17176f7,0x2d919f2,0x0f7d1f5,0x13a3f61,0x04ddb05,0x0c82a51,
        0x286f598,0x2e8c777,0x0007071 } },
    /* 125 */
    { { 0x0f8fcb9,0x3e83966,0x170c6fd,0x3825343,0x089cec8,0x01b482a,
        0x0993971,0x3327282,0x39aba8a,0x32456fe,0x1507e01,0x1c3252d,
        0x21ffb13,0x29822a0,0x0083246 },
      { 0x23c378f,0x1cea7ef,0x1be9a82,0x224d689,0x37e5447,0x3764a75,
        0x3a49724,0x361e1b3,0x19d365b,0x3a61ffb,0x1c29a7a,0x20ab251,
        0x17ec549,0x175d777,0x004589a } },
    /* 126 */
    { { 0x15540a9,0x2ec5d2a,0x05b09fa,0x1bc058b,0x07cfb88,0x28f7b86,
        0x3e766be,0x189305e,0x01fe88e,0x23fdf69,0x0b919c3,0x02dc7ae,
        0x3f9a9ad,0x0b83cc7,0x0086a52 },
      { 0x28bc259,0x39bdca1,0x39e4bc8,0x0e0f33b,0x16130c6,0x2919955,
        0x31f4549,0x2fed027,0x30919b2,0x0a39b03,0x0ca7bb2,0x1711b24,
        0x3b67b94,0x05a136b,0x00acd87 } },
    /* 127 */
    { { 0x0c53841,0x31cb284,0x3ced090,0x06d5693,0x1c20ae0,0x0408d2b,
        0x37ebd5e,0x081900f,0x26a8589,0x0acfd0a,0x34a1472,0x2f0c302,
        0x124ccbd,0x10de328,0x00971bc },
      { 0x17ff2ff,0x27d1b54,0x147b6f7,0x38bb2ea,0x26a9c96,0x0a49448,
        0x39f2f46,0x247c579,0x3b16a4e,0x28c2a5a,0x2d4c72d,0x11f248c,
        0x1e4df11,0x047d604,0x0065bc3 } },
    /* 128 */
    { { 0x39b3239,0x1f75f44,0x3bae87c,0x139360c,0x18b5782,0x3ffc005,
        0x3c48789,0x2bc6af2,0x38b909e,0x223ff3b,0x31443a7,0x017d3bb,
        0x0bfed99,0x128b857,0x00020dd },
      { 0x306d695,0x25a7b28,0x2f60ca2,0x2b6e4f2,0x1df940c,0x1fa9b8e,
        0x37fab78,0x13f959f,0x10ff98c,0x38343b8,0x019cb91,0x11a1e6b,
        0x17ab4c6,0x1431f47,0x004b4ea } },
    /* 129 */
    { { 0x20db57e,0x102515e,0x170219e,0x2b66a32,0x1e6017c,0x2f973fe,
        0x3739e51,0x0e28b6f,0x3cda7a9,0x30d91ac,0x28350df,0x1444215,
        0x098b504,0x1bcd5b8,0x00ad3bd },
      { 0x22e3e3e,0x3aeaffb,0x26cb935,0x0091ce4,0x2fbd017,0x3a7ed6a,
        0x335b029,0x3bfc1f1,0x3852e3f,0x2b14a86,0x046b405,0x266af4c,
        0x3997191,0x33b0e40,0x00e306f } },
    /* 130 */
    { { 0x3e4712c,0x26bb208,0x18eed6d,0x1b30f06,0x27ca837,0x06faf62,
        0x1831873,0x3fbcf9b,0x3f3d88b,0x1fb55eb,0x0f44edc,0x29917bb,
        0x3151772,0x342d72e,0x00d4e63 },
      { 0x2ee0ecf,0x39e8733,0x2e8e98c,0x0cd4e0f,0x08f0126,0x1ad157a,
        0x079078a,0x23018ee,0x196c765,0x2b2f34f,0x0783336,0x075bf9c,
        0x3713672,0x098d699,0x00f21a7 } },
    /* 131 */
    { { 0x186ba11,0x22cf365,0x048019d,0x2ca2970,0x0d9e0ae,0x08c3bd7,
        0x261dbf2,0x2fc2790,0x1ee02e6,0x10256a7,0x00dc778,0x18dc8f2,
        0x157b189,0x2ebc514,0x005c97d },
      { 0x3c4503e,0x1d10d12,0x337097e,0x0c6169a,0x30fb1cb,0x3481752,
        0x0df2bec,0x19768fa,0x1bcf8f7,0x2925f74,0x2c988a1,0x3be571d,
        0x04cfa92,0x2ea9937,0x003f924 } },
    /* 132 */
    { { 0x268b448,0x06e375c,0x1b946bf,0x287bf5e,0x3d4c28b,0x138d547,
        0x21f8c8e,0x21ea4be,0x2d45c91,0x35da78e,0x00326c0,0x210ed35,
        0x1d66928,0x0251435,0x00fefc8 },
      { 0x0339366,0x216ff64,0x2c3a30c,0x3c5733d,0x04eeb56,0x2333477,
        0x32b1492,0x25e3839,0x1b5f2ce,0x0dcfba1,0x3165bb2,0x3acafcc,
        0x10abfcd,0x248d390,0x008106c } },
    /* 133 */
    { { 0x102f4ee,0x3c0585f,0x1225c8d,0x11c6388,0x08a7815,0x2b3e790,
        0x2895eb6,0x18cf53a,0x0b56e5a,0x2e2c003,0x3e981ff,0x0761b55,
        0x1bc32f3,0x0a7111d,0x00f5c80 },
      { 0x3568973,0x1587386,0x16ec764,0x20698a6,0x02f809b,0x2821502,
        0x113d64d,0x38c2679,0x15de61c,0x0309f60,0x272999e,0x29bfe64,
        0x173f70d,0x1de7fab,0x00bd284 } },
    /* 134 */
    { { 0x31cdf2b,0x0f0be66,0x2151603,0x01af17e,0x32a99cf,0x085dece,
        0x27d2591,0x1520df4,0x273c448,0x1ec7c54,0x102e229,0x355f604,
        0x2acb75f,0x005f1fd,0x003d43e },
      { 0x270eb28,0x22ec2ce,0x306b41a,0x238fa02,0x167de2d,0x030a379,
        0x245a417,0x1808c24,0x0b1a7b2,0x3ab5f6f,0x2cbc6c1,0x2c228d4,
        0x3041f70,0x2d9a6cc,0x00b504f } },
    /* 135 */
    { { 0x17a27c2,0x216ad7e,0x011ba8e,0x22f0428,0x16ac5ec,0x3ef3c58,
        0x345533f,0x0298155,0x2856579,0x0005e03,0x19ee75b,0x146fe16,
        0x29881e4,0x18ece70,0x008907a },
      { 0x20189ed,0x119ce09,0x35cb76d,0x0d91ef4,0x2284a44,0x032ad87,
        0x0e8c402,0x3c82b5d,0x38c416c,0x398992f,0x1fd820c,0x169b255,
        0x3b5fcfa,0x1343c92,0x00fa715 } },
    /* 136 */
    { { 0x33f5034,0x20b3b26,0x28fd184,0x16b3679,0x3962d44,0x15d1bc8,
        0x2fb1d69,0x1292c99,0x25a58c9,0x1b19ab7,0x2d68a5b,0x2f6a09b,
        0x0d6aedb,0x2935eac,0x0005664 },
      { 0x25e32fc,0x13f9440,0x3252bcd,0x2fea5b7,0x161a5ae,0x0564a8c,
        0x0a07e23,0x1545f62,0x0de9890,0x1d76765,0x1fd440e,0x2ed0041,
        0x3db4c96,0x1e8ba01,0x001b0c4 } },
    /* 137 */
    { { 0x0223878,0x29ab202,0x15585c2,0x1a79969,0x1ba08c2,0x2ef09ff,
        0x2b1b9b9,0x181f748,0x1bf72b9,0x224645c,0x2588dc5,0x2d157e7,
        0x22d939a,0x05b88d9,0x006d549 },
      { 0x31de0c1,0x23a4e0e,0x278f8da,0x1aa013c,0x1a84d18,0x0d185a5,
        0x0988ccd,0x2c32efd,0x3bee10e,0x37d7ab8,0x3f2a66e,0x3e2da3e,
        0x1b5701f,0x3d9f0c1,0x00a68da } },
    /* 138 */
    { { 0x0b2e045,0x0133fd1,0x05d4c10,0x0d92c70,0x391b5e1,0x2292281,
        0x2e40908,0x2ec694e,0x195ea11,0x29cfeca,0x3d93a4e,0x01215c0,
        0x08a5f32,0x37a0eff,0x00cce45 },
      { 0x2b3106e,0x12a5fb0,0x0b4faff,0x0c2da12,0x09069c6,0x35d8907,
        0x2837a6e,0x3db3fb6,0x3136cc3,0x222836b,0x3da018a,0x2741274,
        0x13ba319,0x1ac7642,0x00f867c } },
    /* 139 */
    { { 0x2527296,0x10a9595,0x178de4d,0x0f739c4,0x0ae26c7,0x3094599,
        0x20adac6,0x2b875c2,0x3ae5dc0,0x3e04d20,0x1aab2da,0x1d3ab37,
        0x15f4f75,0x0b730b5,0x00c56b5 },
      { 0x1f32923,0x2f059e5,0x2a89872,0x2056f74,0x04be175,0x1da67c0,
        0x17f1e7a,0x3780a6d,0x0723ac2,0x257f367,0x1237773,0x2bcee86,
        0x0b97f83,0x38aff14,0x00a64d4 } },
    /* 140 */
    { { 0x2552b40,0x0b6b883,0x12e8217,0x0974d35,0x062f497,0x1e563e6,
        0x30ee400,0x375d1e4,0x290751f,0x0d5b68a,0x353e48c,0x064a0d3,
        0x3c343f1,0x309a394,0x0034d2a },
      { 0x3111286,0x0f08604,0x1827107,0x0536a76,0x0201dac,0x3a574de,
        0x2c29dbe,0x382c7b0,0x1191f3e,0x324c5bc,0x144ce71,0x24327c1,
        0x1212778,0x22bc9d8,0x00d7713 } },
    /* 141 */
    { { 0x34ad1cd,0x1179b4e,0x1bc1780,0x1392a92,0x2cd86b9,0x359de85,
        0x251f1df,0x0da5d5f,0x135fa61,0x0f64a42,0x34f4d89,0x0fe564c,
        0x3cf9b7a,0x122d757,0x008c9c2 },
      { 0x370d4e9,0x0e9209b,0x0ae99f2,0x1518c64,0x0172734,0x2c20692,
        0x1d7c135,0x149c52f,0x38928d6,0x3c78b78,0x25841d1,0x2eaa897,
        0x372e50b,0x29e5d19,0x00c4c18 } },
    /* 142 */
    { { 0x13375ac,0x389a056,0x211310e,0x2f9f757,0x04f3288,0x103cd4e,
        0x17b2fb2,0x2c78a6a,0x09f1de6,0x23e8442,0x1351bc5,0x1b69588,
        0x285b551,0x0464b7e,0x00573b6 },
      { 0x0ba7df5,0x259a0db,0x2b4089e,0x05630a2,0x3f299be,0x350ff2f,
        0x1c9348a,0x3becfa4,0x3cc9a1c,0x17a6ef1,0x338b277,0x2b761d9,
        0x2aa01c8,0x3cb9dd7,0x006e3b1 } },
    /* 143 */
    { { 0x277788b,0x16a222d,0x173c036,0x310ff58,0x2634ae8,0x392636f,
        0x0987619,0x1e6acc1,0x26dc8f7,0x242310f,0x0c09aca,0x22b8e11,
        0x0d17006,0x1c2c806,0x002380c },
      { 0x297c5ec,0x1fef0e8,0x3948cf7,0x14f2915,0x2dacbc8,0x0dafb1f,
        0x10de043,0x31184da,0x06414ee,0x3c9aeeb,0x1f713ab,0x308f1f8,
        0x1569ed1,0x3f379bf,0x00f08bb } },
    /* 144 */
    { { 0x0770ee3,0x058fd21,0x17065f8,0x251d128,0x10e0c7f,0x06cb51b,
        0x0f05f7e,0x3666a72,0x3e7d01f,0x2d05fab,0x11440e5,0x28577d4,
        0x2fbcf2b,0x14aa469,0x00dc5c5 },
      { 0x270f721,0x1c75d28,0x085b862,0x1d68011,0x132c0a0,0x37be81d,
        0x1a87e38,0x083fa74,0x3acbf0d,0x16d6429,0x0feda1f,0x031070a,
        0x2ec2443,0x21e563d,0x00454d2 } },
    /* 145 */
    { { 0x0525435,0x1e98d5f,0x3dbc52b,0x1fcdf12,0x13d9ef5,0x3ff311d,
        0x393e9ed,0x3cef8ae,0x2987710,0x3bdee2e,0x21b727d,0x3ba1b68,
        0x10d0142,0x3c64b92,0x0055ac3 },
      { 0x0c1c390,0x38e9bb0,0x1e7b487,0x11511b3,0x1036fb3,0x25aba54,
        0x1eb2764,0x048d022,0x0d971ed,0x1bb7fb5,0x100f0b4,0x06c3756,
        0x2f0d366,0x3c6e160,0x0011bd6 } },
    /* 146 */
    { { 0x36bc9d1,0x24d43c1,0x12c35cf,0x2fb3cf3,0x015d903,0x16bc0c7,
        0x0fc8c22,0x3195c87,0x2488b1c,0x1f82b4c,0x30014e8,0x27ee58d,
        0x31658dd,0x1684a5f,0x00f0f3a },
      { 0x1f703aa,0x023eebc,0x20babb9,0x080bd9d,0x12f9cc4,0x1a8e2d4,
        0x0eec666,0x1176803,0x33005d6,0x1137b68,0x37de339,0x33d71cb,
        0x0c906b9,0x14086b5,0x00aeef6 } },
    /* 147 */
    { { 0x219045d,0x0f22c5e,0x024c058,0x00b414a,0x0ae7c31,0x3db3e96,
        0x234979f,0x0cf00a8,0x3c962c7,0x27fa77f,0x1c0c4b0,0x1fe8942,
        0x218053a,0x1eed3f8,0x0051643 },
      { 0x2a23ddb,0x138f570,0x104e945,0x21ca270,0x30726d8,0x3f45490,
        0x37d9184,0x242ea25,0x33f6d77,0x3f15679,0x065af85,0x34fa1f5,
        0x2e46b8f,0x31d17fb,0x00a2615 } },
    /* 148 */
    { { 0x335167d,0x181ea10,0x0887c8d,0x01383d7,0x18b42d8,0x263447e,
        0x1f13df3,0x0319d7e,0x0872074,0x2d6aa94,0x23d9234,0x36a69aa,
        0x0bad183,0x3138a95,0x00bd3a5 },
      { 0x1b0f658,0x0e4530b,0x373add1,0x1b968fc,0x329dcb6,0x09169ca,
        0x162df55,0x0211eff,0x02391e4,0x3867460,0x3136b1a,0x37dd36e,
        0x3bc5bd9,0x2dacfe4,0x0072a06 } },
    /* 149 */
    { { 0x119d96f,0x067b0eb,0x00996da,0x293eca9,0x2b342da,0x1889c7a,
        0x21633a6,0x0152c39,0x281ce8c,0x18ef3b3,0x0bd62dc,0x3238186,
        0x38d8b7c,0x3867b95,0x00ae189 },
      { 0x0ed1eed,0x1e89777,0x13ab73e,0x029e1d7,0x2c1257f,0x33fbc09,
        0x32d5a21,0x3d870b2,0x39bb1fd,0x33663bc,0x24e83e6,0x239bda4,
        0x3088bcd,0x01db1ed,0x00d71e7 } },
    /* 150 */
    { { 0x14245bf,0x0da0c27,0x153b339,0x05cab0a,0x122d962,0x1b0f0f3,
        0x3f5a825,0x267a2ce,0x2910d06,0x254326f,0x0f36645,0x025118e,
        0x37c35ec,0x36e944e,0x006c056 },
      { 0x05ab0e3,0x29aa0c1,0x1295687,0x1fd1172,0x08d40b5,0x05bd655,
        0x345048a,0x02a1c3c,0x2393d8f,0x0992d71,0x1f71c5e,0x18d4e8a,
        0x30dd410,0x11d61d3,0x00dd58b } },
    /* 151 */
    { { 0x2230c72,0x30213d8,0x05e367e,0x329204e,0x0f14f6c,0x3369ddd,
        0x0bb4074,0x2edafd6,0x1b1aa2d,0x0785404,0x0c035ab,0x220da74,
        0x1f2fdd4,0x092a091,0x00ef83c },
      { 0x3dc2538,0x1cca3e7,0x246afb5,0x24c647f,0x0798082,0x0bb7952,
        0x0f5c443,0x008b38a,0x299ea1a,0x3c6cf36,0x3df2ec7,0x398e6dc,
        0x29a1839,0x1cadd83,0x0077b62 } },
    /* 152 */
    { { 0x25d56d5,0x3546f69,0x16e02b1,0x3e5fa9a,0x03a9b71,0x2413d31,
        0x250ecc9,0x1d2de54,0x2ebe757,0x2a2f135,0x2aeeb9a,0x0d0fe2b,
        0x204cb0e,0x07464c3,0x00c473c },
      { 0x24cd8ae,0x0c86c41,0x221c282,0x0795588,0x1f4b437,0x06fc488,
        0x0c81ecd,0x020bf07,0x3a9e2c8,0x2294a81,0x3a64a95,0x0363966,
        0x32c9a35,0x0f79bec,0x0029e4f } },
    /* 153 */
    { { 0x289aaa5,0x2755b2e,0x059e0aa,0x3031318,0x0f0208a,0x35b7729,
        0x00d9c6b,0x3dd29d0,0x075f2c2,0x0ece139,0x31562dd,0x04187f2,
        0x13b8d4c,0x0920b85,0x003924e },
      { 0x09808ab,0x2e36621,0x2a36f38,0x1829246,0x229bf32,0x20883b7,
        0x159ada8,0x3108a14,0x15bbe5b,0x1e2d1e4,0x1730096,0x0d35cbb,
        0x15d0da9,0x0e60b94,0x00c4f30 } },
    /* 154 */
    { { 0x31de38b,0x27b9086,0x2760e3e,0x169098d,0x2a124e2,0x00596c6,
        0x3f73c09,0x0d31642,0x2341464,0x248600a,0x2e1fa10,0x2aa0fc8,
        0x051e954,0x00f3b67,0x001d4bd },
      { 0x18751e6,0x25a8e1e,0x07f5c2d,0x17e30d4,0x0ed2723,0x23093e2,
        0x3b80e2c,0x13de2d7,0x2fad37f,0x1be1cfb,0x3224ba9,0x0a7f5d3,
        0x1714972,0x06667b7,0x009dcd9 } },
    /* 155 */
    { { 0x294f22a,0x3e06993,0x0341ee9,0x24bdc7b,0x2e56098,0x2660a13,
        0x018ddda,0x2c261b2,0x2953b54,0x267f51c,0x0e8a7cc,0x29ab00c,
        0x3a38247,0x397ac81,0x00de684 },
      { 0x36b956b,0x347b34a,0x35834bd,0x053c06c,0x0090844,0x148cec5,
        0x380b325,0x2f17b8b,0x054ef5e,0x09683fb,0x3f8b29a,0x33c979a,
        0x1e01474,0x3e81fca,0x001c757 } },
    /* 156 */
    { { 0x30fdfe4,0x2d712ba,0x13671bc,0x2cfc226,0x3d7c649,0x16f020e,
        0x368e3f0,0x2981ebb,0x246a78a,0x115e81b,0x21223a4,0x04dbb30,
        0x1a50ba2,0x12114bd,0x0089bd6 },
      { 0x055f15a,0x1046e51,0x00fd724,0x1c022a7,0x323dfa9,0x36d8efb,
        0x0da4d16,0x0910dec,0x2c1fb16,0x2dbe29f,0x298284f,0x2b273bb,
        0x26022c1,0x20accd5,0x00085a5 } },
    /* 157 */
    { { 0x01f138a,0x2d87e7b,0x0c2815c,0x0c19a3c,0x311c9a2,0x3e4fce3,
        0x029729d,0x21236b2,0x2984048,0x3f3bc95,0x2bba8fb,0x1a1b680,
        0x0619a3f,0x29e0447,0x00ed5fe },
      { 0x2d1c833,0x3dcef35,0x3f809b4,0x01a1b9e,0x1509516,0x10ac754,
        0x2735080,0x27b0a8a,0x2495fb8,0x0a7bdba,0x1ef8b89,0x00233a5,
        0x0568bf1,0x1a126ba,0x0078a7e } },
    /* 158 */
    { { 0x0470cd8,0x20e9f04,0x30003fe,0x20be1b7,0x1927346,0x2a5026d,
        0x1ac06bd,0x2717ed7,0x2609493,0x3079ea5,0x1cc116d,0x31b0541,
        0x2c8ccde,0x10219ae,0x001a52b },
      { 0x2864045,0x0e8d95b,0x2fc1530,0x0aa44e7,0x345eae7,0x3cc7553,
        0x3ec6466,0x229b60e,0x06f6e95,0x00bed2a,0x0ff4403,0x181c639,
        0x2e0df67,0x1f8fa46,0x0000811 } },
    /* 159 */
    { { 0x04310a2,0x20cee8e,0x09fc5d5,0x3707f5b,0x0bdfb4e,0x12713ee,
        0x24f1028,0x0787ee6,0x39a581c,0x3797ec8,0x10a9746,0x112cb9f,
        0x142b9ba,0x1da0ef6,0x0078f7b },
      { 0x07607ae,0x3232872,0x2a7e076,0x0bb572a,0x182b23c,0x1d8f918,
        0x181f392,0x37c45a9,0x24a3886,0x0b2a297,0x264e7f2,0x1fa433c,
        0x0fcfcc8,0x21c0857,0x0004f74 } },
    /* 160 */
    { { 0x01d161c,0x1744585,0x2d17528,0x03a4f13,0x267cd2e,0x30d861f,
        0x062a647,0x213284b,0x139ed25,0x27d4ca5,0x02fbbd6,0x31ddf11,
        0x3c50ac4,0x1dd86f7,0x00107de },
      { 0x16beebd,0x1b7317a,0x2151997,0x256a196,0x3be2aff,0x3621cab,
        0x0a9da19,0x05f3038,0x23da63c,0x3178d5e,0x215cc67,0x07f7f63,
        0x0c6d8d3,0x3bf5e5c,0x00c44bb } },
    /* 161 */
    { { 0x00c62f1,0x3e0f893,0x1572703,0x3b93865,0x19b1e28,0x389b33b,
        0x02858bf,0x0e3e9aa,0x04bc436,0x234e072,0x25ba43d,0x3dca19e,
        0x0274394,0x20f442e,0x003b4a7 },
      { 0x176451e,0x2b5ed5d,0x35c8ee1,0x25c52da,0x0c3d0b5,0x32b306e,
        0x030954f,0x275ecf7,0x10e472c,0x21577c4,0x02f8a32,0x321bb5c,
        0x0098f97,0x104e237,0x00d0433 } },
    /* 162 */
    { { 0x0a8f2fe,0x034548b,0x141f1a6,0x121246f,0x1616409,0x237f80d,
        0x2e29a55,0x1218db6,0x3ea278e,0x1669856,0x1ad7c8e,0x36d11de,
        0x2c2fcbb,0x18c0b3a,0x001c706 },
      { 0x1699b4b,0x2d531a6,0x17e85e2,0x1b48e78,0x2b509ca,0x2818ea0,
        0x0165fee,0x0b809ca,0x09db6a2,0x3dad798,0x326ee1d,0x204e416,
        0x091fa12,0x1c890e5,0x0007b9f } },
    /* 163 */
    { { 0x0ff4e49,0x0bb0512,0x0129159,0x05db591,0x03e4e9f,0x055ab30,
        0x0f82881,0x0ac2deb,0x3a8bb09,0x356a8d2,0x3d38393,0x03e4089,
        0x38187cd,0x1377a93,0x0041672 },
      { 0x0139e73,0x3990730,0x187d3c4,0x33e4793,0x2e0fe46,0x2ad87e2,
        0x33c792c,0x21d4fb6,0x1e4d386,0x2932d1b,0x20f1098,0x1270874,
        0x0ea6ee4,0x0167d6e,0x005e5fd } },
    /* 164 */
    { { 0x1856031,0x2b7519d,0x3bd07fc,0x337abcb,0x089c7a4,0x2a1f120,
        0x3523ce7,0x2ba406b,0x09561d9,0x1797f04,0x3cdb95f,0x2d6193e,
        0x32c7d3f,0x223aed6,0x00beb51 },
      { 0x2e65825,0x158f0ce,0x16413d1,0x310395f,0x3116854,0x250baf4,
        0x373d341,0x156cc47,0x104c069,0x0893716,0x195a0a6,0x035320e,
        0x37b7d8a,0x21b5755,0x00fb26b } },
    /* 165 */
    { { 0x286ae17,0x04239f1,0x1a56c53,0x0e74707,0x29090d7,0x2bb142b,
        0x03b0139,0x1aac916,0x08ba49a,0x0376682,0x3382f85,0x064bbab,
        0x2910e28,0x1d5bd7f,0x00cc8df },
      { 0x0ab7630,0x208e8e7,0x3fc1877,0x26bee39,0x264984a,0x192ff05,
        0x08ef9c3,0x0aa6951,0x071c44e,0x26eed3e,0x035c95e,0x06906ad,
        0x10a0690,0x397eaa9,0x00c6c23 } },
    /* 166 */
    { { 0x034d8dd,0x005b064,0x279bb78,0x12c2c4f,0x1856bb4,0x0c90681,
        0x06409ab,0x3b48617,0x19a2d78,0x0a34bf8,0x326eddf,0x31f09b5,
        0x04f04dc,0x3d7c944,0x003ccaf },
      { 0x321f843,0x35fb71a,0x1e4c397,0x377a5d7,0x2da88e4,0x3d6ada7,
        0x33d3964,0x1b30149,0x0e39aae,0x054dda0,0x3e6f946,0x1273394,
        0x3ffd3f7,0x2f6655e,0x00021dd } },
    /* 167 */
    { { 0x37233cf,0x11617dd,0x26f07b6,0x3d8250a,0x0fe6771,0x3f9bbbc,
        0x2aba7ad,0x200a58d,0x3568603,0x198eefa,0x1e8fcf3,0x3b9610b,
        0x20524ac,0x2a67528,0x0048d9a },
      { 0x1a5e57a,0x1e9d303,0x16c9cff,0x0f39527,0x3c23259,0x03c8a1e,
        0x104bccf,0x182d5a1,0x18dbc83,0x05b5f42,0x1b402f4,0x317c525,
        0x11bf1ea,0x3c46e1f,0x0061936 } },
    /* 168 */
    { { 0x0153a9d,0x36859ee,0x2cf0aa9,0x2b27a0f,0x0a49fe3,0x2d984e1,
        0x018f8e1,0x1378453,0x1ab3843,0x1987093,0x283dae9,0x25cf0e8,
        0x14fc93d,0x280609d,0x00c99ba },
      { 0x026b1e3,0x34663d3,0x2202477,0x21a9d45,0x212e8e1,0x18ab77e,
        0x2e52f63,0x0a14ce1,0x295c396,0x00c7a3d,0x2aaedb6,0x30abc4d,
        0x374acde,0x1318a73,0x00fcfdb } },
    /* 169 */
    { { 0x0a40298,0x3ba5633,0x11956b3,0x14fcbd7,0x3c38781,0x34bab96,
        0x165630e,0x1f3c831,0x37e3a69,0x2b4226c,0x2d5029e,0x3b4ab1e,
        0x1da6ac2,0x3eb43c3,0x007e5cd },
      { 0x1b86202,0x109b7f6,0x2054f98,0x2c50cd7,0x2ed1960,0x3c518e7,
        0x1b02463,0x319c07f,0x1c30db6,0x045fdc2,0x373421e,0x31a1eb9,
        0x1a8acbf,0x31289b0,0x0013fef } },
    /* 170 */
    { { 0x3fa0a5f,0x068661f,0x2109e36,0x00b18ff,0x1f4b261,0x31d3844,
        0x0acbc56,0x3aebc99,0x1fa77ab,0x152bd11,0x24cddb7,0x2313f74,
        0x06eea44,0x15f5114,0x000b131 },
      { 0x2e9993d,0x1ac565c,0x2cbe22a,0x3921797,0x12c3c57,0x360f868,
        0x33560bf,0x320ee99,0x382c3b8,0x39af88f,0x00bbe38,0x2c4ea59,
        0x3399b40,0x00ceb45,0x0066eea } },
    /* 171 */
    { { 0x0c6c693,0x31ba56d,0x3d3849f,0x378dabd,0x0efc735,0x17f90bf,
        0x13343d3,0x2df0f81,0x27c6a9a,0x13c2a90,0x0a0fcb2,0x27c10d9,
        0x3bc50c7,0x090e4fa,0x0016287 },
      { 0x2927e1e,0x35af405,0x184c5c3,0x3499cee,0x240158e,0x33522e6,
        0x386fc84,0x0a0b69f,0x1a660ea,0x34590fb,0x22a1bee,0x2ce4fab,
        0x31a9445,0x0e78655,0x00664c8 } },
    /* 172 */
    { { 0x3eeaf94,0x115d409,0x21e7577,0x097aa67,0x22875c9,0x021ab7a,
        0x27e7ba5,0x1093f04,0x2a086fe,0x05d9494,0x2b6c028,0x10f31b0,
        0x1312d11,0x262759c,0x00c9bb2 },
      { 0x1acb0a5,0x30cdf14,0x0f78880,0x0574f18,0x1a37109,0x098adbb,
        0x2113c09,0x2060925,0x1f89ce4,0x1974976,0x3381358,0x2dab5ca,
        0x2159c53,0x3af1303,0x000ea3b } },
    /* 173 */
    { { 0x1e49bea,0x29142b1,0x1a59cab,0x055f017,0x0684e54,0x39eb0db,
        0x29cab9d,0x255ee8b,0x35f2e6f,0x05329e6,0x09b817b,0x1ec091c,
        0x1df0fef,0x2641f62,0x00eb304 },
      { 0x2fe5096,0x3dcc1d1,0x2aaf508,0x3a0b813,0x0695810,0x144bddb,
        0x2f1bd93,0x281ae23,0x3513ebc,0x1ddd984,0x0cf158b,0x35218eb,
        0x257daf7,0x391253b,0x00b2a81 } },
    /* 174 */
    { { 0x153e6ba,0x22396db,0x0ea2ff2,0x2a45121,0x0a90de1,0x34cf23b,
        0x2db60ce,0x1a900be,0x2f328b6,0x355e75b,0x2c24372,0x0b75b77,
        0x2ec7d4f,0x3f24759,0x00e9e33 },
      { 0x39eab6e,0x2267480,0x3b5e110,0x1e8fa5e,0x2a31a66,0x3f739a3,
        0x00166dc,0x3552d88,0x3ae5137,0x3efa0fa,0x0800acd,0x17df61d,
        0x38c8608,0x04cc31b,0x00cf4ab } },
    /* 175 */
    { { 0x31e08fb,0x1961164,0x22c003f,0x078541b,0x3643855,0x30da587,
        0x11f0dc9,0x324595e,0x329e3dc,0x29a041e,0x3495d2c,0x0908dd3,
        0x1895b83,0x198dbb9,0x00d8cfb },
      { 0x0349b1b,0x383c5a8,0x2b86525,0x1b1283e,0x133cd2c,0x2be376a,
        0x012ee82,0x1eb4d1b,0x0ba71e9,0x01f3109,0x37621eb,0x1d9b77c,
        0x0d39069,0x3d5a97c,0x0095565 } },
    /* 176 */
    { { 0x20f5e94,0x1eefc86,0x1327e0e,0x054760b,0x2f771e1,0x3ac447e,
        0x033e3dc,0x198e040,0x04dd342,0x1b49a5d,0x00d01ef,0x3cb6768,
        0x1ceafbd,0x31c6812,0x001cb80 },
      { 0x221c677,0x060ca27,0x398b17f,0x0146723,0x36452af,0x02d9e65,
        0x39c5f78,0x3cf50d6,0x0be40f8,0x2970b87,0x26d667c,0x3e45959,
        0x16e7943,0x01673e7,0x009faaa } },
    /* 177 */
    { { 0x2078fe6,0x0918602,0x11dd8ad,0x399193f,0x0f6cc73,0x0f8dd12,
        0x2ce34dc,0x06d7d34,0x0c5e327,0x0989254,0x2fc5af7,0x2443d7b,
        0x32bc662,0x2fe2a84,0x008b585 },
      { 0x039327f,0x08e616a,0x252f117,0x1f52ab0,0x234e2d2,0x0a5b313,
        0x2f59ef6,0x0f7a500,0x15c4705,0x2c02b81,0x28b4f09,0x08aa5c8,
        0x0180efc,0x0993e83,0x00a9e86 } },
    /* 178 */
    { { 0x0310ecc,0x2d8892f,0x14ed0b7,0x3c59fe8,0x08a1a74,0x0850e57,
        0x1d09607,0x044a21f,0x109f5c9,0x237c6cf,0x06b264a,0x3fc8f1a,
        0x0d4c539,0x2740f96,0x00dc2d4 },
      { 0x1d6f501,0x0adf4ea,0x14f7215,0x0930102,0x3f4c32e,0x24e2643,
        0x366596d,0x081ff18,0x38f94fb,0x2c21341,0x328594c,0x267c75c,
        0x196b3fd,0x29932cb,0x0036def } },
    /* 179 */
    { { 0x3ed7cbe,0x26de044,0x3d0e461,0x0565e12,0x295e500,0x31dc17f,
        0x32251c2,0x3420ca8,0x3995f0d,0x2e8ddab,0x0361a45,0x10971b0,
        0x11e7b55,0x33bc7ca,0x00812d2 },
      { 0x3d94972,0x1606817,0x0383ccf,0x0e795b7,0x026e20e,0x0f6fefc,
        0x13685d6,0x315d402,0x0cc36b8,0x1c7f059,0x390ef5e,0x316ae04,
        0x08c66b9,0x2fac9a4,0x0040086 } },
    /* 180 */
    { { 0x3e3c115,0x153de4d,0x1a8ae5e,0x2330511,0x169b8ee,0x1d965c2,
        0x2edff2b,0x3ef99e6,0x1631b46,0x1f8a238,0x118d7bb,0x12113c3,
        0x26424db,0x0f4122a,0x00e0ea2 },
      { 0x3d80a73,0x30393bc,0x0f98714,0x278ef59,0x087a0aa,0x3b18c20,
        0x04b8a82,0x2068e21,0x030255d,0x3382b27,0x055397f,0x05448dd,
        0x2015586,0x1190be0,0x000b979 } },
    /* 181 */
    { { 0x2e03080,0x2895692,0x09fb127,0x2d1602a,0x1232306,0x105bd4e,
        0x28cd6a6,0x0a83813,0x1ee13b0,0x2abadc3,0x0c09684,0x00e33e1,
        0x033eea3,0x30f0a39,0x00a710e },
      { 0x01b1f7d,0x1c959da,0x017077a,0x254bf0a,0x086fbce,0x15cd6b2,
        0x008683f,0x23a4f4d,0x22a6bd6,0x14e8c93,0x0027d15,0x31d0d4f,
        0x271777e,0x1533510,0x00ab603 } },
    /* 182 */
    { { 0x34c209d,0x14d0abb,0x270432a,0x1d02358,0x22ba752,0x209757f,
        0x34af6fc,0x1ffc52e,0x1ced28e,0x1870e46,0x1e0340f,0x3f0bf73,
        0x33ba91d,0x2ebca7c,0x00c6580 },
      { 0x1d442cb,0x0879d50,0x24e4ae1,0x3f4e91c,0x04c7727,0x093cd1d,
        0x16d6a45,0x10a8b95,0x0c77856,0x361f84f,0x217845f,0x0bbeec6,
        0x0485718,0x33c5385,0x00dcec0 } },
    /* 183 */
    { { 0x1539819,0x225507a,0x1bf11cb,0x13e7653,0x0c8cb3b,0x05f695e,
        0x353f634,0x2827874,0x3fb8053,0x22de9a5,0x035d8b7,0x2105cc7,
        0x2a7a98d,0x35bed95,0x0085748 },
      { 0x1859c5d,0x00e51f0,0x22a21fd,0x3054d74,0x06ce965,0x328eab7,
        0x26a13e0,0x13bfc65,0x01d4fb1,0x36600b9,0x36dd3fc,0x01232ed,
        0x15bbaa9,0x0ad7a51,0x0089b18 } },
    /* 184 */
    { { 0x3360710,0x1eb5a90,0x136bd77,0x3bd57a6,0x0841287,0x12886c9,
        0x35c6700,0x21bc6eb,0x25f35ad,0x3bcb01c,0x0707e72,0x23e9943,
        0x03e5233,0x34bb622,0x002bf8e },
      { 0x16e0d6a,0x04b3d2d,0x290cb02,0x049a10c,0x350537e,0x22cf71b,
        0x3184a19,0x2dc8b62,0x2350210,0x3b4afa6,0x159781e,0x1d01b6d,
        0x1853440,0x16442f0,0x005a78d } },
    /* 185 */
    { { 0x348b02c,0x1ea8ab5,0x3b954d5,0x14684ac,0x0be5b34,0x11c4496,
        0x0a7a456,0x14f6eb7,0x11a3221,0x2d65f82,0x32eb1ea,0x09c4018,
        0x3f301f3,0x32e8a1c,0x00bd9ad },
      { 0x0543f7f,0x31e744e,0x1fefd1d,0x24a486c,0x1000220,0x3977e3b,
        0x1b3ef51,0x2512a1b,0x2049e6b,0x122232b,0x391a32b,0x2f4a7b1,
        0x1c13e71,0x081a9b4,0x00d3516 } },
    /* 186 */
    { { 0x1924f43,0x1ae5495,0x28d52ef,0x2b93e77,0x2d2f401,0x371a010,
        0x33e8d7a,0x06ed3f1,0x30c0d9d,0x2589fa9,0x3bf3567,0x2ecf8fa,
        0x2dee4c3,0x152b620,0x007e8a2 },
      { 0x1924407,0x01bd42d,0x044a089,0x18686b5,0x2f14a0e,0x17cdce3,
        0x0efa216,0x3c586a8,0x1d6ae71,0x375831f,0x3175894,0x20e43eb,
        0x34c009e,0x3480527,0x00d115c } },
    /* 187 */
    { { 0x12abf77,0x38b0769,0x25682f2,0x295508c,0x0c2a0dc,0x1259b73,
        0x023ea25,0x340e7b5,0x3c7cd0d,0x1f92324,0x176405c,0x1528894,
        0x18f2e1e,0x2c59c35,0x001efb5 },
      { 0x0fb1471,0x07e7665,0x141da75,0x07d9f4a,0x0fdb31e,0x0dccda6,
        0x074eb25,0x3d92a9b,0x11189a0,0x1b4c557,0x24b8d2b,0x0533f92,
        0x0e9e344,0x2fa3dea,0x008d5a4 } },
    /* 188 */
    { { 0x2669e98,0x1ad3514,0x2a035c9,0x08a3f50,0x24547f9,0x0a145d3,
        0x1c1319d,0x3fe833d,0x1ae064b,0x1e01734,0x246d27e,0x3a2f13c,
        0x01e1150,0x263f55e,0x00f89ef },
      { 0x2e0b63f,0x3e57db7,0x23a4b4f,0x11c8899,0x0ad8500,0x348f3a7,
        0x2918604,0x27d6409,0x1ce5001,0x38f94c2,0x29a508a,0x39bdc89,
        0x3a52c27,0x194899e,0x00e9376 } },
    /* 189 */
    { { 0x0368708,0x34a2730,0x2e1da04,0x0bd78c1,0x2c45887,0x0c44bfa,
        0x3a23de3,0x390b9db,0x1746efd,0x05c638e,0x1d20609,0x3263370,
        0x31987f0,0x2988529,0x005fa3c },
      { 0x0aa9f2a,0x20622f7,0x060deee,0x0c9626a,0x3312cc7,0x18ebac7,
        0x008dd6c,0x0ad4fe6,0x3db4ea6,0x1dc3f50,0x090b6e9,0x0aff8d2,
        0x26aa62c,0x18f3e90,0x00105f8 } },
    /* 190 */
    { { 0x38059ad,0x25e576c,0x3ea00b2,0x1fa4191,0x25686b7,0x2d1ce8f,
        0x30470ed,0x3478bbf,0x340f9b6,0x1c9e348,0x3d594ec,0x2ffe56e,
        0x3f23deb,0x0cd34e9,0x00f4b72 },
      { 0x1a83f0b,0x2166029,0x28b32a2,0x06a5c5a,0x20786c4,0x0944604,
        0x0901bd2,0x379b84e,0x221e2fe,0x0346d54,0x1f4eb59,0x01b8993,
        0x2462e08,0x25f9d8b,0x006c4c8 } },
    /* 191 */
    { { 0x0b41d9d,0x2e417ed,0x265bd10,0x199148e,0x3826ca4,0x1a67e8d,
        0x1bbd13b,0x23e414d,0x3d773bc,0x356e64c,0x0d2118a,0x0cb587f,
        0x25fd093,0x24fb529,0x00158c6 },
      { 0x2806e63,0x3ecaa39,0x251b4dd,0x3b2d779,0x2e31ed3,0x066f1a6,
        0x060e518,0x2c7e3e5,0x0d62c76,0x0d88a70,0x101970a,0x1e3c8c6,
        0x272b8bb,0x083e73b,0x0031f38 } },
    /* 192 */
    { { 0x09e1c72,0x072bcb0,0x0cf4e93,0x2604a64,0x00715f2,0x10c98b6,
        0x2ad81d9,0x234fcce,0x37a7304,0x1974a4a,0x1c7415f,0x14aaa93,
        0x19587b1,0x3f643f4,0x00c3d10 },
      { 0x1ddadd0,0x2cd715d,0x294cf76,0x14479ed,0x19f5f4a,0x0198c09,
        0x1ab7ebc,0x182c0bc,0x0879202,0x1807273,0x05d39da,0x2c7d868,
        0x29c4ec4,0x1b13ad2,0x006dcd7 } },
    /* 193 */
    { { 0x1c83f01,0x0245bff,0x24f90ba,0x112554f,0x2354c8b,0x3f17988,
        0x0c511af,0x39e1e9b,0x26ae95b,0x0ae551c,0x35b41a6,0x0120455,
        0x1e989cb,0x1b37aff,0x00fa2ae },
      { 0x324659a,0x1aef1c3,0x1c43637,0x3f530a2,0x313a999,0x326af62,
        0x134184e,0x2ac131c,0x3f6a789,0x30a300a,0x13e526e,0x2107af3,
        0x093a8ff,0x2479902,0x00442b1 } },
    /* 194 */
    { { 0x22b6e20,0x31b18be,0x18614ca,0x26fdb5a,0x197f29e,0x325b44b,
        0x0ab1dbb,0x042348a,0x3275e8e,0x15bae44,0x0077124,0x2cf5345,
        0x2803ad4,0x188f2a2,0x0061b20 },
      { 0x2a560b1,0x3ced069,0x3cf42c2,0x100e167,0x3879e1d,0x0936ff0,
        0x1b51450,0x14c55f3,0x3153bfa,0x2957423,0x2a93823,0x15f5dce,
        0x2c9a22f,0x16731a8,0x00a97f2 } },
    /* 195 */
    { { 0x18edbbb,0x18c5ef9,0x1f13c30,0x071e77f,0x225ade5,0x1b60f75,
        0x1beaf11,0x3e495ad,0x2441dd8,0x2fa00e2,0x32a87b6,0x00050f2,
        0x038de7f,0x0037d6d,0x00a885d },
      { 0x39e48bd,0x1d9e433,0x2768e9f,0x3c29458,0x3f0bdf9,0x35ed5f2,
        0x36709fa,0x176dc10,0x012f7c1,0x2df8547,0x1d90ee3,0x053c089,
        0x21a8d35,0x200cb0d,0x002e84e } },
    /* 196 */
    { { 0x23ec8d8,0x1d81f55,0x0cb7227,0x07f8e4d,0x2a66181,0x163f577,
        0x272e7af,0x131a8f2,0x2046229,0x25e6276,0x36bbefe,0x2cdc22f,
        0x17c8288,0x33dd4fb,0x000d524 },
      { 0x330c073,0x1a6728b,0x1cf369f,0x12e7707,0x2f0fa26,0x17c2abd,
        0x0a45680,0x26ebd13,0x3c7d19b,0x1c3d6c8,0x2abd110,0x064fd07,
        0x09b8339,0x02b4a9f,0x009e3e1 } },
    /* 197 */
    { { 0x0ae972f,0x2093c35,0x06e7a90,0x0af1ba1,0x243eef0,0x2748582,
        0x0606122,0x13a45f9,0x0acfe60,0x08a685e,0x0eb184b,0x015bc11,
        0x0cdf423,0x157fad5,0x004fcad },
      { 0x2728d15,0x3e5bceb,0x0331a0f,0x31b1a80,0x28a2680,0x3b94955,
        0x04cae07,0x176b57e,0x03ac5a6,0x3d7918b,0x22d23f4,0x0ae077f,
        0x1eb075d,0x006f16c,0x006e473 } },
    /* 198 */
    { { 0x38219b9,0x0475a2b,0x107a774,0x39946c6,0x1cb883c,0x004e0ed,
        0x087e571,0x25c3497,0x059982f,0x0a71f66,0x118305d,0x1aaf294,
        0x3a5dbaa,0x34be404,0x00725fe },
      { 0x3abd109,0x336ebea,0x2528487,0x15a1d61,0x0c0f8cf,0x2b56095,
        0x2591e68,0x3549a80,0x1d1debb,0x0701c6c,0x161e7e3,0x1f7fa2e,
        0x3dfe192,0x17e6498,0x0055f89 } },
    /* 199 */
    { { 0x175645b,0x26c036c,0x0b92f89,0x09ed96d,0x351f3a6,0x19ce67b,
        0x33ac8db,0x2f0828b,0x27fe400,0x0b9c5e1,0x1967b95,0x3324080,
        0x11de142,0x1d44fb3,0x003d596 },
      { 0x3979775,0x3af37b6,0x3e88d41,0x2f1a8b9,0x299ba61,0x085413c,
        0x1149a53,0x0beb40e,0x31427ba,0x239f708,0x357d836,0x1558c22,
        0x280a79f,0x1b255f6,0x002b6d1 } },
    /* 200 */
    { { 0x39ad982,0x3d79d89,0x01a684a,0x0b6722e,0x39bb4c9,0x39a6399,
        0x1ad44e0,0x3059f5e,0x048265f,0x33a2fa4,0x0c3a4cc,0x0d7df98,
        0x23a33f1,0x34e2e21,0x00a0a10 },
      { 0x386efd9,0x1c91f34,0x06c2e19,0x3e6d48d,0x00eefd3,0x2181ef2,
        0x2415f97,0x1d33b08,0x0625086,0x1e8aa3e,0x08c9d60,0x0ab427b,
        0x2764fa7,0x3b7943e,0x00cd9f0 } },
    /* 201 */
    { { 0x1a46d4d,0x0e471f4,0x1693063,0x0467ac0,0x22df51c,0x127a0f7,
        0x0498008,0x20e0b16,0x1aa8ad0,0x1923f42,0x2a74273,0x01761ce,
        0x1600ca4,0x187b87e,0x00ee49e },
      { 0x0c76f73,0x19daf92,0x0b2ad76,0x3d8049d,0x1d9c100,0x0fe1c63,
        0x0bb67c8,0x035cc44,0x02002fc,0x37b2169,0x344656a,0x1127879,
        0x1939bc0,0x0dd8df6,0x0028ce7 } },
    /* 202 */
    { { 0x0544ac7,0x26bdc91,0x042697e,0x356e804,0x1f2c658,0x2ceb7ef,
        0x2dec39f,0x02c1dcc,0x391a2df,0x2344beb,0x2171e20,0x3099c94,
        0x0fa548a,0x37216c9,0x00f820c },
      { 0x0f4cf77,0x29bbaa5,0x33c6307,0x34a5128,0x118c783,0x2dd06b1,
        0x139d4c0,0x2db912e,0x1153ffb,0x1075eb3,0x3a255e4,0x2892161,
        0x36d5006,0x125338c,0x0014fbc } },
    /* 203 */
    { { 0x1584e3c,0x0830314,0x00279b9,0x167df95,0x2c7733c,0x2108aef,
        0x0ce1398,0x35aaf89,0x012523b,0x3c46b6a,0x388e6de,0x01a2002,
        0x0582dde,0x19c7fa3,0x007b872 },
      { 0x1e53510,0x11bca1f,0x19684e7,0x267de5c,0x2492f8b,0x364a2b0,
        0x080bc77,0x2c6d47b,0x248432e,0x3ace44f,0x32028f6,0x0212198,
        0x2f38bad,0x20d63f0,0x00122bb } },
    /* 204 */
    { { 0x30b29c3,0x3cec78e,0x01510a9,0x0c93e91,0x3837b64,0x1eca3a9,
        0x105c921,0x05d42e6,0x1379845,0x07ce6f2,0x0e8b6da,0x0e0f093,
        0x220b2cd,0x1f6c041,0x00299f5 },
      { 0x0afdce3,0x2b0e596,0x2f477b6,0x2ccf417,0x3a15206,0x26ec0bf,
        0x2e37e2b,0x2593282,0x0ab9db3,0x2841dd8,0x27954be,0x277a681,
        0x03f82e2,0x2b610c7,0x00446a1 } },
    /* 205 */
    { { 0x06b8195,0x3b3a817,0x31b9c6f,0x317d279,0x3d744a7,0x1de9eb9,
        0x296acc1,0x1ce9ea3,0x06c3587,0x246815d,0x3756736,0x0588518,
        0x1c971a4,0x1fde1f4,0x00aa021 },
      { 0x3fd3226,0x274561d,0x00be61e,0x01393d8,0x30f6f23,0x29b7fc1,
        0x04cebc7,0x0a892a7,0x20109f1,0x27456be,0x0c863ee,0x2eb6c8a,
        0x38c782b,0x039397a,0x00a2829 } },
    /* 206 */
    { { 0x29de330,0x21fe80f,0x145b55b,0x1986570,0x012b260,0x2482fbc,
        0x0536e0a,0x16b7382,0x32c4d19,0x1deffdb,0x145f418,0x0c67a76,
        0x2ce477f,0x218fe24,0x00f9848 },
      { 0x3e37657,0x3f074d3,0x245ad0e,0x20973c3,0x23c58de,0x2c332ef,
        0x2ad21a8,0x0bf1589,0x208af95,0x1f4a8c4,0x2b43735,0x1e46657,
        0x15d4f81,0x0c3e63a,0x005f19d } },
    /* 207 */
    { { 0x26865bb,0x20f6683,0x16a672e,0x0efd8d1,0x222f5af,0x18f2367,
        0x1e9c734,0x25c3902,0x178dfe6,0x2903a79,0x311b91c,0x1adbbe9,
        0x225a387,0x0b3e509,0x0089551 },
      { 0x34e462b,0x23b6a32,0x27c884c,0x129104b,0x384c015,0x3adedc7,
        0x325db1c,0x021dc10,0x1e366f7,0x3054df7,0x1992b9a,0x2824e64,
        0x0ae77f3,0x181b526,0x00a7316 } },
    /* 208 */
    { { 0x2d260f5,0x2434bf2,0x28c0139,0x0a7bb03,0x176c3be,0x3def5f5,
        0x05bee00,0x3692df7,0x3d2efeb,0x3a6f859,0x1122b87,0x38f779a,
        0x1415ccc,0x2c260ad,0x0075a28 },
      { 0x04607a6,0x042f37a,0x3f0df68,0x0a1bd36,0x3c6d581,0x2d36bfa,
        0x2d577d1,0x0a3affa,0x0b2066b,0x2e6f110,0x0b17e84,0x3c76a5e,
        0x1a57553,0x012f36a,0x0004595 } },
    /* 209 */
    { { 0x29e5836,0x0e6808c,0x269d13e,0x147dc5c,0x32c9e7d,0x09b258e,
        0x2c58d6f,0x1efd716,0x0437996,0x34ec31b,0x15908d9,0x2efa8fd,
        0x09ad160,0x079fc1f,0x00d8481 },
      { 0x3d20e4a,0x18269d6,0x3aa8fe7,0x34829c2,0x2e4325d,0x0d800e1,
        0x11f370b,0x10c08dc,0x22fd092,0x1a5fe55,0x0acc443,0x037030d,
        0x1cdd404,0x097379e,0x00fd6d7 } },
    /* 210 */
    { { 0x313eafb,0x3f438f3,0x2e5fb3e,0x2ed6a82,0x121009c,0x240889e,
        0x00c5537,0x269b792,0x334b2fc,0x1dd573c,0x07096ae,0x19296fc,
        0x3813985,0x2742f48,0x00ddd64 },
      { 0x2045041,0x3842c62,0x1572d0d,0x04f255f,0x06e05b4,0x383ec97,
        0x1ff8064,0x18bed71,0x39b6411,0x2764cc5,0x257439f,0x3521217,
        0x172aa42,0x342a2a3,0x0070c5b } },
    /* 211 */
    { { 0x3bdf646,0x1c5ce25,0x1f7ca76,0x2d2acca,0x3aa1485,0x23c97f7,
        0x3e11d6f,0x0609338,0x07ec622,0x01da8ff,0x3392474,0x17ca07f,
        0x13a9a04,0x353a5b4,0x0024557 },
      { 0x14c27cd,0x32012f7,0x3fea875,0x3d03d71,0x211c5f0,0x3157fdf,
        0x0c880bd,0x3c406b2,0x2c51103,0x24ab377,0x399faa8,0x0d06887,
        0x16b5738,0x28b33a7,0x00c7b67 } },
    /* 212 */
    { { 0x2357586,0x35c93e3,0x0da09a0,0x3d77d92,0x11d7f4f,0x37b98a9,
        0x3e6c9bf,0x2cdca70,0x2f00389,0x2412673,0x18eab87,0x0101436,
        0x11617e9,0x06d9b01,0x00e8eef },
      { 0x37e3ca9,0x16ffaf0,0x391debf,0x1b69382,0x07c5e94,0x312fa8a,
        0x0973142,0x2cadde4,0x109ee67,0x3a07db0,0x1afc5ed,0x08df66f,
        0x304c7af,0x0804aae,0x00d2e60 } },
    /* 213 */
    { { 0x24f57bf,0x1818322,0x182a615,0x25bfc44,0x0f97586,0x0a5bbc0,
        0x36773c6,0x1a2660c,0x3ceff66,0x3270152,0x319cd11,0x2845845,
        0x1acfad6,0x19076f8,0x009824a },
      { 0x289fd01,0x2de97ee,0x39d80b7,0x026227d,0x0f8d3b8,0x15e0a17,
        0x21ea08f,0x20a2317,0x136ae6d,0x3deb1d1,0x3521ef5,0x0de8801,
        0x0a25d5d,0x0612c98,0x005ecc4 } },
    /* 214 */
    { { 0x308c8d3,0x3aec669,0x01ecddc,0x13f18fe,0x1e63ed0,0x061cfe5,
        0x05f5a01,0x1db5741,0x14479f2,0x0ced6b5,0x025ae5b,0x09ca8f5,
        0x2160581,0x1404433,0x008bfeb },
      { 0x08228bf,0x0e02722,0x37df423,0x33ecabf,0x34bd82a,0x32f529f,
        0x28f1800,0x0c8f671,0x1246b44,0x1ff35dc,0x091db95,0x303f3da,
        0x28f7f60,0x3624136,0x00cfbb4 } },
    /* 215 */
    { { 0x326139a,0x2977e4e,0x3eb89a6,0x20ecb31,0x13e076a,0x2a592f3,
        0x28e82d5,0x235ad1e,0x239b927,0x262938a,0x2444354,0x141b263,
        0x0d56693,0x2a3fc78,0x0006497 },
      { 0x31efa05,0x3a3664a,0x3e333de,0x2a114e4,0x12da63c,0x3c15e6b,
        0x2f7277c,0x363aa92,0x2393236,0x16bd2d1,0x32b617f,0x32b656c,
        0x3b1246c,0x22e2e22,0x00ce76d } },
    /* 216 */
    { { 0x03843dc,0x094de82,0x13b463d,0x0507905,0x089eb35,0x2a6bf25,
        0x35ebc4e,0x2bb5d45,0x1808ed1,0x1de9949,0x185e829,0x0a55847,
        0x0b73d67,0x1a2ed61,0x008dd2d },
      { 0x133c3a4,0x04e7980,0x38ea237,0x2ad2f49,0x19de838,0x018bf36,
        0x29b072c,0x21c1ba0,0x14f63ba,0x31c1cc3,0x13cd05e,0x20120ff,
        0x1f84d60,0x16e0321,0x00872ab } },
    /* 217 */
    { { 0x19d4d49,0x1ddb4e6,0x05e7fc0,0x37bb0fd,0x1a3eb59,0x36b87f0,
        0x190e440,0x1c7fef2,0x31ea153,0x14cd65a,0x1bc7ab2,0x11f72ca,
        0x39582d4,0x0fa4d65,0x00cd5b6 },
      { 0x3d1ff11,0x0d9be9d,0x2903ae3,0x017b7b9,0x259f28f,0x110cefc,
        0x03fed1a,0x38039bd,0x09bdf9c,0x3055027,0x2ca9c5d,0x2d737b6,
        0x3bdb421,0x16560b5,0x00f9f33 } },
    /* 218 */
    { { 0x022c792,0x110de25,0x38bf959,0x08f2562,0x1239ea9,0x3c1d950,
        0x21a247d,0x315112d,0x285bb9f,0x2534a73,0x0b42455,0x1a4a99c,
        0x069009a,0x1680392,0x006e0ca },
      { 0x1b3bece,0x269e0a1,0x18926b7,0x0e7187e,0x241f35e,0x39d1fe0,
        0x02099aa,0x1675bfe,0x23fd0ca,0x3d6322b,0x19406b5,0x324c38a,
        0x242434a,0x3ae677c,0x002ce04 } },
    /* 219 */
    { { 0x2c37b82,0x1ae6506,0x0d83436,0x23496c1,0x0ff0c72,0x2711edf,
        0x1513611,0x04f9c7d,0x1edbeff,0x376fcb5,0x212a683,0x23bf547,
        0x0f9c4f7,0x16e6627,0x0082cd8 },
      { 0x0cb5d37,0x31b6db8,0x1a15e23,0x2f5cbb8,0x0818aee,0x21dc6c5,
        0x12aafd2,0x205f608,0x1d91def,0x3def088,0x1445c51,0x3100e8a,
        0x3746bda,0x145c4b0,0x00711b0 } },
    /* 220 */
    { { 0x2a99ecc,0x27b5217,0x35e10ed,0x036e32a,0x0f79950,0x15c32f7,
        0x2c87dcb,0x3ebb2a3,0x2c2d35d,0x114b3ec,0x2e4d80a,0x0c7eb89,
        0x2abe58d,0x3727737,0x00e6a37 },
      { 0x1eca452,0x1968d07,0x344e5d3,0x29435a2,0x109a5f8,0x181d12c,
        0x238ea5a,0x127a564,0x00dbb42,0x0fcbfb7,0x2909b2e,0x2571d3a,
        0x08250e3,0x0694e4e,0x00e156d } },
    /* 221 */
    { { 0x3181ae9,0x1acf411,0x3808d79,0x2a11065,0x0baf44b,0x133cfeb,
        0x1330943,0x1711b9a,0x2dec3bd,0x1906a9a,0x2ed947c,0x369d763,
        0x1a5254f,0x104a7a9,0x00acd9d },
      { 0x030301b,0x31568f5,0x2a4965c,0x33ded4b,0x03c9a5b,0x16541fc,
        0x1319cf1,0x2a3748b,0x1b5de74,0x18bb82e,0x077ac2b,0x309a87a,
        0x3c31420,0x0f6a4b9,0x00387d7 } },
    /* 222 */
    { { 0x0d3fdac,0x120cfa3,0x1b8e13c,0x1ccccb9,0x376fcd4,0x0bf87f4,
        0x271b4be,0x363b3fd,0x28b5d98,0x0535cd3,0x114bbc1,0x3ab4f19,
        0x10494b1,0x2161ece,0x00d14ca },
      { 0x12d37e9,0x110ebd7,0x062295a,0x1cc0119,0x073c6ea,0x15d5411,
        0x0aeb4b1,0x23fba91,0x175fab5,0x3ee8fe1,0x1c680a6,0x1e76f27,
        0x3ddfc97,0x3d69ecd,0x00e1ee5 } },
    /* 223 */
    { { 0x2d29f46,0x2d19204,0x3137cd0,0x02c3b54,0x193295b,0x02fbdb2,
        0x2260948,0x22c02ff,0x3885424,0x1299595,0x00e7f9c,0x310ff2a,
        0x01ea169,0x0deef85,0x0021908 },
      { 0x1b26cfb,0x38566a8,0x2852875,0x21debff,0x290ca9f,0x0b29663,
        0x26550d9,0x2b44457,0x05d1938,0x1f8f825,0x366ef93,0x1d8daec,
        0x069e5ef,0x342ece6,0x00b6034 } },
    /* 224 */
    { { 0x2d8356e,0x1578c09,0x226f4d2,0x3b74c51,0x0f83666,0x0323b59,
        0x1ddf61d,0x1ed8508,0x3c52667,0x0e5b91c,0x1e9b18b,0x352bdfa,
        0x13f75da,0x352aa4e,0x00fceff },
      { 0x1c731d5,0x04e2844,0x01d9843,0x286cbc5,0x105bcb3,0x05edd9c,
        0x21fa956,0x3b1ec83,0x01288cc,0x22fbf3a,0x10f1b56,0x081cf72,
        0x15cb758,0x18687c1,0x00f5722 } },
    /* 225 */
    { { 0x2973088,0x1209dcd,0x3980f31,0x0221aa7,0x1c008e7,0x011b098,
        0x395947e,0x2f2806d,0x27dca76,0x037c79a,0x31acddf,0x2bf6219,
        0x0d8f4ab,0x13644d9,0x00ff705 },
      { 0x2260594,0x18d51f8,0x277e2cf,0x1cb5cec,0x2468a53,0x3e6f4d7,
        0x019e24e,0x0f30f1d,0x0202404,0x34ad287,0x090b39c,0x23c11ea,
        0x1a2e3a2,0x3a851be,0x00dca2c } },
    /* 226 */
    { { 0x3277538,0x221cd94,0x3738ab7,0x0973da5,0x1a734e2,0x2c8b8b0,
        0x2e1d1e6,0x348499b,0x389ebe1,0x18b1854,0x02bb076,0x1b2b500,
        0x0f207f3,0x170cf99,0x0012088 },
      { 0x0fbfec2,0x1df55a4,0x34ae59e,0x2ab5e95,0x3f9e781,0x3411794,
        0x1410b05,0x17c3a00,0x0aaa91b,0x074ed7c,0x3fbb352,0x3477c01,
        0x3ee9ab3,0x0cfb1ca,0x0011c4b } },
    /* 227 */
    { { 0x3c3a7f3,0x2e60ca0,0x2354d32,0x33e2362,0x28083ab,0x03d3b16,
        0x3164045,0x0a41f7a,0x3f0641e,0x38635d1,0x31bbf03,0x225e2bb,
        0x0cd894e,0x1f72228,0x0093244 },
      { 0x33d5897,0x383faf3,0x0e6d561,0x0bc4d80,0x3fc3a68,0x05a9adc,
        0x0b9d73d,0x3d6031e,0x2ded29b,0x339c4ff,0x08d69e5,0x089488c,
        0x3fda40a,0x295c7fd,0x003a924 } },
    /* 228 */
    { { 0x0093bee,0x115532d,0x2ec0fb6,0x0969631,0x3a6d65a,0x0f43b4d,
        0x26994d4,0x0b51104,0x2515515,0x3695a26,0x284caa8,0x397aa30,
        0x25538b8,0x353f47c,0x0033f05 },
      { 0x3615d6e,0x37f8246,0x07dae0f,0x23dc154,0x02ded7e,0x1eef320,
        0x1631e51,0x3447f75,0x13e267f,0x353e1d1,0x3f89d62,0x369c8ff,
        0x1a21dc6,0x2b8b8f3,0x0055cbc } },
    /* 229 */
    { { 0x34e84f3,0x2f2539a,0x2c35336,0x0c53bdc,0x1728630,0x3ad5fe6,
        0x05fdeee,0x3386db6,0x272a42e,0x29fd38c,0x36f0320,0x21b2ed4,
        0x331e67f,0x28ae48c,0x00f09b6 },
      { 0x2778435,0x0fb3c55,0x32d221d,0x2660c8e,0x32977ba,0x1c12f03,
        0x1b57fb1,0x01229a8,0x38b389f,0x375ddf3,0x2c6b42c,0x3885d3e,
        0x2c55a9c,0x2ffc279,0x00404e2 } },
    /* 230 */
    { { 0x04c5ddb,0x2c4d788,0x150e9b9,0x110fbfd,0x29dbfe0,0x30ef83d,
        0x2ab4bfe,0x395bcd7,0x30d0a43,0x0e2d30f,0x0e73f9b,0x07199cc,
        0x0c9054c,0x22f4b1e,0x0092ed3 },
      { 0x386e27c,0x00fdaa8,0x0507c70,0x1beb3b6,0x0b9c4f4,0x277d519,
        0x024ec85,0x1cbaba8,0x1524295,0x112be58,0x21fc119,0x273578b,
        0x2358c27,0x280ca07,0x00aa376 } },
    /* 231 */
    { { 0x0dbc95c,0x16488cf,0x337a078,0x1abbcb8,0x0aae1aa,0x1caa151,
        0x00108d4,0x1edf701,0x3e68d03,0x1203214,0x0c7eee2,0x084c572,
        0x07752d2,0x215a3b9,0x00195d3 },
      { 0x2cd7fbe,0x06e80f6,0x052bd4b,0x07b4f83,0x24b5ac6,0x2aaded4,
        0x13c0526,0x0ffa9a3,0x08c660e,0x13c35c9,0x3145efb,0x36cfe24,
        0x0936daf,0x268e3d0,0x00a73fd } },
    /* 232 */
    { { 0x31b17ce,0x2e7bcee,0x3f31891,0x19f1849,0x1140236,0x015487f,
        0x32e58d3,0x202204a,0x049e350,0x1ce91f9,0x3f75150,0x27f212f,
        0x0d16ee4,0x1c894c4,0x004023f },
      { 0x33399fa,0x2397b6d,0x2a3ea60,0x36354ca,0x1f12632,0x117a105,
        0x22758e8,0x361844e,0x3851fc2,0x0ab92db,0x339d02f,0x1e7d6c4,
        0x19ebd38,0x0a9a036,0x00446d2 } },
    /* 233 */
    { { 0x3e164f1,0x008c092,0x19200f5,0x35a22e0,0x38d09d2,0x212b3bf,
        0x0056f19,0x3a03545,0x1f075e9,0x0e97137,0x1f496a9,0x32d1f9b,
        0x36bf738,0x35ace37,0x00899e1 },
      { 0x19eb2a6,0x21fa22d,0x338b69e,0x18e6d1f,0x1280d9d,0x1953a55,
        0x1411ea3,0x2960566,0x0fd969a,0x1f3e375,0x130742a,0x170aebd,
        0x33085ff,0x14d868d,0x00a4391 } },
    /* 234 */
    { { 0x0a4bdd2,0x39ca8ea,0x37026ac,0x346da3b,0x0c656cd,0x03136b6,
        0x233e7e9,0x0714352,0x08a9d95,0x192bb38,0x085d68e,0x20016b8,
        0x102b8ea,0x1f5dbdd,0x00fdd7a },
      { 0x0d6fa45,0x3ec29a6,0x2b8cce6,0x1c84413,0x0228f86,0x28275f7,
        0x3d8787d,0x0c19748,0x28b2ae9,0x1954850,0x2a56c36,0x3eae8f7,
        0x0aca595,0x00e42a2,0x00edbe5 } },
    /* 235 */
    { { 0x3b26c82,0x3682b6f,0x2f9cd64,0x0f254b0,0x0e5d70b,0x1f9dfda,
        0x28f365f,0x35a57d7,0x00208f2,0x19c8d38,0x112e7be,0x3e403bb,
        0x3734efa,0x24d12b3,0x0027dc6 },
      { 0x260a46a,0x13fd7b0,0x1c2880e,0x338b70c,0x27da5eb,0x29a7d54,
        0x1c5d73c,0x2130921,0x32969cc,0x2b37eda,0x2d6d4ec,0x0716bfb,
        0x0763703,0x1320889,0x00c7bbf } },
    /* 236 */
    { { 0x1fe01b2,0x2dcb1d2,0x11b89d5,0x219e4ea,0x0347851,0x3d1810e,
        0x3a3c54c,0x06dbe8e,0x03d3ab2,0x2dcfa39,0x3e57b8a,0x337a382,
        0x0426450,0x0e9f748,0x006488b },
      { 0x1dc4582,0x0e62cf7,0x06fea9e,0x2a56fb1,0x31698c1,0x15b4e10,
        0x1446ef1,0x0a689fc,0x1d87703,0x20ff497,0x2c71066,0x2c48868,
        0x2e6cf05,0x30aa9cb,0x0065b2d } },
    /* 237 */
    { { 0x1021d63,0x2217df3,0x1f0821a,0x057fa98,0x23f344b,0x173dcf9,
        0x1ba6ddc,0x22c8eb5,0x18f227a,0x0455343,0x1c55931,0x1d0dcf3,
        0x20fa19b,0x1c56618,0x004feab },
      { 0x19ec924,0x224e39f,0x2550509,0x179b51f,0x284d54a,0x2d85d41,
        0x2d1bdc1,0x1a29068,0x3826158,0x1267f85,0x3005a92,0x0769e00,
        0x379b617,0x17b5f63,0x00a70bf } },
    /* 238 */
    { { 0x22216c5,0x049437f,0x33510bc,0x141d806,0x22c37e2,0x1bc1adf,
        0x300175d,0x2e6ded8,0x0a18bfe,0x35377a3,0x382f843,0x08410ca,
        0x00afd4f,0x0be6c6b,0x008d70e },
      { 0x2e91abb,0x1cede2a,0x28f225c,0x28e18c0,0x30230dc,0x173cc2d,
        0x123ecfe,0x3c9962e,0x2c25506,0x27b5d53,0x329a5e3,0x106e231,
        0x3889b8e,0x3b0aeaf,0x00ee67c } },
    /* 239 */
    { { 0x3e46c65,0x0eb3d46,0x1d7ae18,0x23f9d59,0x2978953,0x2589ed3,
        0x073391d,0x2461e1e,0x0c19f1d,0x22fd2b1,0x0691f5c,0x2e67d8d,
        0x1fb985d,0x200dd28,0x00a68df },
      { 0x392b5fa,0x123b46f,0x1c323c4,0x104f82f,0x0a098c8,0x26fc05b,
        0x34cd557,0x0913639,0x09c115e,0x3977c34,0x3410b66,0x062b404,
        0x0213094,0x132c5e8,0x008b612 } },
    /* 240 */
    { { 0x26e3392,0x3b0ebf0,0x2e00425,0x1c285c8,0x3c07f84,0x08d5ad0,
        0x028190e,0x1669b73,0x1ffb1ef,0x053b65f,0x063028c,0x0aceb47,
        0x18988c2,0x0f09a30,0x0007072 },
      { 0x0f49e7d,0x28c0bd3,0x252270d,0x24cfc4a,0x0c5e87c,0x2165052,
        0x2cdd1d1,0x04931d2,0x3abca74,0x22b57dc,0x169fd47,0x0b928fb,
        0x17cc3e7,0x21a1ec4,0x0061593 } },
    /* 241 */
    { { 0x1aa0486,0x2e55dea,0x15577b7,0x0d6818f,0x36e41fb,0x2a411f5,
        0x17d5c7d,0x1eea6c0,0x28068a8,0x0e31d20,0x1f08ad9,0x117e973,
        0x08a28ab,0x085d30a,0x00cd9fb },
      { 0x347843d,0x1119095,0x11e3595,0x1b29584,0x134d64c,0x2ff3a35,
        0x247ea14,0x099fc4b,0x2056169,0x145dd03,0x2ed03fb,0x1250e3b,
        0x3f5135c,0x2b753f0,0x009da30 } },
    /* 242 */
    { { 0x0fa5200,0x214a0b3,0x313dc4e,0x23da866,0x3270760,0x15c9b8b,
        0x39a53df,0x1f79772,0x3c9e942,0x2984901,0x154d582,0x1685f87,
        0x2e1183e,0x1f79956,0x00b9987 },
      { 0x15254de,0x3a5cac0,0x37c56f0,0x2c7c29b,0x292a56d,0x195be2c,
        0x17e4e1a,0x0660f4a,0x052ad98,0x1267f80,0x07cfed8,0x194b4bc,
        0x01738d3,0x14ba10f,0x00c7843 } },
    /* 243 */
    { { 0x29b2d8a,0x242bc1f,0x19646ee,0x0615f3c,0x0ac8d70,0x07ca3bf,
        0x2d90317,0x2c83bdb,0x1a96812,0x39fdc35,0x31c61ee,0x2d55fd3,
        0x2375827,0x355f189,0x00f1c9b },
      { 0x21a6194,0x1f4050a,0x2b845cf,0x02c6242,0x2dd614e,0x3a4f0a9,
        0x39de100,0x24714fb,0x175e0cd,0x0be633d,0x14befc3,0x13b0318,
        0x1d68c50,0x299989e,0x00d0513 } },
    /* 244 */
    { { 0x059fb6a,0x2b6eb6a,0x3666a8e,0x39f6ca0,0x1cf8346,0x388b8d5,
        0x35e61a3,0x271adec,0x22c9963,0x20a4fb3,0x16f241c,0x0058b89,
        0x21ddafa,0x1ee6fde,0x00d2e6c },
      { 0x0075e63,0x39894d0,0x0286d0d,0x187e7b2,0x02405aa,0x3f91525,
        0x37830a8,0x2723088,0x2c7364e,0x013f406,0x104ba75,0x270f486,
        0x3520b4d,0x3852bc6,0x00d589b } },
    /* 245 */
    { { 0x262e53b,0x1da93d1,0x3676135,0x147e41d,0x335ec2f,0x1f02be5,
        0x297d139,0x22d6198,0x1fe9e59,0x13b4c80,0x1e70f60,0x2f1d4a9,
        0x2d95149,0x14d6ec4,0x00b54af },
      { 0x12c1c76,0x2930ac8,0x0dfd36e,0x31fac94,0x218f5bb,0x2828691,
        0x1466cc9,0x3645e83,0x1a4dac2,0x1549593,0x0e95fab,0x19567d2,
        0x27a3320,0x0642729,0x007487c } },
    /* 246 */
    { { 0x1e98e9c,0x2ff8df7,0x119975a,0x098a904,0x099b90b,0x336c7df,
        0x010996d,0x159d46d,0x3118b3b,0x3aacd1b,0x31f8ae1,0x214864f,
        0x398c104,0x089dae2,0x001ec4d },
      { 0x1452baa,0x2f24991,0x2572ba3,0x162b312,0x2387d18,0x147c5c7,
        0x38eff6e,0x0700251,0x37d931e,0x23cd5c1,0x254c8ca,0x3b9df37,
        0x1c9a4ff,0x0bfd547,0x00fb489 } },
    /* 247 */
    { { 0x1b8dff8,0x2f6b40b,0x05a25b1,0x3f5688a,0x1d462f4,0x2802d18,
        0x2aad8ed,0x1b46c75,0x3cf4130,0x250fefb,0x2a13fe1,0x23a1bcd,
        0x0940442,0x04605fe,0x00c8b2f },
      { 0x0d51afb,0x14a2abc,0x1d06762,0x291526c,0x2a3e2fe,0x28f77d9,
        0x3ad8f2e,0x3481a1b,0x04b4fbd,0x2836733,0x0189ff5,0x3a5f533,
        0x319a6cd,0x0f58667,0x00c3679 } },
    /* 248 */
    { { 0x1b85197,0x22426d4,0x2895ea3,0x342d324,0x3ffb17d,0x376cfcf,
        0x30878b1,0x3c3c83a,0x0ffc57c,0x0ac174a,0x1abd57e,0x2f78b9c,
        0x01b20d8,0x0a37103,0x007f2be },
      { 0x19a2d48,0x137288a,0x182d655,0x0ba0dde,0x25130ba,0x01c65c6,
        0x23205f1,0x2097621,0x2827cf2,0x2c57b98,0x03748f2,0x2db15fc,
        0x385a0d4,0x13690c0,0x00a9e3f } },
    /* 249 */
    { { 0x3fbc9c6,0x2df3b20,0x377e33e,0x31d1505,0x024a311,0x3c1d9ff,
        0x1377f74,0x00b6b20,0x2364ab7,0x184ab6b,0x2a77969,0x3f2db6c,
        0x2a6adb7,0x0a10073,0x004a6fb },
      { 0x1fc73de,0x2c74ab3,0x3d325e8,0x2346c0b,0x1d0efae,0x2076146,
        0x19c190d,0x225c4fe,0x3fafc80,0x2cf063d,0x11b7ae7,0x3dc4f9d,
        0x3c3f841,0x10d7c1f,0x000a4b3 } },
    /* 250 */
    { { 0x19b7d2e,0x28f1300,0x0b897dd,0x06b5371,0x0631c8d,0x336cc4f,
        0x09cd6e1,0x2ec1952,0x1104c07,0x07512bb,0x35f000d,0x25f84e9,
        0x1df4d8f,0x193f769,0x000e9ee },
      { 0x2346910,0x267cecf,0x0ad7eaa,0x087e8a5,0x1622f69,0x342cbfa,
        0x2aa20d0,0x206e88a,0x3991e58,0x093fb4b,0x0157180,0x3cecb5b,
        0x2e17c9a,0x1ea371f,0x00919e6 } },
    /* 251 */
    { { 0x2250533,0x13f931d,0x3ef8c72,0x395f605,0x18a2080,0x1cb25d4,
        0x2fb0f41,0x1c0ba8a,0x1eb17c0,0x266c433,0x09b7e3e,0x0e5d78f,
        0x0cdc5bf,0x1f7c734,0x0020611 },
      { 0x205ebd5,0x127986f,0x02c0fb0,0x1705b1e,0x1eb0bb5,0x2dffb42,
        0x2331b8a,0x18fc04e,0x31d6328,0x17db162,0x0d3b619,0x193bdb9,
        0x3f11662,0x2d8e694,0x0092c51 } },
    /* 252 */
    { { 0x08b364d,0x31ef20a,0x25c4a57,0x021ed07,0x14a562e,0x262a684,
        0x1d21c66,0x126e5a6,0x181f3f8,0x2a93b65,0x1eb726b,0x08fbbce,
        0x084f9a2,0x308f30a,0x0013159 },
      { 0x23f4963,0x0c7960e,0x2a81739,0x2242b69,0x3965003,0x2aca542,
        0x28a1c65,0x2ad48fb,0x149775f,0x1bbb7d2,0x0f2671b,0x3594b85,
        0x22f5563,0x2470f13,0x00fed44 } },
    /* 253 */
    { { 0x0eb453e,0x3ab70fd,0x1a5b335,0x18f2b74,0x25ff74b,0x3612a46,
        0x33d0d75,0x28cdda4,0x2b9b49b,0x22728fb,0x004c15b,0x1beb33b,
        0x1a7e41f,0x0c9b702,0x004ef19 },
      { 0x1ca3233,0x0b4c90f,0x1d4b53d,0x2428896,0x20ee405,0x151bc00,
        0x022edb5,0x1adc463,0x00109ea,0x06490a6,0x30e91e6,0x3682b76,
        0x23c50aa,0x3bd2665,0x005fe53 } },
    /* 254 */
    { { 0x0c28c65,0x3741ae4,0x247d372,0x0b04673,0x2176524,0x2c8bf20,
        0x01fb806,0x3330701,0x307b0a7,0x3999fb7,0x1261bec,0x256679c,
        0x3f22ac7,0x26e8673,0x00bc69d },
      { 0x3c06819,0x35df344,0x379d009,0x2bb8a0a,0x0635a66,0x096c6fa,
        0x1ac4a62,0x023e53b,0x0e45240,0x115f53d,0x3056af8,0x0a66b16,
        0x3c386ee,0x1130e82,0x00cc384 } },
    /* 255 */
    { { 0x14c2356,0x190ec73,0x07be490,0x145d415,0x0740a48,0x1251301,
        0x3eaf29d,0x2628190,0x079299a,0x26e95c9,0x2e05fdf,0x2ca7c5b,
        0x32d7b48,0x3d84226,0x0033fb4 },
      { 0x150f955,0x01240aa,0x3ddf867,0x137fb70,0x297e103,0x17eeda8,
        0x1320b60,0x266ec84,0x13f4322,0x0c8f5ee,0x0590e4a,0x386815e,
        0x00ce61f,0x161bd63,0x008e1d0 } },
};

/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Stripe implementation.
 * Pre-generated: 2^0, 2^48, ...
 * Pre-generated: products of all combinations of above.
 * 8 doubles and adds (with qz=1)
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_base_15(sp_point_384* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_384_ecc_mulmod_stripe_15(r, &p384_base, p384_table,
                                      k, map, ct, heap);
}

#endif

/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_base_384(const mp_int* km, ecc_point* r, int map, void* heap)
{
    SP_DECL_VAR(sp_point_384, point, 1);
    SP_DECL_VAR(sp_digit, k, 15);
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_point_384, point, 1, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_digit, k, 15, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        sp_384_from_mp(k, 15, km);

            err = sp_384_ecc_mulmod_base_15(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_15(point, r);
    }

    SP_FREE_VAR(k, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(point, heap, DYNAMIC_TYPE_ECC);

    return err;
}

/* Multiply the base point of P384 by the scalar, add point a and return
 * the result. If map is true then convert result to affine coordinates.
 *
 * km      Scalar to multiply by.
 * am      Point to add to scalar multiply result.
 * inMont  Point to add is in montgomery form.
 * r       Resulting point.
 * map     Indicates whether to convert result to affine.
 * heap    Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */

/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_384_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i;
    int j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 18U) {
            r[j] &= 0x3ffffff;
            s = 26U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * rng  Random number generator.
 * k    Scalar value.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
static int sp_384_ecc_gen_k_15(WC_RNG* rng, sp_digit* k)
{
    (void)rng;
    (void)k;
    return NOT_COMPILED_IN;
}

/* Makes a random EC key pair.
 *
 * rng   Random number generator.
 * priv  Generated private value.
 * pub   Generated public point.
 * heap  Heap to use for allocation.
 * returns ECC_INF_E when the point does not have the correct order, RNG
 * failures, MEMORY_E when memory allocation fails and MP_OKAY on success.
 */



SP_NOINLINE static void sp_384_rshift_15(sp_digit* r, const sp_digit* a,
        byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<14; i++) {
        r[i] = (sp_digit)(((a[i] >> n) | (a[i + 1] << (26 - n))) & 0x3ffffff);
    }
#else
    for (i=0; i<8; i += 8) {
        r[i+0] = (a[i+0] >> n) | (sp_digit)((a[i+1] << (26 - n)) & 0x3ffffff);
        r[i+1] = (a[i+1] >> n) | (sp_digit)((a[i+2] << (26 - n)) & 0x3ffffff);
        r[i+2] = (a[i+2] >> n) | (sp_digit)((a[i+3] << (26 - n)) & 0x3ffffff);
        r[i+3] = (a[i+3] >> n) | (sp_digit)((a[i+4] << (26 - n)) & 0x3ffffff);
        r[i+4] = (a[i+4] >> n) | (sp_digit)((a[i+5] << (26 - n)) & 0x3ffffff);
        r[i+5] = (a[i+5] >> n) | (sp_digit)((a[i+6] << (26 - n)) & 0x3ffffff);
        r[i+6] = (a[i+6] >> n) | (sp_digit)((a[i+7] << (26 - n)) & 0x3ffffff);
        r[i+7] = (a[i+7] >> n) | (sp_digit)((a[i+8] << (26 - n)) & 0x3ffffff);
    }
    r[8] = (a[8] >> n) | (sp_digit)((a[9] << (26 - n)) & 0x3ffffff);
    r[9] = (a[9] >> n) | (sp_digit)((a[10] << (26 - n)) & 0x3ffffff);
    r[10] = (a[10] >> n) | (sp_digit)((a[11] << (26 - n)) & 0x3ffffff);
    r[11] = (a[11] >> n) | (sp_digit)((a[12] << (26 - n)) & 0x3ffffff);
    r[12] = (a[12] >> n) | (sp_digit)((a[13] << (26 - n)) & 0x3ffffff);
    r[13] = (a[13] >> n) | (sp_digit)((a[14] << (26 - n)) & 0x3ffffff);
#endif /* WOLFSSL_SP_SMALL */
    r[14] = a[14] >> n;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_384_mul_d_15(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    sp_int64 tb = b;
    sp_int64 t = 0;
    int i;

    for (i = 0; i < 15; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x3ffffff);
        t >>= 26;
    }
    r[15] = (sp_digit)t;
#else
    sp_int64 tb = b;
    sp_int64 t[15];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    t[ 7] = tb * a[ 7];
    t[ 8] = tb * a[ 8];
    t[ 9] = tb * a[ 9];
    t[10] = tb * a[10];
    t[11] = tb * a[11];
    t[12] = tb * a[12];
    t[13] = tb * a[13];
    t[14] = tb * a[14];
    r[ 0] = (sp_digit)                 (t[ 0] & 0x3ffffff);
    r[ 1] = (sp_digit)((t[ 0] >> 26) + (t[ 1] & 0x3ffffff));
    r[ 2] = (sp_digit)((t[ 1] >> 26) + (t[ 2] & 0x3ffffff));
    r[ 3] = (sp_digit)((t[ 2] >> 26) + (t[ 3] & 0x3ffffff));
    r[ 4] = (sp_digit)((t[ 3] >> 26) + (t[ 4] & 0x3ffffff));
    r[ 5] = (sp_digit)((t[ 4] >> 26) + (t[ 5] & 0x3ffffff));
    r[ 6] = (sp_digit)((t[ 5] >> 26) + (t[ 6] & 0x3ffffff));
    r[ 7] = (sp_digit)((t[ 6] >> 26) + (t[ 7] & 0x3ffffff));
    r[ 8] = (sp_digit)((t[ 7] >> 26) + (t[ 8] & 0x3ffffff));
    r[ 9] = (sp_digit)((t[ 8] >> 26) + (t[ 9] & 0x3ffffff));
    r[10] = (sp_digit)((t[ 9] >> 26) + (t[10] & 0x3ffffff));
    r[11] = (sp_digit)((t[10] >> 26) + (t[11] & 0x3ffffff));
    r[12] = (sp_digit)((t[11] >> 26) + (t[12] & 0x3ffffff));
    r[13] = (sp_digit)((t[12] >> 26) + (t[13] & 0x3ffffff));
    r[14] = (sp_digit)((t[13] >> 26) + (t[14] & 0x3ffffff));
    r[15] = (sp_digit) (t[14] >> 26);
#endif /* WOLFSSL_SP_SMALL */
}

SP_NOINLINE static void sp_384_lshift_30(sp_digit* r, const sp_digit* a,
        byte n)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    r[30] = a[29] >> (26 - n);
    for (i=29; i>0; i--) {
        r[i] = (sp_digit)(((a[i] << n) | (a[i-1] >> (26 - n))) & 0x3ffffff);
    }
#else
    sp_int_digit s;
    sp_int_digit t;

    s = (sp_int_digit)a[29];
    r[30] = s >> (26U - n);
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = (sp_digit)(((s << n) | (t >> (26U - n))) & 0x3ffffff);
#endif /* WOLFSSL_SP_SMALL */
    r[0] = (sp_digit)((a[0] << n) & 0x3ffffff);
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * Simplified based on top word of divisor being (1 << 26) - 1
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_384_div_15(const sp_digit* a, const sp_digit* d,
        const sp_digit* m, sp_digit* r)
{
    SP_DECL_VAR(sp_digit, t1, 4 * 15 + 3);
    int i;
    sp_digit r1;
    sp_digit mask;
    sp_digit* t2 = NULL;
    sp_digit* sd = NULL;
    int err = MP_OKAY;

    (void)m;

    SP_ALLOC_VAR(sp_digit, t1, 4 * 15 + 3, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (err == MP_OKAY) {
        t2 = t1 + 30 + 1;
        sd = t2 + 15 + 1;

        sp_384_mul_d_15(sd, d, (sp_digit)1 << 6);
        sp_384_lshift_30(t1, a, 6);
        t1[15 + 15] += t1[15 + 15 - 1] >> 26;
        t1[15 + 15 - 1] &= 0x3ffffff;
        for (i=14; i>=0; i--) {
            r1 = t1[15 + i];
            sp_384_mul_d_15(t2, sd, r1);
            (void)sp_384_sub_15(&t1[i], &t1[i], t2);
            t1[15 + i] -= t2[15];
            sp_384_norm_15(&t1[i + 1]);

            mask = ~((t1[15 + i] - 1) >> 31);
            sp_384_cond_sub_15(t1 + i, t1 + i, sd, mask);
            sp_384_norm_15(&t1[i + 1]);
        }
        sp_384_norm_15(t1);
        sp_384_rshift_15(r, t1, 6);
    }

    SP_FREE_VAR(t1, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_384_mod_15(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_384_div_15(a, m, NULL, r);
}

/* Multiply two number mod the order of P384 curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_384_mont_mul_order_15(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_384_mul_15(r, a, b);
    sp_384_mont_reduce_order_15(r, p384_order, p384_mp_order);
}

#if defined(HAVE_ECC_SIGN) || (defined(HAVE_ECC_VERIFY) && defined(WOLFSSL_SP_SMALL))
#ifdef WOLFSSL_SP_SMALL
/* Order-2 for the P384 curve. */
static const word32 p384_order_minus_2[12] = {
    0xccc52971U,0xecec196aU,0x48b0a77aU,0x581a0db2U,0xf4372ddfU,0xc7634d81U,
    0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU
};
#else
/* The low half of the order-2 of the P384 curve. */
static const word32 p384_order_low[6] = {
    0xccc52971U,0xecec196aU,0x48b0a77aU,0x581a0db2U,0xf4372ddfU,0xc7634d81U
};
#endif /* WOLFSSL_SP_SMALL */

/* Square number mod the order of P384 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_order_15(sp_digit* r, const sp_digit* a)
{
    sp_384_sqr_15(r, a);
    sp_384_mont_reduce_order_15(r, p384_order, p384_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P384 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_n_order_15(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_384_mont_sqr_order_15(r, a);
    for (i=1; i<n; i++) {
        sp_384_mont_sqr_order_15(r, r);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the order of the P384 curve.
 * (r = 1 / a mod order)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */


static void sp_384_mont_inv_order_15(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 15);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_order_15(t, t);
        if ((p384_order_minus_2[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_384_mont_mul_order_15(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 15U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 15;
    sp_digit* t3 = td + 4 * 15;
    int i;

    /* t = a^2 */
    sp_384_mont_sqr_order_15(t, a);
    /* t = a^3 = t * a */
    sp_384_mont_mul_order_15(t, t, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_384_mont_sqr_n_order_15(t2, t, 2);
    /* t = a^f = t2 * t */
    sp_384_mont_mul_order_15(t, t2, t);
    /* t2= a^f0 = t ^ 2 ^ 4 */
    sp_384_mont_sqr_n_order_15(t2, t, 4);
    /* t = a^ff = t2 * t */
    sp_384_mont_mul_order_15(t, t2, t);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_384_mont_sqr_n_order_15(t2, t, 8);
    /* t3= a^ffff = t2 * t */
    sp_384_mont_mul_order_15(t3, t2, t);
    /* t2= a^ffff0000 = t3 ^ 2 ^ 16 */
    sp_384_mont_sqr_n_order_15(t2, t3, 16);
    /* t = a^ffffffff = t2 * t3 */
    sp_384_mont_mul_order_15(t, t2, t3);
    /* t2= a^ffffffff0000 = t ^ 2 ^ 16  */
    sp_384_mont_sqr_n_order_15(t2, t, 16);
    /* t = a^ffffffffffff = t2 * t3 */
    sp_384_mont_mul_order_15(t, t2, t3);
    /* t2= a^ffffffffffff000000000000 = t ^ 2 ^ 48  */
    sp_384_mont_sqr_n_order_15(t2, t, 48);
    /* t= a^fffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_15(t, t2, t);
    /* t2= a^ffffffffffffffffffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_order_15(t2, t, 96);
    /* t2= a^ffffffffffffffffffffffffffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_15(t2, t2, t);
    for (i=191; i>=1; i--) {
        sp_384_mont_sqr_order_15(t2, t2);
        if ((p384_order_low[i / 32] & ((sp_int_digit)1 << (i % 32))) != 0) {
            sp_384_mont_mul_order_15(t2, t2, a);
        }
    }
    sp_384_mont_sqr_order_15(t2, t2);
    sp_384_mont_mul_order_15(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}

#endif /* HAVE_ECC_SIGN || (HAVE_ECC_VERIFY && WOLFSSL_SP_SMALL) */

#ifndef WOLFSSL_SP_SMALL
static const char sp_384_tab32_15[32] = {
     1, 10,  2, 11, 14, 22,  3, 30,
    12, 15, 17, 19, 23, 26,  4, 31,
     9, 13, 21, 29, 16, 18, 25,  8,
    20, 28, 24,  7, 27,  6,  5, 32};

static int sp_384_num_bits_26_15(sp_digit v)
{
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return sp_384_tab32_15[(word32)(v*0x07C4ACDD) >> 27];
}

static int sp_384_num_bits_15(const sp_digit* a)
{
    int i;
    int r = 0;

    for (i = 14; i >= 0; i--) {
        if (a[i] != 0) {
            r = sp_384_num_bits_26_15(a[i]);
            r += i * 26;
            break;
        }
    }

    return r;
}

/* Non-constant time modular inversion.
 *
 * @param  [out]  r   Resulting number.
 * @param  [in]   a   Number to invert.
 * @param  [in]   m   Modulus.
 * @return  MP_OKAY on success.
 * @return  MEMEORY_E when dynamic memory allocation fails.
 */
static int sp_384_mod_inv_15(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    int err = MP_OKAY;
    SP_DECL_VAR(sp_digit, u, 15 * 4);
    sp_digit* v = NULL;
    sp_digit* b = NULL;
    sp_digit* d = NULL;
    int ut;
    int vt;

    SP_ALLOC_VAR(sp_digit, u, 15 * 4, NULL, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        v = u + 15;
        b = u + 2 * 15;
        d = u + 3 * 15;

        XMEMCPY(u, m, sizeof(sp_digit) * 15);
        XMEMCPY(v, a, sizeof(sp_digit) * 15);

        ut = sp_384_num_bits_15(u);
        vt = sp_384_num_bits_15(v);

        XMEMSET(b, 0, sizeof(sp_digit) * 15);
        if ((v[0] & 1) == 0) {
            sp_384_rshift1_15(v, v);
            XMEMCPY(d, m, sizeof(sp_digit) * 15);
            d[0]++;
            sp_384_rshift1_15(d, d);
            vt--;

            while ((v[0] & 1) == 0) {
                sp_384_rshift1_15(v, v);
                if (d[0] & 1)
                    sp_384_add_15(d, d, m);
                sp_384_rshift1_15(d, d);
                vt--;
            }
        }
        else {
            XMEMSET(d+1, 0, sizeof(sp_digit) * (15 - 1));
            d[0] = 1;
        }

        while (ut > 1 && vt > 1) {
            if ((ut > vt) || ((ut == vt) &&
                    (sp_384_cmp_15(u, v) >= 0))) {
                sp_384_sub_15(u, u, v);
                sp_384_norm_15(u);

                sp_384_sub_15(b, b, d);
                sp_384_norm_15(b);
                if (b[14] < 0)
                    sp_384_add_15(b, b, m);
                sp_384_norm_15(b);
                ut = sp_384_num_bits_15(u);

                do {
                    sp_384_rshift1_15(u, u);
                    if (b[0] & 1)
                        sp_384_add_15(b, b, m);
                    sp_384_rshift1_15(b, b);
                    ut--;
                }
                while (ut > 0 && (u[0] & 1) == 0);
            }
            else {
                sp_384_sub_15(v, v, u);
                sp_384_norm_15(v);

                sp_384_sub_15(d, d, b);
                sp_384_norm_15(d);
                if (d[14] < 0)
                    sp_384_add_15(d, d, m);
                sp_384_norm_15(d);
                vt = sp_384_num_bits_15(v);

                do {
                    sp_384_rshift1_15(v, v);
                    if (d[0] & 1)
                        sp_384_add_15(d, d, m);
                    sp_384_rshift1_15(d, d);
                    vt--;
                }
                while (vt > 0 && (v[0] & 1) == 0);
            }
        }

        if (ut == 1)
            XMEMCPY(r, b, sizeof(sp_digit) * 15);
        else
            XMEMCPY(r, d, sizeof(sp_digit) * 15);
    }
    SP_FREE_VAR(u, NULL, DYNAMIC_TYPE_ECC);

    return err;
}

#endif /* WOLFSSL_SP_SMALL */

/* Add point p1 into point p2. Handles p1 == p2 and result at infinity.
 *
 * p1   First point to add and holds result.
 * p2   Second point to add.
 * tmp  Temporary storage for intermediate numbers.
 */
static void sp_384_add_points_15(sp_point_384* p1, const sp_point_384* p2,
    sp_digit* tmp)
{

        sp_384_proj_point_add_15(p1, p1, p2, tmp);
    if (sp_384_iszero_15(p1->z)) {
        if (sp_384_iszero_15(p1->x) && sp_384_iszero_15(p1->y)) {
                sp_384_proj_point_dbl_15(p1, p2, tmp);
        }
        else {
            /* Y ordinate is not used from here - don't set. */
            p1->x[0] = 0;
            p1->x[1] = 0;
            p1->x[2] = 0;
            p1->x[3] = 0;
            p1->x[4] = 0;
            p1->x[5] = 0;
            p1->x[6] = 0;
            p1->x[7] = 0;
            p1->x[8] = 0;
            p1->x[9] = 0;
            p1->x[10] = 0;
            p1->x[11] = 0;
            p1->x[12] = 0;
            p1->x[13] = 0;
            p1->x[14] = 0;
            XMEMCPY(p1->z, p384_norm_mod, sizeof(p384_norm_mod));
        }
    }
}

/* Calculate the verification point: [e/s]G + [r/s]Q
 *
 * p1    Calculated point.
 * p2    Public point and temporary.
 * s     Second part of signature as a number.
 * u1    Temporary number.
 * u2    Temporary number.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_calc_vfy_point_15(sp_point_384* p1, sp_point_384* p2,
    sp_digit* s, sp_digit* u1, sp_digit* u2, sp_digit* tmp, void* heap)
{
    int err;

#ifndef WOLFSSL_SP_SMALL
    err = sp_384_mod_inv_15(s, s, p384_order);
    if (err == MP_OKAY)
#endif /* !WOLFSSL_SP_SMALL */
    {
        sp_384_mul_15(s, s, p384_norm_order);
        err = sp_384_mod_15(s, s, p384_order);
    }
    if (err == MP_OKAY) {
        sp_384_norm_15(s);
#ifdef WOLFSSL_SP_SMALL
        {
            sp_384_mont_inv_order_15(s, s, tmp);
            sp_384_mont_mul_order_15(u1, u1, s);
            sp_384_mont_mul_order_15(u2, u2, s);
        }
#else
        {
            sp_384_mont_mul_order_15(u1, u1, s);
            sp_384_mont_mul_order_15(u2, u2, s);
        }
#endif /* WOLFSSL_SP_SMALL */
        {
            err = sp_384_ecc_mulmod_base_15(p1, u1, 0, 0, heap);
        }
    }
    if ((err == MP_OKAY) && sp_384_iszero_15(p1->z)) {
        p1->infinity = 1;
    }
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_15(p2, p2, u2, 0, 0, heap);
    }
    if ((err == MP_OKAY) && sp_384_iszero_15(p2->z)) {
        p2->infinity = 1;
    }

    if (err == MP_OKAY) {
        sp_384_add_points_15(p1, p2, tmp);
    }

    return err;
}

/* Verify the signature values with the hash and public key.
 *   e = Truncate(hash, 384)
 *   u1 = e/s mod order
 *   u2 = r/s mod order
 *   r == (u1.G + u2.Q)->x mod order
 * Optimization: Leave point in projective form.
 *   (x, y, 1) == (x' / z'*z', y' / z'*z'*z', z' / z')
 *   (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x'
 * The hash is truncated to the first 384 bits.
 *
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * rng      Random number generator.
 * priv     Private part of key - scalar.
 * rm       First part of result as an mp_int.
 * sm       Sirst part of result as an mp_int.
 * heap     Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_verify_384(const byte* hash, word32 hashLen, const mp_int* pX,
    const mp_int* pY, const mp_int* pZ, const mp_int* rm, const mp_int* sm,
    int* res, void* heap)
{
    SP_DECL_VAR(sp_digit, u1, 18 * 15);
    SP_DECL_VAR(sp_point_384, p1, 2);
    sp_digit* u2 = NULL;
    sp_digit* s = NULL;
    sp_digit* tmp = NULL;
    sp_point_384* p2 = NULL;
    sp_digit carry;
    sp_int32 c = 0;
    int err = MP_OKAY;

    SP_ALLOC_VAR(sp_digit, u1, 18 * 15, heap, DYNAMIC_TYPE_ECC);
    SP_ALLOC_VAR(sp_point_384, p1, 2, heap, DYNAMIC_TYPE_ECC);
    if (err == MP_OKAY) {
        u2  = u1 + 2 * 15;
        s   = u1 + 4 * 15;
        tmp = u1 + 6 * 15;
        p2 = p1 + 1;

        if (hashLen > 48U) {
            hashLen = 48U;
        }

        sp_384_from_bin(u1, 15, hash, (int)hashLen);
        sp_384_from_mp(u2, 15, rm);
        sp_384_from_mp(s, 15, sm);
        sp_384_from_mp(p2->x, 15, pX);
        sp_384_from_mp(p2->y, 15, pY);
        sp_384_from_mp(p2->z, 15, pZ);

        err = sp_384_calc_vfy_point_15(p1, p2, s, u1, u2, tmp, heap);
    }
    if (err == MP_OKAY) {
        /* (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x' */
        /* Reload r and convert to Montgomery form. */
        sp_384_from_mp(u2, 15, rm);
        err = sp_384_mod_mul_norm_15(u2, u2, p384_mod);
    }

    if (err == MP_OKAY) {
        /* u1 = r.z'.z' mod prime */
            sp_384_mont_sqr_15(p1->z, p1->z, p384_mod, p384_mp_mod);
            sp_384_mont_mul_15(u1, u2, p1->z, p384_mod, p384_mp_mod);
        *res = (int)(sp_384_cmp_15(p1->x, u1) == 0);
        if (*res == 0) {
            /* Reload r and add order. */
            sp_384_from_mp(u2, 15, rm);
            carry = sp_384_add_15(u2, u2, p384_order);
            /* Carry means result is greater than mod and is not valid. */
            if (carry == 0) {
                sp_384_norm_15(u2);

                /* Compare with mod and if greater or equal then not valid. */
                c = sp_384_cmp_15(u2, p384_mod);
            }
        }
        if ((*res == 0) && (c < 0)) {
            /* Convert to Montogomery form */
            err = sp_384_mod_mul_norm_15(u2, u2, p384_mod);
            if (err == MP_OKAY) {
                /* u1 = (r + 1*order).z'.z' mod prime */
                {
                    sp_384_mont_mul_15(u1, u2, p1->z, p384_mod, p384_mp_mod);
                }
                *res = (sp_384_cmp_15(p1->x, u1) == 0);
            }
        }
    }

    SP_FREE_VAR(p1, heap, DYNAMIC_TYPE_ECC);
    SP_FREE_VAR(u1, heap, DYNAMIC_TYPE_ECC);
    return err;
}


/* Check that the x and y ordinates are a valid point on the curve.
 *
 * point  EC point.
 * heap   Heap to use if dynamically allocating.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */

/* Check that the x and y ordinates are a valid point on the curve.
 *
 * pX  X ordinate of EC point.
 * pY  Y ordinate of EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */

/* Check that the private scalar generates the EC point (px, py), the point is
 * on the curve and the point has the correct order.
 *
 * pX     X ordinate of EC point.
 * pY     Y ordinate of EC point.
 * privm  Private scalar that generates EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve, ECC_INF_E if the point does not have the correct order,
 * ECC_PRIV_KEY_E when the private scalar doesn't generate the EC point and
 * MP_OKAY otherwise.
 */
