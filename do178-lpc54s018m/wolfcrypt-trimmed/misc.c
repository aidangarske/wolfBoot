/* misc.c
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
/*

DESCRIPTION
This module implements the arithmetic-shift right, left, byte swapping, XOR,
masking and clearing memory logic.

*/

#ifdef WOLFSSL_VIS_FOR_TESTS
    #ifdef HAVE_CONFIG_H
        #include <config.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#endif

#ifndef WOLF_CRYPT_MISC_C
#define WOLF_CRYPT_MISC_C

#include <wolfssl/wolfcrypt/misc.h>

/* inlining these functions is a huge speed increase and a small size decrease,
   because the functions are smaller than function call setup/cleanup, e.g.,
   md5 benchmark is twice as fast with inline.  If you don't want it, then
   define NO_INLINE and compile this file into wolfssl, otherwise it's used as
   a source header
 */

/* Check for if compiling misc.c when not needed. */
#if !defined(WOLFSSL_MISC_INCLUDED) && !defined(NO_INLINE)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning misc.c does not need to be compiled when using inline (NO_INLINE not defined)
    #endif

#else


#if defined(__ICCARM__)
    #include <intrinsics.h>
#endif


#ifdef INTEL_INTRINSICS

    #include <stdlib.h>      /* get intrinsic definitions */

    /* for non visual studio probably need no long version, 32 bit only
     * i.e., _rotl and _rotr */
    #pragma intrinsic(_lrotl, _lrotr)

    WC_MISC_STATIC WC_INLINE word32 rotlFixed(word32 x, word32 y)
    {
        return y ? _lrotl(x, y) : x;
    }


#elif defined(__CCRX__)

    #include <builtin.h>      /* get intrinsic definitions */

    #if !defined(NO_INLINE)

    #define rotlFixed(x, y) _builtin_rotl(x, y)

    #define rotrFixed(x, y) _builtin_rotr(x, y)

    #else /* create real function */

    WC_MISC_STATIC WC_INLINE word32 rotlFixed(word32 x, word32 y)
    {
        return _builtin_rotl(x, y);
    }


    #endif

#else /* generic */
/* This routine performs a left circular arithmetic shift of <x> by <y> value. */

    WC_MISC_STATIC WC_INLINE word32 rotlFixed(word32 x, word32 y)
    {
        return (x << y) | (x >> (sizeof(x) * 8 - y));
    }

/* This routine performs a right circular arithmetic shift of <x> by <y> value. */

#endif

/* This routine performs a left circular arithmetic shift of <x> by <y> value */


/* This routine performs a right circular arithmetic shift of <x> by <y> value */

/* This routine performs a byte swap of 32-bit word value. */
#if defined(__CCRX__) && !defined(NO_INLINE) /* shortest version for CC-RX */
    #define ByteReverseWord32(value) _builtin_revl(value)
#else
WC_MISC_STATIC WC_INLINE word32 ByteReverseWord32(word32 value)
{
#ifdef PPC_INTRINSICS
    /* PPC: load reverse indexed instruction */
    return (word32)__lwbrx(&value,0);
#elif defined(__ICCARM__)
    return (word32)__REV(value);
#elif defined(KEIL_INTRINSICS)
    return (word32)__rev(value);
#elif defined(__CCRX__)
    return (word32)_builtin_revl(value);
#elif defined(WOLF_ALLOW_BUILTIN) && \
        defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
    return (word32)__builtin_bswap32(value);
#elif defined(WOLFSSL_BYTESWAP32_ASM) && defined(__GNUC__) && \
      defined(__aarch64__)
    __asm__ volatile (
        "REV32 %0, %0  \n"
        : "+r" (value)
        :
    );
    return value;
#elif defined(WOLFSSL_BYTESWAP32_ASM) && defined(__GNUC__) && \
      (defined(__thumb__) || defined(__arm__))
    __asm__ volatile (
        "REV %0, %0  \n"
        : "+r" (value)
        :
    );
    return value;
#elif defined(FAST_ROTATE)
    /* 5 instructions with rotate instruction, 9 without */
    return (rotrFixed(value, 8U) & 0xff00ff00) |
           (rotlFixed(value, 8U) & 0x00ff00ff);
#else
    /* 6 instructions with rotate instruction, 8 without */
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return rotlFixed(value, 16U);
#endif
}
#endif /* __CCRX__ */
/* This routine performs a byte swap of words array of a given count. */





#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_NO_WORD64_OPS)







WC_MISC_STATIC WC_INLINE word64 rotrFixed64(word64 x, word64 y)
{
    return (x >> y) | (x << (sizeof(y) * 8 - y));
}


WC_MISC_STATIC WC_INLINE word64 ByteReverseWord64(word64 value)
{
#if defined(WOLF_ALLOW_BUILTIN) && defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
    return (word64)__builtin_bswap64(value);
#elif defined(WOLFCRYPT_SLOW_WORD64)
    return (word64)((word64)ByteReverseWord32((word32) value)) << 32 |
        (word64)ByteReverseWord32((word32)(value   >> 32));
#else
    value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) |
        ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
    value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) |
        ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
    return rotlFixed64(value, 32U);
#endif
}


WC_MISC_STATIC WC_INLINE void ByteReverseWords64(word64* out, const word64* in,
                                      word32 byteCount)
{
    word32 count = byteCount/(word32)sizeof(word64), i;

#ifdef WOLFSSL_USE_ALIGN
    if ((((size_t)in & 0x7) == 0) &&
        (((size_t)out & 0x7) == 0))
#endif
    {
        for (i = 0; i < count; i++)
            out[i] = ByteReverseWord64(in[i]);
    }
#ifdef WOLFSSL_USE_ALIGN
    else if (((size_t)in & 0x7) == 0) {
        byte *out_bytes = (byte *)out;
        word64 scratch;

        byteCount &= ~0x7U;

        for (i = 0; i < byteCount; i += (word32)sizeof(word64)) {
            scratch = ByteReverseWord64(*in++);
            XMEMCPY(out_bytes + i, &scratch, sizeof(scratch));
        }
    }
    else if (((size_t)out & 0x7) == 0) {
        const byte *in_bytes = (const byte *)in;
        word64 scratch;

        byteCount &= ~0x7U;

        for (i = 0; i < byteCount; i += (word32)sizeof(word64)) {
            XMEMCPY(&scratch, in_bytes + i, sizeof(scratch));
            *out++ = ByteReverseWord64(scratch);
        }
    }
    else {
        const byte *in_bytes = (const byte *)in;
        byte *out_bytes = (byte *)out;
        word64 scratch;

        byteCount &= ~0x7U;

        for (i = 0; i < byteCount; i += (word32)sizeof(word64)) {
            XMEMCPY(&scratch, in_bytes + i, sizeof(scratch));
            scratch = ByteReverseWord64(scratch);
            XMEMCPY(out_bytes + i, &scratch, sizeof(scratch));
        }
    }
#endif
}

#endif /* WORD64_AVAILABLE && !WOLFSSL_NO_WORD64_OPS */

#ifndef WOLFSSL_NO_XOR_OPS

/* Leave no doubt that WOLFSSL_WORD_SIZE is a power of 2. */
wc_static_assert((WOLFSSL_WORD_SIZE & (WOLFSSL_WORD_SIZE - 1)) == 0);

/* This routine performs a bitwise XOR operation of <*a> and <*b> for <n> number
of wolfssl_words, placing the result in <*r>. */

/* This routine performs a bitwise XOR operation of <*buf> and <*mask> of n
counts, placing the result in <*out>. */


/* This routine performs a bitwise XOR operation of <*r> and <*a> for <n> number
of wolfssl_words, placing the result in <*r>. */

/* This routine performs a bitwise XOR operation of <*buf> and <*mask> of n
counts, placing the result in <*buf>. */


#endif /* !WOLFSSL_NO_XOR_OPS */

#ifndef WOLFSSL_NO_FORCE_ZERO
/* This routine fills the first len bytes of the memory area pointed by mem
   with zeros. It ensures compiler optimization doesn't skip it. */
WC_MISC_STATIC WC_INLINE void ForceZero(void* mem, size_t len)
{
    byte *zb = (byte *)mem;
    unsigned long *zl;

    XFENCE();

    while ((wc_ptr_t)zb & (wc_ptr_t)(sizeof(unsigned long) - 1U)) {
        if (len == 0)
            return;
        *zb++ = 0;
        --len;
    }

    zl = (unsigned long *)zb;

    while (len >= sizeof(unsigned long)) {
        *zl++ = 0;
        len -= sizeof(unsigned long);
    }

    zb = (byte *)zl;

    while (len) {
        *zb++ = 0;
        --len;
    }

    XFENCE();
}
#endif


#ifndef WOLFSSL_NO_CONST_CMP
/* check all length bytes for equality, return 0 on success */
#endif


#if defined(WOLFSSL_NO_CT_OPS) && (!defined(NO_RSA) || !defined(WOLFCRYPT_ONLY)) \
    && (!defined(WOLFSSL_RSA_VERIFY_ONLY))
/* constant time operations with mask are required for RSA and TLS operations */
#warning constant time operations required unless using NO_RSA & WOLFCRYPT_ONLY
#endif

#if !defined(WOLFSSL_NO_CT_OPS) || !defined(NO_RSA) || !defined(WOLFCRYPT_ONLY)
/* Constant time - mask set when a > b. */
WC_MISC_STATIC WC_INLINE byte ctMaskGT(int a, int b)
{
    return (byte)((((word32)a - (word32)b - 1) >> 31) - 1);
}

/* Constant time - mask set when a >= b. */

/* Constant time - mask set when a >= b. */

#ifdef WORD64_AVAILABLE
/* Constant time - mask set when a >= b. */
WC_MISC_STATIC WC_INLINE word32 ctMaskWord32GTE(word32 a, word32 b)
{
  return (word32)((((word64)a - (word64)b) >> 63) - 1);
}
#endif

/* Constant time - mask set when a < b. */
WC_MISC_STATIC WC_INLINE byte ctMaskLT(int a, int b)
{
    return (byte)((((word32)b - (word32)a - 1) >> 31) - 1);
}

/* Constant time - mask set when a <= b. */

/* Constant time - mask set when a == b. */
WC_MISC_STATIC WC_INLINE byte ctMaskEq(int a, int b)
{
    return (byte)((byte)(~ctMaskGT(a, b)) & (byte)(~ctMaskLT(a, b)));
}

/* Constant time - sets 16 bit integer mask when a > b */

/* Constant time - sets 16 bit integer mask when a >= b */

/* Constant time - sets 16 bit integer mask when a < b. */

/* Constant time - sets 16 bit integer mask when a <= b. */

/* Constant time - sets 16 bit integer mask when a == b. */

/* Constant time - mask set when a != b. */

/* Constant time - select a when mask is set and b otherwise. */

/* Constant time - select integer a when mask is set and integer b otherwise. */

/* Constant time - select word32 a when mask is set and word32 b otherwise. */

/* Constant time - bit set when a <= b. */

/* Constant time - conditionally copy size bytes from src to dst if mask is set
 */

#endif /* !WOLFSSL_NO_CT_OPS */

#ifndef WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MIN
    #if defined(HAVE_FIPS) && !defined(min) /* so ifdef check passes */
        #define min min
    #endif
    /* returns the smaller of a and b */
    WC_MISC_STATIC WC_INLINE word32 min(word32 a, word32 b)
    {
#if !defined(WOLFSSL_NO_CT_OPS) && !defined(WOLFSSL_NO_CT_MAX_MIN) && \
    defined(WORD64_AVAILABLE)
        volatile word32 gte_mask = (word32)ctMaskWord32GTE(a, b);
        word32 r = (a & ~gte_mask);
        r |= (b & gte_mask);
        return r;
#else /* WOLFSSL_NO_CT_OPS */
        return a > b ? b : a;
#endif /* WOLFSSL_NO_CT_OPS */
    }
#endif /* !WOLFSSL_HAVE_MIN */

#ifndef WOLFSSL_HAVE_MAX
    #define WOLFSSL_HAVE_MAX
    #if defined(HAVE_FIPS) && !defined(max) /* so ifdef check passes */
        #define max max
    #endif
#endif /* !WOLFSSL_HAVE_MAX */

#ifndef WOLFSSL_NO_INT_ENCODE
/* converts a 32 bit integer to 24 bit */

/* convert 16 bit integer to opaque */

/* convert 32 bit integer to opaque */
#endif

#ifndef WOLFSSL_NO_INT_DECODE
/* convert a 24 bit integer into a 32 bit one */


/* convert opaque to 24 bit integer */

/* convert opaque to 16 bit integer */

/* convert opaque to 32 bit integer */

/* convert opaque to 32 bit integer. Interpret as little endian. */


#endif

WC_MISC_STATIC WC_INLINE signed char HexCharToByte(char ch)
{
    signed char ret = (signed char)ch;
    if (ret >= '0' && ret <= '9')
        ret = (signed char)(ret - '0');
    else if (ret >= 'A' && ret <= 'F')
        ret = (signed char)(ret - ('A' - 10));
    else if (ret >= 'a' && ret <= 'f')
        ret = (signed char)(ret - ('a' - 10));
    else
        ret = -1; /* error case - return code must be signed */
    return ret;
}



WC_MISC_STATIC WC_INLINE int CharIsWhiteSpace(char ch)
{
#ifndef WOLFSSL_NO_CT_OPS
    return (ctMaskEq(ch, ' ') |
            ctMaskEq(ch, '\t') |
            ctMaskEq(ch, '\n')) & 1;
#else /* WOLFSSL_NO_CT_OPS */
    switch (ch) {
        case ' ':
        case '\t':
        case '\n':
            return 1;
        default:
            return 0;
    }
#endif /* WOLFSSL_NO_CT_OPS */
}

#if defined(WOLFSSL_W64_WRAPPER)
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_W64_WRAPPER_TEST)





















#else





















#endif /* WORD64_AVAILABLE && !WOLFSSL_W64_WRAPPER_TEST */
#endif /* WOLFSSL_W64_WRAPPER */

#if defined(HAVE_SESSION_TICKET) || !defined(NO_CERTS) || \
    !defined(NO_SESSION_CACHE)
/* Make a word from the front of random hash */
#endif /* HAVE_SESSION_TICKET || !NO_CERTS || !NO_SESSION_CACHE */


#if !defined(WOLFCRYPT_ONLY) && !defined(NO_HASH_WRAPPER) && \
    (!defined(NO_SESSION_CACHE) || defined(HAVE_SESSION_TICKET))

#include <wolfssl/wolfcrypt/hash.h>

/* some session IDs aren't random after all, let's make them random */
#endif /* WOLFCRYPT_ONLY && !NO_HASH_WRAPPER &&
        * (!NO_SESSION_CACHE || HAVE_SESSION_TICKET) */


#endif /* !WOLFSSL_MISC_INCLUDED && !NO_INLINE */

#endif /* WOLF_CRYPT_MISC_C */
