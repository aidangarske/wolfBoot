/* sp_int.c
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

/*
DESCRIPTION
This library provides single precision (SP) integer math functions.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>


    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

/* SP Build Options:
 * WOLFSSL_HAVE_SP_RSA:         Enable SP RSA support
 * WOLFSSL_HAVE_SP_DH:          Enable SP DH support
 * WOLFSSL_HAVE_SP_ECC:         Enable SP ECC support
 * WOLFSSL_SP_MATH:             Use only single precision math and algorithms
 *      it supports (no fastmath tfm.c or normal integer.c)
 * WOLFSSL_SP_MATH_ALL          Implementation of all MP functions
 *      (replacement for tfm.c and integer.c)
 * WOLFSSL_SP_SMALL:            Use smaller version of code and avoid large
 *      stack variables
 * WOLFSSL_SP_NO_MALLOC:        Always use stack, no heap XMALLOC/XFREE allowed
 * WOLFSSL_SP_NO_2048:          Disable RSA/DH 2048-bit support
 * WOLFSSL_SP_NO_3072:          Disable RSA/DH 3072-bit support
 * WOLFSSL_SP_4096:             Enable RSA/RH 4096-bit support
 * WOLFSSL_SP_NO_256            Disable ECC 256-bit SECP256R1 support
 * WOLFSSL_SP_384               Enable ECC 384-bit SECP384R1 support
 * WOLFSSL_SP_521               Enable ECC 521-bit SECP521R1 support
 * WOLFSSL_SP_ASM               Enable assembly speedups (detect platform)
 * WOLFSSL_SP_X86_64_ASM        Enable Intel x64 assembly implementation
 * WOLFSSL_SP_ARM32_ASM         Enable Aarch32 assembly implementation
 * WOLFSSL_SP_ARM64_ASM         Enable Aarch64 assembly implementation
 * WOLFSSL_SP_ARM_CORTEX_M_ASM  Enable Cortex-M assembly implementation
 * WOLFSSL_SP_ARM_THUMB_ASM     Enable ARM Thumb assembly implementation
 *      (used with -mthumb)
 * WOLFSSL_SP_X86_64            Enable Intel x86 64-bit assembly speedups
 * WOLFSSL_SP_X86               Enable Intel x86 assembly speedups
 * WOLFSSL_SP_ARM64             Enable Aarch64 assembly speedups
 * WOLFSSL_SP_ARM32             Enable ARM32 assembly speedups
 * WOLFSSL_SP_ARM32_UDIV        Enable word divide asm that uses UDIV instr
 * WOLFSSL_SP_ARM_THUMB         Enable ARM Thumb assembly speedups
 *                              (explicitly uses register 'r7')
 * WOLFSSL_SP_PPC64             Enable PPC64 assembly speedups
 * WOLFSSL_SP_PPC               Enable PPC assembly speedups
 * WOLFSSL_SP_MIPS64            Enable MIPS64 assembly speedups
 * WOLFSSL_SP_MIPS              Enable MIPS assembly speedups
 * WOLFSSL_SP_RISCV64           Enable RISCV64 assembly speedups
 * WOLFSSL_SP_RISCV32           Enable RISCV32 assembly speedups
 * WOLFSSL_SP_S390X             Enable S390X assembly speedups
 * SP_WORD_SIZE                 Force 32 or 64 bit mode
 * WOLFSSL_SP_NONBLOCK          Enables "non blocking" mode for SP math, which
 *      will return FP_WOULDBLOCK for long operations and function must be
 *      called again until complete.
 * WOLFSSL_SP_FAST_NCT_EXPTMOD  Enables the faster non-constant time modular
 *      exponentiation implementation.
 * WOLFSSL_SP_INT_NEGATIVE      Enables negative values to be used.
 * WOLFSSL_SP_INT_DIGIT_ALIGN   Enable when unaligned access of sp_int_digit
 *                              pointer is not allowed.
 * WOLFSSL_SP_NO_DYN_STACK      Disable use of dynamic stack items.
 *                              Dynamic arrays used when not small stack.
 * WOLFSSL_SP_FAST_MODEXP       Allow fast mod_exp with small C code
 * WOLFSSL_SP_LOW_MEM           Use algorithms that use less memory.
 * WOLFSSL_SMALL_STACK:         Use heap for large structures to reduce
 *      stack usage
 * WOLFSSL_KEY_GEN:             Key generation support enabled
 * WOLFSSL_RSA_PUBLIC_ONLY:     Only RSA public operations compiled in
 * WOLFSSL_RSA_VERIFY_ONLY:     Only RSA verify operations compiled in
 * NO_RSA:                      RSA support disabled
 * NO_DH:                       DH support disabled
 * NO_DSA:                      DSA support disabled
 * NO_INLINE:                   sp_int.c includes misc.c directly instead of
 *      inlining
 * HAVE_ECC:                    ECC support enabled, enables ECC-related SP
 *      functions
 * HAVE_FIPS:                   FIPS mode enabled
 * HAVE_WOLF_BIGINT:            wolfBigInt support, enables bigint conversion
 *      functions
 * FREESCALE_LTC_TFM:           Freescale LTC hardware acceleration replaces SP
 *      modular exponentiation
 * OPENSSL_EXTRA:               OpenSSL API compatibility enabled
 * OPENSSL_ALL:                 Full OpenSSL API compatibility enabled
 * WC_NO_HARDEN:                Disable timing attack resistance
 * WC_NO_CACHE_RESISTANT:       Disable cache-resistant (constant-address)
 *      operations
 * WC_NO_RNG:                   No RNG available, disables functions needing
 *      random numbers
 * WC_PROTECT_ENCRYPTED_MEM:    Enable protection of encrypted memory
 *      operations
 * WC_DISABLE_RADIX_ZERO_PAD:   Disable zero padding when converting to a
 *      radix string
 * WOLFSSL_NO_CT_OPS:           Disable constant-time operations
 * WOLFSSL_CHECK_MEM_ZERO:      Enable checking that sensitive memory is
 *      zeroed on free
 * WOLFSSL_SP_MILLER_RABIN_CNT: Number of Miller-Rabin rounds for prime
 *      testing (default: 8)
 * WOLFSSL_NO_ASM:              Disable all assembly implementations
 * WOLFSSL_KEIL:                Keil compiler in use, affects inline assembly
 *      syntax
 * WOLFSSL_USE_SAVE_VECTOR_REGISTERS: Save/restore vector registers around
 *      SP ASM calls
 * WOLFSSL_SP_INT_LARGE_COMBA:  Enable large Comba multiplication and
 *      squaring
 * WOLFSSL_SP_INT_SQR_VOLATILE: Declare squaring intermediate variables as
 *      volatile
 * SP_INT_NO_ASM:               Disable use of SP ASM even when
 *      SP_INT_ASM_AVAILABLE is set
 * SP_MATH_NEED_ADD_OFF:        Enable sp_add variant with an offset into
 *      the result
 *
 * The following are not user settable but are set in settings.h or sp_int.h
 * based on other defines and platform:
 * BIG_ENDIAN_ORDER:            (Auto) Set in types.h when WORDS_BIGENDIAN
 *      is defined by the platform or build system
 * LITTLE_ENDIAN_ORDER:         (Auto) Set in types.h when BIG_ENDIAN_ORDER
 *      is not defined; the default byte ordering
 * WOLFSSL_SP_DYN_STACK:        (Auto) Set in sp_int.h when C99 and
 *      conditions allow a dynamic stack sp_int
 * WOLFSSL_SP_DIV_WORD_HALF:    (Auto) Set in sp_int.h/settings.h when
 *      platform lacks a native double-word type
 * WOLFSSL_ARM_ARCH:            (Auto) Set in sp_int.h as alias for
 *      WOLFSSL_SP_ARM_ARCH; use WOLFSSL_SP_ARM_ARCH to configure
 * WOLFSSL_SP_ADD_D:            (Auto) Set in settings.h; enables sp_add_d
 *      based on which algorithms are active
 * WOLFSSL_SP_SUB_D:            (Auto) Set in settings.h; enables sp_sub_d
 *      based on which algorithms are active
 * WOLFSSL_SP_MUL_D:            (Auto) Set in settings.h; enables sp_mul_d
 *      based on which algorithms are active
 * WOLFSSL_SP_DIV_D:            (Auto) Set in sp_int.c; enables sp_div_d
 *      based on which algorithms are active
 * WOLFSSL_SP_MOD_D:            (Auto) Set in sp_int.c; enables sp_mod_d
 *      based on which algorithms are active
 * WOLFSSL_SP_INVMOD:           (Auto) Set in settings.h; enables
 *      sp_invmod based on which algorithms are active
 * WOLFSSL_SP_INVMOD_MONT_CT:   (Auto) Set in settings.h; enables
 *      constant-time Montgomery inverse when needed
 * WOLFSSL_SP_PRIME_GEN:        (Auto) Set in settings.h; enables prime
 *      generation based on which algorithms are active
 * WOLFSSL_SP_READ_RADIX_16:    (Auto) Set in settings.h; enables reading
 *      base-16 strings based on which algorithms are active
 * WOLFSSL_SP_READ_RADIX_10:    (Auto) Set in settings.h; enables reading
 *      base-10 strings based on which algorithms are active
 *
 * SP_ALLOC:                    (Internal) Heap allocation in use for SP
 *      variables in exptmod
 * SP_ALLOC_PREDEFINED:         (Internal) Set when SP_ALLOC was defined
 *      before this file
 * SP_INT_ASM_AVAILABLE:        (Internal) Set when a platform ASM
 *      implementation is present
 * SP_ASM_DIV_WORD:             (Internal) Platform macro: hardware
 *      double-word division available
 * SP_WORD_OVERFLOW:            (Internal) Set in sp_int.h when mul/sqr
 *      partial sums can overflow sp_int_word
 */

/* TODO: WOLFSSL_SP_SMALL is incompatible with clang-12+ -Os. */

#include <wolfssl/wolfcrypt/sp_int.h>



/* DECL_SP_INT: Declare one variable of type 'sp_int'. */
        /* Declare a variable on the stack. */
        #define DECL_SP_INT(n, s)                sp_int n[1]

/* ALLOC_SP_INT: Allocate an 'sp_int' of required size. */
    /* Array declared on stack - check size is valid. */
    #define ALLOC_SP_INT(n, s, err, h)                                          do {                                                                        if (((err) == MP_OKAY) && ((s) > (int)SP_INT_DIGITS)) {                 (err) = MP_VAL;                                                     }                                                                       }                                                                           while (0)

    /* Array declared on stack - set the size field. */
    #define ALLOC_SP_INT_SIZE(n, s, err, h)                                     do {                                                                        ALLOC_SP_INT(n, s, err, h);                                             if ((err) == MP_OKAY) {                                                 (n)->size = (sp_size_t)(s);                                         }                                                                       }                                                                           while (0)

/* FREE_SP_INT: Free an 'sp_int' variable. */
    /* Nothing to do as declared on stack. */
    #define FREE_SP_INT(n, h) WC_DO_NOTHING


/* Declare a variable that will be assigned a value on XMALLOC. */
#define DECL_DYN_SP_INT_ARRAY(n, s, c)                sp_int* n##d = NULL;                              sp_int* (n)[c];                                   void *n ## _dummy_var = XMEMSET(n, 0, sizeof(n))

/* DECL_SP_INT_ARRAY: Declare array of 'sp_int'. */
    /* Declare a variable on the stack. */
    #define DECL_SP_INT_ARRAY(n, s, c)       sp_int n##d[c];                      sp_int* (n)[c]

/* Dynamically allocate just enough data to support multiple sp_ints of the
 * required size. Use pointers into data to make up array and set sizes.
 */
#define ALLOC_DYN_SP_INT_ARRAY(n, s, c, err, h)                                 do {                                                                            (void)n ## _dummy_var;                                                      if (((err) == MP_OKAY) && ((s) > SP_INT_DIGITS)) {                          (err) = MP_VAL;                                                         }                                                                           if ((err) == MP_OKAY) {                                                     n##d = (sp_int*)XMALLOC(MP_INT_SIZEOF(s) * (c), (h),                    DYNAMIC_TYPE_BIGINT);  if (n##d == NULL) {                                                     (err) = MP_MEM;                                                     }                                                                       else {                                                                  int n##ii;                                                          (n)[0] = n##d;                                                      (n)[0]->size = (sp_size_t)(s);                                      for (n##ii = 1; n##ii < (int)(c); n##ii++) {                        (n)[n##ii] = MP_INT_NEXT((n)[n##ii-1], s);                      (n)[n##ii]->size = (sp_size_t)(s);                              }                                                                   }                                                                       }                                                                           }                                                                               while (0)

/* ALLOC_SP_INT_ARRAY: Allocate an array of 'sp_int's of required size. */
    /* Data declared on stack that supports multiple sp_ints of the
     * required size. Set into array and set sizes.
     */
    #define ALLOC_SP_INT_ARRAY(n, s, c, err, h)                                 do {                                                                        if (((err) == MP_OKAY) && ((s) > SP_INT_DIGITS)) {                      (err) = MP_VAL;                                                     }                                                                       if ((err) == MP_OKAY) {                                                 int n##ii;                                                          for (n##ii = 0; n##ii < (int)(c); n##ii++) {                        (n)[n##ii] = &n##d[n##ii];                                      (n)[n##ii]->size = (sp_size_t)(s);                              }                                                                   }                                                                       }                                                                           while (0)

/* Free data variable that was dynamically allocated. */
#define FREE_DYN_SP_INT_ARRAY(n, h)              do {                                             if (n##d != NULL) {                          XFREE(n##d, h, DYNAMIC_TYPE_BIGINT);     }                                            }                                                while (0)

/* FREE_SP_INT_ARRAY: Free an array of 'sp_int'. */
    /* Nothing to do as data declared on stack. */
    #define FREE_SP_INT_ARRAY(n, h) WC_DO_NOTHING
























/* Set the multi-precision number to zero.
 *
 * Assumes a is not NULL.
 *
 * @param [out] a  SP integer to set to zero.
 */
static void _sp_zero(volatile sp_int* a)
{
    volatile sp_int_minimal* am = (volatile sp_int_minimal *)a;

    am->used = 0;
    am->dp[0] = 0;
}


/* Initialize the multi-precision number to be zero with a given max size.
 *
 * @param [out] a     SP integer.
 * @param [in]  size  Number of words to make available.
 */
static void _sp_init_size(sp_int* a, unsigned int size)
{
    volatile sp_int_minimal* am = (sp_int_minimal *)a;

    _sp_zero((volatile sp_int*)am);

    am->size = (sp_size_t)size;
}

/* Initialize the multi-precision number to be zero with a given max size.
 *
 * @param [out] a     SP integer.
 * @param [in]  size  Number of words to make available.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */

/* Initialize the multi-precision number to be zero.
 *
 * @param [out] a  SP integer.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_init(sp_int* a)
{
    int err = MP_OKAY;

    /* Validate parameter. */
    if (a == NULL) {
        err = MP_VAL;
    }
    else {
        /* Assume complete sp_int with SP_INT_DIGITS digits. */
        _sp_init_size(a, SP_INT_DIGITS);
    }

    return err;
}

/* Initialize up to six multi-precision numbers to be zero.
 *
 * @param [out] n1  SP integer.
 * @param [out] n2  SP integer.
 * @param [out] n3  SP integer.
 * @param [out] n4  SP integer.
 * @param [out] n5  SP integer.
 * @param [out] n6  SP integer.
 *
 * @return  MP_OKAY on success.
 */
int sp_init_multi(sp_int* n1, sp_int* n2, sp_int* n3, sp_int* n4, sp_int* n5,
    sp_int* n6)
{
    /* Initialize only those pointers that are valid. */
    if (n1 != NULL) {
        _sp_init_size(n1, SP_INT_DIGITS);
    }
    if (n2 != NULL) {
        _sp_init_size(n2, SP_INT_DIGITS);
    }
    if (n3 != NULL) {
        _sp_init_size(n3, SP_INT_DIGITS);
    }
    if (n4 != NULL) {
        _sp_init_size(n4, SP_INT_DIGITS);
    }
    if (n5 != NULL) {
        _sp_init_size(n5, SP_INT_DIGITS);
    }
    if (n6 != NULL) {
        _sp_init_size(n6, SP_INT_DIGITS);
    }

    return MP_OKAY;
}

/* Free the memory allocated in the multi-precision number.
 *
 * @param [in] a  SP integer.
 */
void sp_free(sp_int* a)
{
    if (a != NULL) {
    }
}

/* Grow multi-precision number to be able to hold l digits.
 * This function does nothing as the number of digits is fixed.
 *
 * @param [in, out] a  SP integer.
 * @param [in]      l  Number of digits to grow to.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when the number of digits requested is more than available.
 */
int sp_grow(sp_int* a, int l)
{
    int err = MP_OKAY;

    /* Validate parameter. */
    if ((a == NULL) || (l < 0)) {
        err = MP_VAL;
    }
    /* Ensure enough words allocated for grow. */
    if ((err == MP_OKAY) && ((unsigned int)l > a->size)) {
        err = MP_MEM;
    }
    if (err == MP_OKAY) {
        unsigned int i;

        /* Put in zeros up to the new length. */
        for (i = a->used; i < (unsigned int)l; i++) {
            a->dp[i] = 0;
        }
    }

    return err;
}

/* Set the multi-precision number to zero.
 *
 * @param [out] a  SP integer to set to zero.
 */

/* Clear the data from the multi-precision number, set to zero and free.
 *
 * @param [out] a  SP integer.
 */
void sp_clear(sp_int* a)
{
    /* Clear when valid pointer passed in. */
    if (a != NULL) {
        unsigned int i;

        /* Only clear the digits being used. */
        for (i = 0; i < a->used; i++) {
            a->dp[i] = 0;
        }
        /* Set back to zero and free. */
        _sp_zero(a);
        sp_free(a);
    }
}

/* Ensure the data in the multi-precision number is zeroed.
 *
 * Use when security sensitive data needs to be wiped.
 *
 * @param [in] a  SP integer.
 */
void sp_forcezero(sp_int* a)
{
    /* Zeroize when a valid pointer passed in. */
    if (a != NULL) {
        /* Ensure all data zeroized - data not zeroed when used decreases. */
        ForceZero(a->dp, a->size * (word32)SP_WORD_SIZEOF);
        /* Set back to zero. */
        /* Make value zero and free. */
        _sp_zero(a);
        sp_free(a);
    }
}

/* Copy value of multi-precision number a into r.
 *
 * @param [in]  a  SP integer - source.
 * @param [out] r  SP integer - destination.
 */

/* Copy value of multi-precision number a into r.
 *
 * @param [in]  a  SP integer - source.
 * @param [out] r  SP integer - destination.
 *
 * @return  MP_OKAY on success.
 */




/* Conditional swap of SP int values in constant time.
 *
 * @param [in, out] a     First SP int to conditionally swap.
 * @param [in, out] b     Second SP int to conditionally swap.
 * @param [in]      cnt   Count of words to copy.
 * @param [in]      swap  When value is 1 then swap.
 * @param [in, out] t     Temporary SP int to use in swap.
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */

/* Conditional swap of SP int values in constant time.
 *
 * @param [in] a     First SP int to conditionally swap.
 * @param [in] b     Second SP int to conditionally swap.
 * @param [in] cnt   Count of words to copy.
 * @param [in] swap  When value is 1 then swap.
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */


/* Compare absolute value of two multi-precision numbers.
 *
 * @param [in] a  SP integer.
 * @param [in] b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equal to b.
 */
static int _sp_cmp_abs(const sp_int* a, const sp_int* b)
{
    int ret = MP_EQ;

    /* Check number of words first. */
    if (a->used > b->used) {
        ret = MP_GT;
    }
    else if (a->used < b->used) {
        ret = MP_LT;
    }
    else {
        int i;

        /* Starting from most significant word, compare words.
         * Stop when different and set comparison return.
         */
        for (i = (int)a->used - 1; i >= 0; i--) {
            if (a->dp[i] > b->dp[i]) {
                ret = MP_GT;
                break;
            }
            else if (a->dp[i] < b->dp[i]) {
                ret = MP_LT;
                break;
            }
        }
        /* If we made to the end then ret is MP_EQ from initialization. */
    }

    return ret;
}


/* Compare two multi-precision numbers.
 *
 * Assumes a and b are not NULL.
 *
 * @param [in] a  SP integer.
 * @param [in] b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equal to b.
 */
static int _sp_cmp(const sp_int* a, const sp_int* b)
{
    int ret;

        /* Compare values. */
        ret = _sp_cmp_abs(a, b);

    return ret;
}

/* Compare two multi-precision numbers.
 *
 * Pointers are compared such that NULL is less than non-NULL.
 *
 * @param [in] a  SP integer.
 * @param [in] b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equal to b.
 */
int sp_cmp(const sp_int* a, const sp_int* b)
{
    int ret;

    /* Check pointers first. Both NULL returns equal. */
    if (a == b) {
        ret = MP_EQ;
    }
    /* Nothing is smaller than something. */
    else if (a == NULL) {
        ret = MP_LT;
    }
    /* Something is larger than nothing. */
    else if (b == NULL) {
        ret = MP_GT;
    }
    else
    {
        /* Compare values - a and b are not NULL. */
        ret = _sp_cmp(a, b);
    }

    return ret;
}


/*************************
 * Bit check/set functions
 *************************/

/* Check if a bit is set
 *
 * When a is NULL, result is 0.
 *
 * @param [in] a  SP integer.
 * @param [in] b  Bit position to check.
 *
 * @return  0 when bit is not set.
 * @return  1 when bit is set.
 */

/* Count the number of bits in the multi-precision number.
 *
 * When a is NULL, result is 0.
 *
 * @param [in] a  SP integer.
 *
 * @return  Number of bits in the SP integer value.
 */
int sp_count_bits(const sp_int* a)
{
    int n = -1;

    /* Check parameter. */
    if ((a != NULL) && (a->used > 0)) {
        /* Get index of last word. */
        n = (int)(a->used - 1);
        /* Don't count leading zeros. */
        while ((n >= 0) && (a->dp[n] == 0)) {
            n--;
        }
    }

    /* -1 indicates SP integer value was zero. */
    if (n < 0) {
        n = 0;
    }
    else {
        /* Get the most significant word. */
        sp_int_digit d = a->dp[n];
        /* Count of bits up to last word. */
        n *= SP_WORD_SIZE;

        /* Check if top word has more than half the bits set. */
        if (d > SP_HALF_MAX) {
            /* Set count to a full last word. */
            n += SP_WORD_SIZE;
            /* Don't count leading zero bits. */
            while ((d & ((sp_int_digit)1 << (SP_WORD_SIZE - 1))) == 0) {
                n--;
                d <<= 1;
            }
        }
        else {
            /* Add to count until highest set bit is shifted out. */
            while (d != 0) {
                n++;
                d >>= 1;
            }
        }
    }

    return n;
}


/* Determine if the most significant byte of the encoded multi-precision number
 * has the top bit set.
 *
 * When a is NULL, result is 0.
 *
 * @param [in] a  SP integer.
 *
 * @return  1 when the top bit of top byte is set.
 * @return  0 when the top bit of top byte is not set.
 */

/* Set one bit of a: a |= 1 << i
 * The field 'used' is updated in a.
 *
 * @param [in, out] a  SP integer to set bit into.
 * @param [in]      i  Index of bit to set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL, index is negative or index is too large.
 */


/**********************
 * Digit/Long functions
 **********************/

/* Set the multi-precision number to be the value of the digit.
 *
 * @param [out] a  SP integer to become number.
 * @param [in]  d  Digit to be set.
 */
static void _sp_set(sp_int* a, sp_int_digit d)
{
    /* Use sp_int_minimal to support allocated byte arrays as sp_ints. */
    sp_int_minimal* am = (sp_int_minimal*)a;

    am->dp[0] = d;
    /* d == 0 => used = 0, d > 0 => used = 1 */
    am->used = (d > 0);
}

/* Set the multi-precision number to be the value of the digit.
 *
 * @param [out] a  SP integer to become number.
 * @param [in]  d  Digit to be set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_set(sp_int* a, sp_int_digit d)
{
    int err = MP_OKAY;

    /* Validate parameters. */
    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        _sp_set(a, d);
    }

    return err;
}


/* Compare a one digit number with a multi-precision number.
 *
 * When a is NULL, MP_LT is returned.
 *
 * @param [in] a  SP integer to compare.
 * @param [in] d  Digit to compare with.
 *
 * @return  MP_GT when a is greater than d.
 * @return  MP_LT when a is less than d.
 * @return  MP_EQ when a is equal to d.
 */

/* Add a one digit number to the multi-precision number.
 *
 * @param [in]  a  SP integer to be added to.
 * @param [in]  d  Digit to add.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for fixed size dp array.
 */
static int _sp_add_d(const sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;

    /* Special case of zero means we want result to have a digit when not adding
     * zero. */
    if (a->used == 0) {
        r->dp[0] = d;
        r->used = (d > 0);
    }
    else {
        unsigned int i = 0;
        sp_int_digit a0 = a->dp[0];

        /* Set used of result - updated if overflow seen. */
        r->used = a->used;

        r->dp[0] = a0 + d;
        /* Check for carry. */
        if (r->dp[0] < a0) {
            /* Do carry through all words. */
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i] + 1;
                if (r->dp[i] != 0) {
                   break;
                }
            }
            /* Add another word if required. */
            if (i == a->used) {
                /* Check result has enough space for another word. */
                if (i < r->size) {
                    r->used++;
                    r->dp[i] = 1;
                }
                else {
                    err = MP_VAL;
                }
            }
        }
        /* When result is not the same as input, copy rest of digits. */
        if ((err == MP_OKAY) && (r != a)) {
            /* Copy any words that didn't update with carry. */
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i];
            }
        }
    }

    return err;
}

/* Sub a one digit number from the multi-precision number.
 *
 * @param [in]  a  SP integer to be subtracted from.
 * @param [in]  d  Digit to subtract.
 * @param [out] r  SP integer to store result in.
 */

/* Add a one digit number to the multi-precision number.
 *
 * @param [in]  a  SP integer to be added to.
 * @param [in]  d  Digit to add.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for fixed size dp array.
 */

/* Sub a one digit number from the multi-precision number.
 *
 * @param [in]  a  SP integer to be subtracted from.
 * @param [in]  d  Digit to subtract.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */

/* Multiply a by digit d and put result into r shifting up o digits.
 *   r = (a * d) << (o * SP_WORD_SIZE)
 *
 * @param [in]  a  SP integer to be multiplied.
 * @param [in]  d  SP digit to multiply by.
 * @param [out] r  SP integer result.
 * @param [in]  o  Number of digits to move result up by.
 * @return  MP_OKAY on success.
 * @return  MP_VAL when result is too large for sp_int.
 */
static int _sp_mul_d(const sp_int* a, sp_int_digit d, sp_int* r, unsigned int o)
{
    int err = MP_OKAY;
    unsigned int i;
#ifndef SQR_MUL_ASM
    sp_int_word t = 0;
#else
    sp_int_digit l = 0;
    sp_int_digit h = 0;
#endif

    /* Zero out offset words. */
    for (i = 0; i < o; i++) {
        r->dp[i] = 0;
    }

    /* Multiply each word of a by n. */
    for (i = 0; i < a->used; i++, o++) {
    #ifndef SQR_MUL_ASM
        /* Add product to top word of previous result. */
        t += (sp_int_word)a->dp[i] * d;
        /* Store low word. */
        r->dp[o] = (sp_int_digit)t;
        /* Move top word down. */
        t >>= SP_WORD_SIZE;
    #else
        /* Multiply and add into low and high from previous result.
         * No overflow of possible with add. */
        SP_ASM_MUL_ADD_NO(l, h, a->dp[i], d);
        /* Store low word. */
        r->dp[o] = l;
        /* Move high word into low word and set high word to 0. */
        l = h;
        h = 0;
    #endif
    }

    /* Check whether new word to be appended to result. */
#ifndef SQR_MUL_ASM
    if (t > 0)
#else
    if (l > 0)
#endif
    {
        /* Validate space available in result. */
        if (o == r->size) {
            err = MP_VAL;
        }
        else {
            /* Store new top word. */
        #ifndef SQR_MUL_ASM
            r->dp[o++] = (sp_int_digit)t;
        #else
            r->dp[o++] = l;
        #endif
        }
    }
    /* Update number of words in result. */
    r->used = (sp_size_t)o;
    /* In case n is zero. */
    sp_clamp(r);

    return err;
}


/* Predefine complicated rules of when to compile in sp_div_d and sp_mod_d. */
#define WOLFSSL_SP_DIV_D

#ifndef SP_ASM_DIV_WORD
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * @param [in] hi  SP integer digit. High digit of the dividend.
 * @param [in] lo  SP integer digit. Low digit of the dividend.
 * @param [in] d   SP integer digit. Number to divide by.
 * @return  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
    sp_int_digit d)
{
    sp_int_word w;
    sp_int_digit r;

    /* Use built-in divide. */
    w = ((sp_int_word)hi << SP_WORD_SIZE) | lo;
    w /= d;
    r = (sp_int_digit)w;

    return r;
}
#endif /* !SP_ASM_DIV_WORD */


/* Divide by small number: r = a / d and rem = a % d
 *
 * @param [in]  a    SP integer to be divided.
 * @param [in]  d    Digit to divide by.
 * @param [out] r    SP integer that is the quotient. May be NULL.
 * @param [out] rem  SP integer that is the remainder. May be NULL.
 */
static void _sp_div_small(const sp_int* a, sp_int_digit d, sp_int* r,
    sp_int_digit* rem)
{
    int i;
#ifndef SQR_MUL_ASM
    sp_int_word t;
    sp_int_digit tt;
#else
    sp_int_digit l = 0;
    sp_int_digit tt = 0;
#endif
    sp_int_digit tr = 0;
    sp_int_digit m = SP_DIGIT_MAX / d;

    {
        /* Divide starting at most significant word down to least. */
        for (i = (int)a->used - 1; i >= 0; i--) {
        #ifndef SQR_MUL_ASM
            /* Combine remainder from last operation with this word. */
            t = ((sp_int_word)tr << SP_WORD_SIZE) | a->dp[i];
            /* Get top digit after multiplying. */
            tt = (sp_int_digit)((t * m) >> SP_WORD_SIZE);
            /* Subtract trial division. */
            tr = (sp_int_digit)t - (sp_int_digit)(tt * d);
        #else
            /* Multiply digit. */
            SP_ASM_MUL(l, tt, a->dp[i], m);
            /* Add multiplied remainder to top digit. */
            tt += tr * m;
            /* Subtract trial division from digit. */
            tr = a->dp[i] - (tt * d);
        #endif
            /* tr < d * d */
            /* Fix up result. */
            tt += tr / d;
            /* Fix up remainder. */
            tr %= d;
            /* Store result of dividing the digit. */
            if (r != NULL)
            {
                r->dp[i] = tt;
            }
        }

        if (r != NULL)
        {
            /* Set the used amount to maximal amount. */
            r->used = a->used;
            /* Remove leading zeros. */
            sp_clamp(r);
        }
        /* Return remainder if required. */
        if (rem != NULL) {
            *rem = tr;
        }
    }
}

/* Divide a multi-precision number by a digit size number and calculate
 * remainder.
 *   r = a / d; rem = a % d
 *
 * Use trial division algorithm.
 *
 * @param [in]  a    SP integer to be divided.
 * @param [in]  d    Digit to divide by.
 * @param [out] r    SP integer that is the quotient. May be NULL.
 * @param [out] rem  Digit that is the remainder. May be NULL.
 */
static void _sp_div_d(const sp_int* a, sp_int_digit d, sp_int* r,
    sp_int_digit* rem)
{
    int i;
#ifndef SQR_MUL_ASM
    sp_int_word w = 0;
#else
    sp_int_digit l;
    sp_int_digit h = 0;
#endif
    sp_int_digit t;

    /* Divide starting at most significant word down to least. */
    for (i = (int)a->used - 1; i >= 0; i--) {
    #ifndef SQR_MUL_ASM
        /* Combine remainder from last operation with this word and divide. */
        t = sp_div_word((sp_int_digit)w, a->dp[i], d);
        /* Combine remainder from last operation with this word. */
        w = (w << SP_WORD_SIZE) | a->dp[i];
        /* Subtract to get modulo result. */
        w -= (sp_int_word)t * d;
    #else
        /* Get current word. */
        l = a->dp[i];
        /* Combine remainder from last operation with this word and divide. */
        t = sp_div_word(h, l, d);
        /* Subtract to get modulo result. */
        h = l - t * d;
    #endif
        /* Store result of dividing the digit. */
        if (r != NULL) {
            r->dp[i] = t;
        }
    }
    if (r != NULL) {
        /* Set the used amount to maximal amount. */
        r->used = a->used;
        /* Remove leading zeros. */
        sp_clamp(r);
    }

    /* Return remainder if required. */
    if (rem != NULL) {
    #ifndef SQR_MUL_ASM
        *rem = (sp_int_digit)w;
    #else
        *rem = h;
    #endif
    }
}

/* Divide a multi-precision number by a digit size number and calculate
 * remainder.
 *   r = a / d; rem = a % d
 *
 * @param [in]  a    SP integer to be divided.
 * @param [in]  d    Digit to divide by.
 * @param [out] r    SP integer that is the quotient. May be NULL.
 * @param [out] rem  Digit that is the remainder. May be NULL.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or d is 0.
 */


/* Divides a by 2 and stores in r: r = a >> 1
 *
 * @param [in]  a  SP integer to divide.
 * @param [out] r  SP integer to hold result.
 */



/************************
 * Add/Subtract Functions
 ************************/

/* Add offset b to a into r: r = a + (b << (o * SP_WORD_SIZE))
 *
 * @param [in]  a  SP integer to add to.
 * @param [in]  b  SP integer to add.
 * @param [out] r  SP integer to store result in.
 * @param [in]  o  Number of digits to offset b.
 */

/* Sub offset b from a into r: r = a - (b << (o * SP_WORD_SIZE))
 * a must be greater than b.
 *
 * When using offset, r == a is faster.
 *
 * @param [in]  a  SP integer to subtract from.
 * @param [in]  b  SP integer to subtract.
 * @param [out] r  SP integer to store result in.
 * @param [in]  o  Number of digits to offset b.
 */

/* Add b to a into r: r = a + b
 *
 * @param [in]  a  SP integer to add to.
 * @param [in]  b  SP integer to add.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */

/* Subtract b from a into r: r = a - b
 *
 * a must be greater than b unless WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param [in]  a  SP integer to subtract from.
 * @param [in]  b  SP integer to subtract.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */

/****************************
 * Add/Subtract mod functions
 ****************************/



/* Constant time clamping.
 *
 * @param [in, out] a  SP integer to clamp.
 */
static void sp_clamp_ct(sp_int* a)
{
    int i;
    sp_size_t used = a->used;
    volatile sp_size_t mask = (sp_size_t)-1;

    for (i = (int)a->used - 1; i >= 0; i--) {
        sp_size_t zeroMask =
            (sp_size_t)((((sp_int_sword)a->dp[i]) - 1) >> SP_WORD_SIZE);
        mask &= (sp_size_t)zeroMask;
        used = (sp_size_t)(used + mask);
    }
    a->used = used;
}





/********************
 * Shifting functions
 ********************/

/* Left shift the multi-precision number by a number of digits.
 *
 * @param [in, out] a  SP integer to shift.
 * @param [in]      s  Number of digits to shift.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL, s is negative or the result is too big.
 */

/* Left shift the multi-precision number by n bits.
 * Bits may be larger than the word size.
 *
 * Used by sp_mul_2d() and other internal functions.
 *
 * @param [in, out] a  SP integer to shift.
 * @param [in]      n  Number of bits to shift left.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when the result is too big.
 */


/* Shift a right by n bits into r: r = a >> n
 *
 * @param [in]  a  SP integer to shift.
 * @param [in]  n  Number of bits to shift.
 * @param [out] r  SP integer to store result in.
 */


/* Divide a by d and return the quotient in r and the remainder in a.
 *   r = a / d; a = a % d
 *
 * Note: a is constantly having multiplies of d subtracted.
 *
 * @param [in, out] a      SP integer to be divided and remainder on out.
 * @param [in]      d      SP integer to divide by.
 * @param [out]     r      SP integer that is the quotient.
 * @param [out]     trial  SP integer that is product in trial division.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when operation fails - only when compiling small code.
 */
static int _sp_div_impl(sp_int* a, const sp_int* d, sp_int* r, sp_int* trial)
{
    int err = MP_OKAY;
    sp_size_t i;
    int c;
    sp_int_digit t;
    sp_int_digit dt;

    /* Set result size to clear. */
    r->used = (sp_size_t)(a->used - d->used + 1);
    /* Set all potentially used digits to zero. */
    for (i = 0; i < r->used; i++) {
        r->dp[i] = 0;
    }
    /* Get the most significant digit (will have top bit set). */
    dt = d->dp[d->used-1];

    /* Handle when a >= d ^ (2 ^ (SP_WORD_SIZE * x)). */
    _sp_div_same_size(a, d, r);

    /* Keep subtracting multiples of d as long as the digit count of a is
     * greater than equal to d.
     */
    for (i = (sp_size_t)(a->used - 1U); i >= d->used; i--) {
        /* When top digits equal, guestimate maximum multiplier.
         * Worst case, multiplier is actually SP_DIGIT_MAX - 1.
         * That is, for w (word size in bits) > 1, n > 1, let:
         *   a = 2^((n+1)*w-1), d = 2^(n*w-1) + 2^((n-1)*w) - 1, t = 2^w - 2
         * Then,
         *     d * t
         *   = (2^(n*w-1) + 2^((n-1)*w) - 1) * (2^w - 2)
         *   = 2^((n+1)*w-1) - 2^(n*w) + 2^(n*w) - 2^((n-1)*w+1) - 2^w + 2
         *   = 2^((n+1)*w-1) - 2^((n-1)*w+1) - 2^w + 2
         *   = a - 2^((n-1)*w+1) - 2^w + 2
         * d > 2^((n-1)*w+1) + 2^w - 2, when w > 1, n > 1
         */
        if (a->dp[i] == dt) {
            t = SP_DIGIT_MAX;
        }
        else {
            /* Calculate trial quotient by dividing top word of dividend by top
             * digit of divisor.
             * Some implementations segfault when quotient > SP_DIGIT_MAX.
             * Implementations in assembly, using builtins or using
             * digits only (WOLFSSL_SP_DIV_WORD_HALF).
             */
            t = sp_div_word(a->dp[i], a->dp[i-1], dt);
        }
        do {
            /* Calculate trial from trial quotient. */
            err = _sp_mul_d(d, t, trial, i - d->used);
            if (err != MP_OKAY) {
                break;
            }
            /* Check if trial is bigger. */
            c = _sp_cmp_abs(trial, a);
            if (c == MP_GT) {
                /* Decrement trial quotient and try again. */
                t--;
            }
        }
        while (c == MP_GT);

        if (err != MP_OKAY) {
            break;
        }

        /* Subtract the trial and add quotient to result. */
        _sp_sub_off(a, trial, a, 0);
        r->dp[i - d->used] += t;
        /* Handle overflow of digit. */
        if (r->dp[i - d->used] < t) {
            r->dp[i + 1 - d->used]++;
        }
    }
    /* Update used. */
    a->used = (sp_size_t)(i + 1U);
    if (a->used == d->used) {
        /* Finish div now that length of dividend is same as divisor. */
        _sp_div_same_size(a, d, r);
    }

    return err;
}

/* Divide a by d and return the quotient in r and the remainder in rem.
 *   r = a / d; rem = a % d
 *
 * @param [in]  a     SP integer to be divided.
 * @param [in]  d     SP integer to divide by.
 * @param [out] r     SP integer that is the quotient. May be NULL.
 * @param [out] rem   SP integer that is the remainder. May be NULL.
 * @param [in]  used  Number of digits in temporaries to use.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */

/* Divide a by d and return the quotient in r and the remainder in rem.
 *   r = a / d; rem = a % d
 *
 * @param [in]  a    SP integer to be divided.
 * @param [in]  d    SP integer to divide by.
 * @param [out] r    SP integer that is the quotient. May be NULL.
 * @param [out] rem  SP integer that is the remainder. May be NULL.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or d is NULL, r and rem are NULL, or d is 0.
 * @return  MP_MEM when dynamic memory allocation fails.
 */


/* Calculate the remainder of dividing a by m: r = a mod m.
 *
 * @param [in]  a  SP integer to reduce.
 * @param [in]  m  SP integer that is the modulus.
 * @param [out] r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL or m is 0.
 * @return  MP_MEM when dynamic memory allocation fails.
 */


/* START SP_MUL implementations. */
/* This code is generated.
 * To generate:
 *   cd scripts/sp/sp_int
 *   ./gen.sh
 * File sp_mul.c contains code.
 */

#ifdef SQR_MUL_ASM
/* Multiply a by b into r where a and b have same number of digits. r = a * b
 *
 * Optimized code for when number of digits in a and b are the same.
 *
 * @param [in]  a  SP integer to multiply.
 * @param [in]  b  SP integer to multiply by.
 * @param [out] r  SP integer to hold result.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul_nxn(const sp_int* a, const sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    unsigned int i;
    int j;
    unsigned int k;
    sp_int_digit t[SP_INT_DIGITS / 2];

    if (err == MP_OKAY) {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o;
        const sp_int_digit* dp;

        h = 0;
        l = 0;
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        o = 0;
        for (k = 1; k <= (unsigned int)a->used - 1; k++) {
            j = (int)k;
            dp = a->dp;
            for (; j >= 0; dp++, j--) {
                SP_ASM_MUL_ADD(l, h, o, dp[0], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        for (; k <= ((unsigned int)a->used - 1) * 2; k++) {
            i = k - (sp_size_t)(b->used - 1);
            dp = &b->dp[b->used - 1];
            for (; i < a->used; i++, dp--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], dp[0]);
            }
            r->dp[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        r->dp[k] = l;
        XMEMCPY(r->dp, t, a->used * sizeof(sp_int_digit));
        r->used = (sp_size_t)(k + 1);
        sp_clamp(r);
    }

    return err;
}

/* Multiply a by b into r. r = a * b
 *
 * @param [in]  a  SP integer to multiply.
 * @param [in]  b  SP integer to multiply by.
 * @param [out] r  SP integer to hold result.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul(const sp_int* a, const sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    sp_size_t i;
    int j;
    sp_size_t k;
    sp_int_digit t[SP_INT_DIGITS];

    if (err == MP_OKAY) {
        sp_int_digit l;
        sp_int_digit h;
        sp_int_digit o;

        h = 0;
        l = 0;
        SP_ASM_MUL(h, l, a->dp[0], b->dp[0]);
        t[0] = h;
        h = 0;
        o = 0;
        for (k = 1; k <= (sp_size_t)(b->used - 1); k++) {
            i = 0;
            j = (int)k;
            for (; (i < a->used) && (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        for (; k <= (sp_size_t)((a->used - 1) + (b->used - 1)); k++) {
            j = (int)(b->used - 1);
            i = (sp_size_t)(k - (sp_size_t)j);
            for (; (i < a->used) && (j >= 0); i++, j--) {
                SP_ASM_MUL_ADD(l, h, o, a->dp[i], b->dp[j]);
            }
            t[k] = l;
            l = h;
            h = o;
            o = 0;
        }
        t[k] = l;
        r->used = (sp_size_t)(k + 1);
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

    return err;
}
#else
/* Multiply a by b into r. r = a * b
 *
 * @param [in]  a  SP integer to multiply.
 * @param [in]  b  SP integer to multiply by.
 * @param [out] r  SP integer to hold result.
 *
 * @return  MP_OKAY otherwise.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_mul(const sp_int* a, const sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
    sp_size_t i;
    int j;
    sp_size_t k;
    sp_int_digit t[SP_INT_DIGITS];

    if (err == MP_OKAY) {
        sp_int_word w;
        sp_int_word l;
        sp_int_word h;

        w = (sp_int_word)a->dp[0] * b->dp[0];
        t[0] = (sp_int_digit)w;
        l = (sp_int_digit)(w >> SP_WORD_SIZE);
        h = 0;
        for (k = 1; (int)k <= ((int)a->used - 1) + ((int)b->used - 1); k++) {
            i = (sp_size_t)(k - (b->used - 1));
            i &= (sp_size_t)(((unsigned int)i >> (sizeof(i) * 8 - 1)) - 1U);
            j = (int)(k - i);
            for (; (i < a->used) && (j >= 0); i++, j--) {
                w = (sp_int_word)a->dp[i] * b->dp[j];
                l += (sp_int_digit)w;
                h += (sp_int_digit)(w >> SP_WORD_SIZE);
            }
            t[k] = (sp_int_digit)l;
            l >>= SP_WORD_SIZE;
            l += (sp_int_digit)h;
            h >>= SP_WORD_SIZE;
        }
        t[k] = (sp_int_digit)l;
        r->used = (sp_size_t)(k + 1);
        XMEMCPY(r->dp, t, r->used * sizeof(sp_int_digit));
        sp_clamp(r);
    }

    return err;
}
#endif


/* Multiply a by b and store in r: r = a * b
 *
 * @param [in]  a  SP integer to multiply.
 * @param [in]  b  SP integer to multiply.
 * @param [out] r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b or r is NULL; or the result will be too big for
 *          fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
/* END SP_MUL implementations. */



/* Calculates the multiplicative inverse in the field. r*a = x*m + 1
 * Right-shift Algorithm. NOT constant time.
 *
 * Algorithm:
 *   1. u = m, v = a, b = 0, c = 1
 *   2. While v != 1 and u != 0
 *     2.1. If u even
 *       2.1.1. u /= 2
 *       2.1.2. b = (b / 2) mod m
 *     2.2. Else if v even
 *       2.2.1. v /= 2
 *       2.2.2. c = (c / 2) mod m
 *     2.3. Else if u >= v
 *       2.3.1. u -= v
 *       2.3.2. b = (b - c) mod m
 *     2.4. Else (v > u)
 *       2.4.1. v -= u
 *       2.4.2. c = (c - b) mod m
 *  3. NO_INVERSE if u == 0
 *
 * @param [in]      a  SP integer to find inverse of.
 * @param [in]      m  SP integer that is the modulus.
 * @param [in, out] u  SP integer to use in calculation.
 * @param [in, out] v  SP integer to use in calculation.
 * @param [in, out] b  SP integer to use in calculation.
 * @param [in, out] c  SP integer that is the inverse.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when no inverse.
 */
static int _sp_invmod_bin(const sp_int* a, const sp_int* m, sp_int* u,
    sp_int* v, sp_int* b, sp_int* c)
{
    int err = MP_OKAY;

    /* 1. u = m, v = a, b = 0, c = 1 */
    _sp_copy(m, u);
    if (a != v) {
        _sp_copy(a, v);
    }
    _sp_zero(b);
    _sp_set(c, 1);

    /* 2. While v != 1 and u != 0 */
    while (!sp_isone(v) && !sp_iszero(u)) {
        /* 2.1. If u even */
        if ((u->dp[0] & 1) == 0) {
            /* 2.1.1. u /= 2 */
            _sp_div_2(u, u);
            /* 2.1.2. b = (b / 2) mod m */
            if (sp_isodd(b)) {
                _sp_add_off(b, m, b, 0);
            }
            _sp_div_2(b, b);
        }
        /* 2.2. Else if v even */
        else if ((v->dp[0] & 1) == 0) {
            /* 2.2.1. v /= 2 */
            _sp_div_2(v, v);
            /* 2.2.2. c = (c / 2) mod m */
            if (sp_isodd(c)) {
                _sp_add_off(c, m, c, 0);
            }
            _sp_div_2(c, c);
        }
        /* 2.3. Else if u >= v */
        else if (_sp_cmp_abs(u, v) != MP_LT) {
            /* 2.3.1. u -= v */
            _sp_sub_off(u, v, u, 0);
            /* 2.3.2. b = (b - c) mod m */
            if (_sp_cmp_abs(b, c) == MP_LT) {
                _sp_add_off(b, m, b, 0);
            }
            _sp_sub_off(b, c, b, 0);
        }
        /* 2.4. Else (v > u) */
        else {
            /* 2.4.1. v -= u */
            _sp_sub_off(v, u, v, 0);
            /* 2.4.2. c = (c - b) mod m */
            if (_sp_cmp_abs(c, b) == MP_LT) {
                _sp_add_off(c, m, c, 0);
            }
            _sp_sub_off(c, b, c, 0);
        }
    }
    /* 3. NO_INVERSE if u == 0 */
    if (sp_iszero(u)) {
        err = MP_VAL;
    }

    return err;
}


/* Calculates the multiplicative inverse in the field.
 * Right-shift Algorithm or Extended Euclidean Algorithm. NOT constant time.
 *
 * r*a = x*m + 1
 *
 * @param [in]  a  SP integer to find inverse of.
 * @param [in]  m  SP integer that is the modulus.
 * @param [out] r  SP integer to hold result. r cannot be m.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when m is even and a divides m evenly.
 * @return  MP_MEM when dynamic memory allocation fails.
 */

/* Calculates the multiplicative inverse in the field.
 * Right-shift Algorithm or Extended Euclidean Algorithm. NOT constant time.
 *
 * r*a = x*m + 1
 *
 * @param [in]  a  SP integer to find inverse of.
 * @param [in]  m  SP integer that is the modulus.
 * @param [out] r  SP integer to hold result. r cannot be m.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; a or m is zero; a and m are even or
 *          m is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */



/**************************
 * Exponentiation functions
 **************************/






/***************
 * 2^e functions
 ***************/


/* The bottom e bits: r = a & ((1 << e) - 1)
 *
 * @param [in]  a  SP integer to reduce.
 * @param [in]  e  Modulus bits (modulus equals 2^e).
 * @param [out] r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL, e is negative or e is too large for
 *          result.
 */



/* START SP_SQR implementations */
/* This code is generated.
 * To generate:
 *   cd scripts/sp/sp_int
 *   ./gen.sh
 * File sp_sqr.c contains code.
 */



/* Square a and store in r. r = a * a
 *
 * @param [in]  a  SP integer to square.
 * @param [out] r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL, or the result will be too big for fixed
 *          data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
/* END SP_SQR implementations */


/* Square a mod m and store in r: r = (a * a) mod m
 *
 * @param [in]  a  SP integer to square.
 * @param [in]  m  SP integer that is the modulus.
 * @param [out] r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
static int _sp_sqrmod(const sp_int* a, const sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if (sp_iszero(a)) {
        _sp_zero(r);
    }
    else {
        /* Create temporary for multiplication result. */
        DECL_SP_INT(t, a->used * 2);

        ALLOC_SP_INT(t, a->used * 2, err, NULL);
        if (err == MP_OKAY) {
            err = sp_init_size(t, a->used * 2U);
        }

        /* Square and reduce. */
        if (err == MP_OKAY) {
            err = sp_sqr(a, t);
        }
        if (err == MP_OKAY) {
            err = sp_mod(t, m, r);
        }

        /* Dispose of an allocated SP int. */
        FREE_SP_INT(t, NULL);
    }

    return err;
}

/* Square a mod m and store in r: r = (a * a) mod m
 *
 * @param [in]  a  SP integer to square.
 * @param [in]  m  SP integer that is the modulus.
 * @param [out] r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; or m is 0; or a squared is too big
 *          for fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */

/**********************
 * Montgomery functions
 **********************/


/*********************************
 * To and from binary and strings.
 *********************************/

/* Calculate the number of 8-bit values required to represent the
 * multi-precision number.
 *
 * When a is NULL, returns 0.
 *
 * @param [in] a  SP integer.
 *
 * @return  The count of 8-bit values.
 * @return  0 when a is NULL.
 */
int sp_unsigned_bin_size(const sp_int* a)
{
    int cnt = 0;

    if (a != NULL) {
        cnt = (sp_count_bits(a) + 7) >> 3;
    }

    return cnt;
}

/* Convert a number as an array of bytes in big-endian format to a
 * multi-precision number.
 *
 * @param [out] a     SP integer.
 * @param [in]  in    Array of bytes.
 * @param [in]  inSz  Number of data bytes in array.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when the number is too big to fit in an SP integer.
 */
int sp_read_unsigned_bin(sp_int* a, const byte* in, word32 inSz)
{
    int err = MP_OKAY;

    /* Validate parameters. */
    if ((a == NULL) || ((in == NULL) && (inSz > 0))) {
        err = MP_VAL;
    }

    /* Check a has enough space for number. */
    if ((err == MP_OKAY) && (inSz > (word32)a->size * SP_WORD_SIZEOF)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        /* Load full digits at a time from in. */
        int i;
        int j = 0;

        a->used = (sp_size_t)((inSz + SP_WORD_SIZEOF - 1) / SP_WORD_SIZEOF);

        /* Construct digit from required number of bytes. */
        for (i = (int)(inSz-1); i >= SP_WORD_SIZEOF - 1; i -= SP_WORD_SIZEOF) {
            a->dp[j]  = ((sp_int_digit)in[i - 0] <<  0)
                      | ((sp_int_digit)in[i - 1] <<  8)
                      | ((sp_int_digit)in[i - 2] << 16) |
                        ((sp_int_digit)in[i - 3] << 24)
                                                       ;
            j++;
        }

        /* Handle leftovers. */
        if (i >= 0) {
            /* Cast digits to an array of bytes so we can insert directly. */
            byte *d = (byte*)a->dp;

            /* Zero out all bytes in last digit. */
            a->dp[a->used - 1] = 0;
            /* Place remaining bytes directly into digit. */
            switch (i) {
                case 2: d[inSz - 1 - 2] = in[2]; FALL_THROUGH;
                case 1: d[inSz - 1 - 1] = in[1]; FALL_THROUGH;
                case 0: d[inSz - 1 - 0] = in[0];
            }
        }
        sp_clamp_ct(a);
    }

    return err;
}

/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 *
 * @param [in]  a    SP integer.
 * @param [out] out  Array to put encoding into.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */

/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 * Front-pads the output array with zeros to make number the size of the array.
 *
 * @param [in]  a      SP integer.
 * @param [out] out    Array to put encoding into.
 * @param [in]  outSz  Size of the array in bytes.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */

/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * Constant-time implementation.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 * Front-pads the output array with zeros to make number the size of the array.
 *
 * @param [in]  a      SP integer.
 * @param [out] out    Array to put encoding into.
 * @param [in]  outSz  Size of the array in bytes.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */


/* Convert hexadecimal number as string in big-endian format to a
 * multi-precision number.
 *
 * Assumes negative sign and leading zeros have been stripped.
 *
 * @param [out] a   SP integer.
 * @param [in]  in  NUL terminated string.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a character is not valid or not enough space in a.
 */
static int _sp_read_radix_16(sp_int* a, const char* in)
{
    int err = MP_OKAY;
    int i;
    unsigned int s = 0;
    sp_size_t j = 0;
    sp_int_digit d;
    /* Skip whitespace at end of line */
    int eol_done = 0;

    /* Make all nibbles in digit 0. */
    d = 0;
    /* Step through string a character at a time starting at end - least
     * significant byte. */
    for (i = (int)(XSTRLEN(in) - 1); i >= 0; i--) {
        volatile char c = in[i];
        /* Convert character from hex. */
        int ch = (int)HexCharToByte(c);
        /* Check for invalid character. */
        if (ch < 0) {
            if (!eol_done && CharIsWhiteSpace(c))
                continue;
            err = MP_VAL;
            break;
        }
        eol_done = 1;

        /* Check whether we have filled the digit. */
        if (s == SP_WORD_SIZE) {
            /* Store digit and move index to next in a. */
            a->dp[j++] = d;
            /* Fail if we are out of space in a. */
            if (j >= a->size) {
                err = MP_VAL;
                break;
            }
            /* Set shift back to 0 - lowest nibble. */
            s = 0;
            /* Make all nibbles in digit 0. */
            d = 0;
        }

        /* Put next nibble into digit. */
        d |= ((sp_int_digit)ch) << s;
        /* Update shift for next nibble. */
        s += 4;
    }

    if (err == MP_OKAY) {
        /* If space, store last digit. */
        if (j < a->size) {
            a->dp[j] = d;
        }
        /* Update used count. */
        a->used = (sp_size_t)(j + 1U);
        /* Remove leading zeros. */
        sp_clamp(a);
    }

    return err;
}


/* Convert a number as string in big-endian format to a big number.
 * Only supports base-16 (hexadecimal) and base-10 (decimal).
 *
 * Negative values supported when WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param [out] a      SP integer.
 * @param [in]  in     NUL terminated string.
 * @param [in]  radix  Number of values in a digit.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or in is NULL, radix is not supported, value is
 *          negative, or a character is not valid.
 */
int sp_read_radix(sp_int* a, const char* in, int radix)
{
    int err = MP_OKAY;

    if ((a == NULL) || (in == NULL)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        if (*in == '-') {
            err = MP_VAL;
        }
        else
        {
            /* Skip leading zeros. */
            while (*in == '0') {
                in++;
            }

            if (radix == 16) {
                err = _sp_read_radix_16(a, in);
            }
            else {
                err = MP_VAL;
            }

        }
    }

    return err;
}

/* Put the big-endian, hex string encoding of a into str.
 *
 * Assumes str is large enough for result.
 * Use sp_radix_size() to calculate required length.
 *
 * @param [in]  a    SP integer to convert.
 * @param [out] str  String to hold hex string result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL.
 */

/* Put the big-endian, decimal string encoding of a into str.
 *
 * Assumes str is large enough for result.
 * Use sp_radix_size() to calculate required length.
 *
 * @param [in]  a    SP integer to convert.
 * @param [out] str  String to hold decimal string result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL.
 * @return  MP_MEM when dynamic memory allocation fails.
 */

/* Put the string version, big-endian, of a in str using the given radix.
 *
 * @param [in]  a      SP integer to convert.
 * @param [out] str    String to hold radix based string result.
 * @param [in]  radix  Base of character.
 *                     Valid values: MP_RADIX_HEX, MP_RADIX_DEC.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL, or radix is not supported.
 */

/* Calculate the length of the string version, big-endian, of a using the given
 * radix.
 *
 * @param [in]  a      SP integer to convert.
 * @param [in]  radix  Base of character.
 *                     Valid values: MP_RADIX_HEX, MP_RADIX_DEC.
 * @param [out] size   The number of characters in encoding.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or size is NULL, or radix is not supported.
 */

/***************************************
 * Prime number generation and checking.
 ***************************************/





/* Returns the run time settings.
 *
 * @return  Settings value.
 */

/* Returns the fast math settings.
 *
 * @return  Setting - number of bits in a digit.
 */



