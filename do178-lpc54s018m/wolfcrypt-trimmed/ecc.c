/* ecc.c
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


/*
Possible ECC enable options:
 * HAVE_ECC:            Overall control of ECC                  default: on
 * HAVE_ECC_ENCRYPT:    ECC encrypt/decrypt w/AES and HKDF      default: off
 * HAVE_ECC_SIGN:       ECC sign                                default: on
 * HAVE_ECC_VERIFY:     ECC verify                              default: on
 * HAVE_ECC_DHE:        ECC build shared secret                 default: on
 * HAVE_ECC_CDH:        ECC cofactor DH shared secret           default: off
 * HAVE_ECC_KEY_IMPORT: ECC Key import                          default: on
 * HAVE_ECC_KEY_EXPORT: ECC Key export                          default: on
 * ECC_SHAMIR:          Enables Shamir calc method              default: on
 * HAVE_COMP_KEY:       Enables compressed key                  default: off
 * WOLFSSL_VALIDATE_ECC_IMPORT: Validate ECC key on import      default: off
 * WOLFSSL_VALIDATE_ECC_KEYGEN: Validate ECC key gen            default: off
 * WOLFSSL_CUSTOM_CURVES: Allow non-standard curves.            default: off
 *                        Includes the curve "a" variable in calculation
 * ECC_DUMP_OID:        Enables dump of OID encoding and sum    default: off
 * ECC_CACHE_CURVE:     Enables cache of curve info to improve performance
 *                                                              default: off
 * FP_ECC:              ECC Fixed Point Cache                   default: off
 *                      FP cache is not supported for SECP160R1, SECP160R2,
 *                      SECP160K1 and SECP224K1. These do not work with scalars
 *                      that are the length of the order when the order is
 *                      longer than the prime. Use wc_ecc_fp_free to free cache.
 * WOLFSSL_ECC_CURVE_STATIC:                                    default off (on for windows)
 *                      For the ECC curve parameters `ecc_set_type` use fixed
 *                      array for hex string
 * WC_ECC_NONBLOCK:     Enable non-blocking support for sign/verify/keygen/secret.
 *                      Requires SP with WOLFSSL_SP_NONBLOCK
 * WC_ECC_NONBLOCK_ONLY Enable the non-blocking function only, no fall-back to
 *                      normal blocking API's
 * WOLFSSL_ECDSA_SET_K: Enables the setting of the 'k' value to use during ECDSA
 *                      signing. If the value is invalid, a new random 'k' is
 *                      generated in the loop. (For testing)
 *                                                              default: off
 * WOLFSSL_ECDSA_SET_K_ONE_LOOP:
 *                      Enables the setting of the 'k' value to use during ECDSA
 *                      signing. If the value is invalid then an error is
 *                      returned rather than generating a new 'k'. (For testing)
 *                                                              default: off
 * WOLFSSL_ECDSA_DETERMINISTIC_K: Enables RFC6979 implementation of
 *                      deterministic ECC signatures. The following function
 *                      can be used to set the deterministic signing flag in the
 *                      ecc key structure.
 *                      int wc_ecc_set_deterministic(ecc_key* key, byte flag)
 *                                                              default: off
 *
 * WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT: RFC6979 lists a variant that uses the
 *                      hash directly instead of doing bits2octets(H(m)), when
 *                      the variant macro is used the bits2octets operation on
 *                      the hash is removed.
 *                                                              default: off
 *
 * WC_PROTECT_ENCRYPTED_MEM:
 *                      Enables implementations that protect data that is in
 *                      encrypted memory.
 *                                                              default: off
 * WOLFSSL_ECC_GEN_REJECT_SAMPLING
 *                      Enables generation of scalar (private key and ECDSA
 *                      nonce) to be performed using reject sampling algorithm.
 *                      Use this when CPU state can be closely observed by
 *                      attacker.
 *                                                              default: off
 * WOLFSSL_ECC_BLIND_K
 *                      Blind the private key k by using a random mask.
 *                      The private key is never stored unprotected but an
 *                      unmasked copy is computed and stored each time it is
 *                      needed.
 *                                                              default: off
 * WOLFSSL_CHECK_VER_FAULTS
 *                      Sanity check on verification steps in case of faults.
 *                                                              default: off
 * ECC_TIMING_RESISTANT: Enables constant-time ECC operations   default: on
 *                      to prevent timing side-channel attacks.
 *                      Auto-enabled for FIPS and some embedded builds.
 * WC_NO_CACHE_RESISTANT: Disables cache-resistant operations   default: off
 *                      (conditional swaps) in ECC scalar multiply to
 *                      reduce overhead. Not recommended for secure use.
 * ALT_ECC_SIZE:        Uses alternate smaller fixed-size arrays default: off
 *                      for ECC points instead of full mp_int arrays,
 *                      reducing memory. Requires USE_FAST_MATH.
 * WOLFSSL_ECC_NO_SMALL_STACK: Disables WOLFSSL_SMALL_STACK     default: off
 *                      optimizations for ECC, using stack instead of heap.
 * HAVE_ECC_CHECK_PUBKEY_ORDER: Validates ECC public key order  default: on
 *                      during import. Auto-enabled unless
 *                      NO_ECC_CHECK_PUBKEY_ORDER is defined.
 * NO_ECC_CHECK_PUBKEY_ORDER: Disables public key order check   default: off
 *                      during ECC key import. Not recommended.
 * HAVE_ECC_MAKE_PUB:   Enables computing public key from       default: on
 *                      private key via wc_ecc_make_pub.
 * HAVE_ECC_VERIFY_HELPER: Enables ECC verify helper functions  default: on
 *                      Auto-enabled unless using hardware accelerators.
 * WOLFSSL_PUBLIC_ECC_ADD_DBL: Makes ecc_projective_add_point   default: off
 *                      and ecc_projective_dbl_point public APIs.
 * SQRTMOD_USE_MOD_EXP: Computes square root mod prime using    default: off
 *                      modular exponentiation instead of Jacobi method
 *                      for compressed key decompression.
 *
 * ECIES options:
 * WOLFSSL_ECIES_OLD:   Uses original wolfSSL ECIES format      default: off
 *                      (public key not in shared secret material).
 * WOLFSSL_ECIES_ISO18033: Uses ISO 18033 ECIES standard        default: off
 *                      (includes public key in shared secret).
 * WOLFSSL_ECIES_GEN_IV: Generates random IV for ECIES          default: off
 *                      encryption instead of deriving from KDF.
 *
 * Fixed Point Cache options (requires FP_ECC):
 * FP_ENTRIES:          Number of FP cache entries               default: 15
 * FP_LUT:              FP lookup table bit size (2-12). Larger  default: 8
 *                      values use more memory but faster verify.
 * FP_ECC_CONTROL:      Auto-selects cached FP ECC verify with  default: on
 *                      SP when WOLFSSL_HAVE_SP_ECC is available.
 *
 * SP Math ECC options:
 * WOLFSSL_HAVE_SP_ECC: Enables SP math optimizations for ECC   default: on
 *                      Provides significant performance improvement.
 * WOLFSSL_SP_NO_256:   Disables SP P-256 support               default: off
 * WOLFSSL_SP_384:      Enables SP P-384 support                default: off
 * WOLFSSL_SP_521:      Enables SP P-521 support                default: off
 * WOLFSSL_SP_1024:     Enables SP 1024-bit support for SAKKE   default: off
 * WOLFSSL_SP_SM2:      Enables SP SM2 curve support            default: off
 *                      Auto-enabled with WOLFSSL_SM2.
 *
 * Hardware/Offload options:
 * WOLFSSL_KCAPI_ECC:   Offload ECC to Linux Kernel Crypto API  default: off
 * WC_ASYNC_ENABLE_ECC: Enables async ECC with crypto callbacks default: off
 *                      Requires WOLFSSL_ASYNC_CRYPT.
 * WC_ASYNC_ENABLE_ECC_KEYGEN: Enables async ECC key gen        default: off
 * PLUTON_CRYPTO_ECC:   Uses ARM Pluton TEE for ECC operations  default: off
 * WOLFSSL_CAAM_BLACK_KEY_SM: Uses NXP CAAM secure memory for   default: off
 *                      encrypted black key storage.
 */

/*
ECC Curve Types:
 * NO_ECC_SECP          Disables SECP curves                    default: off (not defined)
 * HAVE_ECC_SECPR2      Enables SECP R2 curves                  default: off
 * HAVE_ECC_SECPR3      Enables SECP R3 curves                  default: off
 * HAVE_ECC_BRAINPOOL   Enables Brainpool curves                default: off
 * HAVE_ECC_KOBLITZ     Enables Koblitz curves                  default: off
 * WOLFSSL_SM2          Enables SM2 curves                      default: off
 */

/*
ECC Curve Sizes:
 * ECC_USER_CURVES: Allows custom combination of key sizes below
 * HAVE_ALL_CURVES: Enable all key sizes (on unless ECC_USER_CURVES is defined)
 * ECC_MIN_KEY_SZ: Minimum supported ECC key size
 * HAVE_ECC112: 112 bit key
 * HAVE_ECC128: 128 bit key
 * HAVE_ECC160: 160 bit key
 * HAVE_ECC192: 192 bit key
 * HAVE_ECC224: 224 bit key
 * HAVE_ECC239: 239 bit key
 * NO_ECC256: Disables 256 bit key (on by default)
 * HAVE_ECC320: 320 bit key
 * HAVE_ECC384: 384 bit key
 * HAVE_ECC512: 512 bit key
 * HAVE_ECC521: 521 bit key
 */



/* Make sure custom curves is enabled for Brainpool or Koblitz curve types */


/* public ASN interface */
#include <wolfssl/wolfcrypt/asn_public.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <wolfssl/wolfcrypt/sp.h>



    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_ecc_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000005 };
    int wolfCrypt_FIPS_ECC_sanity(void)
    {
        return 0;
    }
#endif










    #undef  HAVE_ECC_VERIFY_HELPER
    #define HAVE_ECC_VERIFY_HELPER

    #undef  HAVE_ECC_MAKE_PUB
    #define HAVE_ECC_MAKE_PUB


/* macro guard for ecc_check_pubkey_order functionality */

    /* CAAM builds use public key validation as a means to check if an
     * imported private key is an encrypted black key or not */
    #undef  HAVE_ECC_CHECK_PUBKEY_ORDER
    #define HAVE_ECC_CHECK_PUBKEY_ORDER

#define MAX_ECC_BITS_USE    MAX_ECC_BITS_NEEDED


#define ECC_KEY_MAX_BITS(key)                                        ((((key) == NULL) || ((key)->dp == NULL)) ? MAX_ECC_BITS_USE :   ((unsigned)((key)->dp->size * 8)))
#define ECC_KEY_MAX_BITS_NONULLCHECK(key)                            (((key)->dp == NULL) ? MAX_ECC_BITS_USE :                        ((unsigned)((key)->dp->size * 8)))



/* forward declarations */
static int  wc_ecc_new_point_ex(ecc_point** point, void* heap);
static void wc_ecc_del_point_ex(ecc_point* p, void* heap);

/* internal ECC states */
enum {
    ECC_STATE_NONE = 0,

    ECC_STATE_SHARED_SEC_GEN,
    ECC_STATE_SHARED_SEC_RES,

    ECC_STATE_SIGN_DO,
    ECC_STATE_SIGN_ENCODE,

    ECC_STATE_VERIFY_DECODE,
    ECC_STATE_VERIFY_DO,
    ECC_STATE_VERIFY_RES
};


/* map
   ptmul -> mulmod
*/

/* 256-bit curve on by default whether user curves or not */
    #define ECC384

/* The encoded OID's for ECC curves */
            #define CODED_SECP384R1    {0x2B,0x81,0x04,0x00,0x22}
            #define CODED_SECP384R1_SZ 5
            static const ecc_oid_t ecc_oid_secp384r1[] = CODED_SECP384R1;
            #define CODED_SECP384R1_OID ecc_oid_secp384r1
        #define ecc_oid_secp384r1_sz CODED_SECP384R1_SZ


/* This holds the key settings.
   ***MUST*** be organized by size from smallest to largest. */

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(6,0,0)
    #undef ecc_sets
    #undef ecc_sets_count
#endif

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(6,0,0)
static
#endif
const ecc_set_type ecc_sets[] = {
    {
        48,                                                                                                 /* size/bytes */
        ECC_SECP384R1,                                                                                      /* ID         */
        "SECP384R1",                                                                                        /* curve name */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", /* prime      */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", /* A          */
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", /* B          */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", /* order      */
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", /* Gx         */
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", /* Gy         */
        ecc_oid_secp384r1, ecc_oid_secp384r1_sz,                                                            /* oid/oidSz  */
        ECC_SECP384R1_OID,                                                                                  /* oid sum    */
        1,                                                                                                  /* cofactor   */
    },
    {
        0,
        ECC_CURVE_INVALID,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        0, 0, 0
    }
};
#define ECC_SET_COUNT   (sizeof(ecc_sets)/sizeof(ecc_set_type))
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(6,0,0)
static
#endif
const size_t ecc_sets_count = ECC_SET_COUNT - 1;



/* Forward declarations */
static int _ecc_validate_public_key(ecc_key* key, int partial, int priv);
#if (FIPS_VERSION_GE(5,0) || defined(WOLFSSL_VALIDATE_ECC_KEYGEN)) &&  !defined(WOLFSSL_KCAPI_ECC)
static int _ecc_pairwise_consistency_test(ecc_key* key, WC_RNG* rng);
#endif




/* Curve Specs */
typedef struct ecc_curve_spec {
    const ecc_set_type* dp;

    mp_int* prime;
    mp_int* Af;
    mp_int* Bf;
    mp_int* order;
    mp_int* Gx;
    mp_int* Gy;

    mp_int* spec_ints;
    word32 spec_count;
    word32 spec_use;

    byte load_mask;
} ecc_curve_spec;

    #define ECC_CURVE_FIELD_NONE    0x00
    #define ECC_CURVE_FIELD_PRIME   0x01
    #define ECC_CURVE_FIELD_AF      0x02
    #define ECC_CURVE_FIELD_BF      0x04
    #define ECC_CURVE_FIELD_ORDER   0x08
    #define ECC_CURVE_FIELD_GX      0x10
    #define ECC_CURVE_FIELD_GY      0x20
    #define ECC_CURVE_FIELD_ALL     0x3F
    #define ECC_CURVE_FIELD_COUNT   6


    #define DECLARE_CURVE_SPECS(intcount)                                mp_int spec_ints[(intcount)];                                    ecc_curve_spec curve_lcl;                                        ecc_curve_spec* curve = &curve_lcl;                              XMEMSET(curve, 0, sizeof(ecc_curve_spec));                       curve->spec_ints = spec_ints;                                    curve->spec_count = (intcount)
    #define ALLOC_CURVE_SPECS(intcount, err) (err) = MP_OKAY
    #define FREE_CURVE_SPECS() WC_DO_NOTHING

static void wc_ecc_curve_cache_free_spec_item(ecc_curve_spec* curve, mp_int* item,
    byte mask)
{
    if (item) {
        mp_clear(item);
    }
    curve->load_mask = (byte)(curve->load_mask & ~mask);
}
static void wc_ecc_curve_cache_free_spec(ecc_curve_spec* curve)
{
    if (curve == NULL) {
        return;
    }

    if (curve->load_mask & ECC_CURVE_FIELD_PRIME)
        wc_ecc_curve_cache_free_spec_item(curve, curve->prime, ECC_CURVE_FIELD_PRIME);
    if (curve->load_mask & ECC_CURVE_FIELD_AF)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Af, ECC_CURVE_FIELD_AF);
    if (curve->load_mask & ECC_CURVE_FIELD_BF)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Bf, ECC_CURVE_FIELD_BF);
    if (curve->load_mask & ECC_CURVE_FIELD_ORDER)
        wc_ecc_curve_cache_free_spec_item(curve, curve->order, ECC_CURVE_FIELD_ORDER);
    if (curve->load_mask & ECC_CURVE_FIELD_GX)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Gx, ECC_CURVE_FIELD_GX);
    if (curve->load_mask & ECC_CURVE_FIELD_GY)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Gy, ECC_CURVE_FIELD_GY);

    curve->load_mask = 0;
}

static void wc_ecc_curve_free(ecc_curve_spec* curve)
{
    if (curve) {
        wc_ecc_curve_cache_free_spec(curve);
    }
}

static int wc_ecc_curve_cache_load_item(ecc_curve_spec* curve, const char* src,
    mp_int** dst, byte mask)
{
    int err;

    /* get mp_int from temp */
    if (curve->spec_use >= curve->spec_count) {
        WOLFSSL_MSG("Invalid DECLARE_CURVE_SPECS count");
        return ECC_BAD_ARG_E;
    }
    *dst = &curve->spec_ints[curve->spec_use++];

    err = mp_init(*dst);
    if (err == MP_OKAY) {
        curve->load_mask |= mask;

        err = mp_read_radix(*dst, src, MP_RADIX_HEX);

    }
    return err;
}

static int wc_ecc_curve_load(const ecc_set_type* dp, ecc_curve_spec** pCurve,
    byte load_mask)
{
    int ret = 0;
    ecc_curve_spec* curve;
    byte load_items = 0; /* mask of items to load */

    if (dp == NULL || pCurve == NULL)
        return BAD_FUNC_ARG;

    curve = *pCurve;

    /* make sure the curve is initialized */
    if (curve->dp != dp) {
        curve->load_mask = 0;

    }
    curve->dp = dp; /* set dp info */

    /* determine items to load */
    load_items = (byte)(((byte)~(word32)curve->load_mask) & load_mask);
    curve->load_mask |= load_items;

    /* load items */
    if (load_items & ECC_CURVE_FIELD_PRIME)
        ret += wc_ecc_curve_cache_load_item(curve, dp->prime, &curve->prime,
            ECC_CURVE_FIELD_PRIME);
    if (load_items & ECC_CURVE_FIELD_AF)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Af, &curve->Af,
            ECC_CURVE_FIELD_AF);
    if (load_items & ECC_CURVE_FIELD_BF)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Bf, &curve->Bf,
            ECC_CURVE_FIELD_BF);
    if (load_items & ECC_CURVE_FIELD_ORDER)
        ret += wc_ecc_curve_cache_load_item(curve, dp->order, &curve->order,
            ECC_CURVE_FIELD_ORDER);
    if (load_items & ECC_CURVE_FIELD_GX)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Gx, &curve->Gx,
            ECC_CURVE_FIELD_GX);
    if (load_items & ECC_CURVE_FIELD_GY)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Gy, &curve->Gy,
            ECC_CURVE_FIELD_GY);

    /* check for error */
    if (ret != 0) {
        wc_ecc_curve_free(curve);
        ret = MP_READ_E;
    }


    return ret;
}



/* Retrieve the curve name for the ECC curve id.
 *
 * curve_id  The id of the curve.
 * returns the name stored from the curve if available, otherwise NULL.
 */

int wc_ecc_set_curve(ecc_key* key, int keysize, int curve_id)
{
    if (key == NULL || (keysize <= 0 && curve_id < 0)) {
        return BAD_FUNC_ARG;
    }

    if (keysize > ECC_MAXSIZE) {
        return ECC_BAD_ARG_E;
    }

    /* handle custom case */
    if (key->idx != ECC_CUSTOM_IDX) {
        int x;

        /* default values */
        key->idx = 0;
        key->dp = NULL;

        /* find ecc_set based on curve_id or key size */
        for (x = 0; ecc_sets[x].size != 0; x++) {
            if (curve_id > ECC_CURVE_DEF) {
                if (curve_id == ecc_sets[x].id)
                  break;
            }
            else if (keysize <= ecc_sets[x].size) {
                break;
            }
        }
        if (ecc_sets[x].size == 0) {
            WOLFSSL_MSG("ECC Curve not found");
            return ECC_CURVE_OID_E;
        }

        key->idx = x;
        key->dp  = &ecc_sets[x];
    }

    return 0;
}







/**
   Perform a point multiplication
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/


/**
   Perform a point multiplication
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/


/** ECC Fixed Point mulmod global
    k        The multiplicand
    G        Base point to multiply
    R        [out] Destination of product
    a        ECC curve parameter a
    modulus  The modulus for the curve
    map      [boolean] If non-zero maps the point back to affine coordinates,
             otherwise it's left in jacobian-montgomery form
    return MP_OKAY if successful
*/


/**
 * Allocate a new ECC point (if one not provided)
 * use a heap hint when creating new ecc_point
 * @return 0 on success
 * @return BAD_FUNC_ARG for invalid arguments
 * @return MEMORY_E on failure to allocate memory
*/
static int wc_ecc_new_point_ex(ecc_point** point, void* heap)
{
   int err = MP_OKAY;
   ecc_point* p;

   if (point == NULL) {
       return BAD_FUNC_ARG;
   }

   p = *point;
   if (p == NULL) {
      p = (ecc_point*)XMALLOC(sizeof(ecc_point), heap, DYNAMIC_TYPE_ECC);
   }
   if (p == NULL) {
      return MEMORY_E;
   }
   XMEMSET(p, 0, sizeof(ecc_point));

   if (*point == NULL)
       p->isAllocated = 1;

   err = mp_init_multi(p->x, p->y, p->z, NULL, NULL, NULL);
   if (err != MP_OKAY) {
      WOLFSSL_MSG("mp_init_multi failed.");
      if (p->isAllocated)
          XFREE(p, heap, DYNAMIC_TYPE_ECC);
      p = NULL;
   }

   *point = p;
   (void)heap;
   return err;
} /* wc_ecc_new_point_ex */



/** Free an ECC point from memory
  p   The point to free
*/
static void wc_ecc_del_point_ex(ecc_point* p, void* heap)
{
   if (p != NULL) {
      mp_clear(p->x);
      mp_clear(p->y);
      mp_clear(p->z);
      if (p->isAllocated)
          XFREE(p, heap, DYNAMIC_TYPE_ECC);
   }
   (void)heap;
}



/** Copy the value of a point to an other one
  p    The point to copy
  r    The created point
*/

/** Compare the value of a point with an other one
 a    The point to compare
 b    The other point to compare

 return MP_EQ if equal, MP_LT/MP_GT if not, < 0 in case of error
 */


/** Returns whether an ECC idx is valid or not
  n      The idx number to check
  return 1 if valid, 0 if not
*/
int wc_ecc_is_valid_idx(int n)
{
   int x;

   if (n >= (int)ECC_SET_COUNT)
       return 0;

   for (x = 0; ecc_sets[x].size != 0; x++)
       ;
   /* -1 is a valid index --- indicating that the domain params
      were supplied by the user */
   if ((n >= ECC_CUSTOM_IDX) && (n < x)) {
      return 1;
   }

   return 0;
}



/* Returns the curve size that corresponds to a given ecc_curve_id identifier
 *
 * id      curve id, from ecc_curve_id enum in ecc.h
 * return  curve size, from ecc_sets[] on success, negative on error
 */

/* Returns the curve index that corresponds to a given curve name in
 * ecc_sets[] of ecc.c
 *
 * name    curve name, from ecc_sets[].name in ecc.c
 * return  curve index in ecc_sets[] on success, negative on error
 */

/* Returns the curve size that corresponds to a given curve name,
 * as listed in ecc_sets[] of ecc.c.
 *
 * name    curve name, from ecc_sets[].name in ecc.c
 * return  curve size, from ecc_sets[] on success, negative on error
 */

/* Returns the curve id that corresponds to a given curve name,
 * as listed in ecc_sets[] of ecc.c.
 *
 * name   curve name, from ecc_sets[].name in ecc.c
 * return curve id, from ecc_sets[] on success, negative on error
 */

/* Compares a curve parameter (hex, from ecc_sets[]) to given input
 * parameter for equality.
 * encType is WC_TYPE_UNSIGNED_BIN or WC_TYPE_HEX_STR
 * Returns MP_EQ on success, negative on error */

/* Returns the curve id in ecc_sets[] that corresponds to a given set of
 * curve parameters.
 *
 * fieldSize  the field size in bits
 * prime      prime of the finite field
 * primeSz    size of prime in octets
 * Af         first coefficient a of the curve
 * AfSz       size of Af in octets
 * Bf         second coefficient b of the curve
 * BfSz       size of Bf in octets
 * order      curve order
 * orderSz    size of curve in octets
 * Gx         affine x coordinate of base point
 * GxSz       size of Gx in octets
 * Gy         affine y coordinate of base point
 * GySz       size of Gy in octets
 * cofactor   curve cofactor
 *
 * return curve id, from ecc_sets[] on success, negative on error
 */

/* Returns the curve id in ecc_sets[] that corresponds
 * to a given domain parameters pointer.
 *
 * dp   domain parameters pointer
 *
 * return curve id, from ecc_sets[] on success, negative on error
 */

/* Returns the curve id that corresponds to a given OID,
 * as listed in ecc_sets[] of ecc.c.
 *
 * oid   OID, from ecc_sets[].name in ecc.c
 * len   OID len, from ecc_sets[].name in ecc.c
 * return curve id, from ecc_sets[] on success, negative on error
 */

/* Get curve parameters using curve index */





/* Checks if a point p lies on the curve with index curve_idx */

/* return 1 if point is at infinity, 0 if not, < 0 on error */

/* generate random and ensure its greater than 0 and less than order */

static WC_INLINE void wc_ecc_reset(ecc_key* key)
{
    /* make sure required key variables are reset */
    key->state = ECC_STATE_NONE;
}


/* create the public ECC key from a private key
 *
 * key     an initialized private key to generate public part from
 * curve   [in]curve for key, cannot be NULL
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 * Note this function is local to the file because of the argument type
 *      ecc_curve_spec. Having this argument allows for not having to load the
 *      curve type multiple times when generating a key with wc_ecc_make_key().
 * For async the results are placed directly into pubOut, so this function
 *      does not need to be called again
 *
 * returns MP_OKAY on success
 */
static int ecc_make_pub_ex(ecc_key* key, ecc_curve_spec* curve,
        ecc_point* pubOut, WC_RNG* rng)
{
    int err = MP_OKAY;
#ifdef HAVE_ECC_MAKE_PUB
    ecc_point* pub;
#endif /* HAVE_ECC_MAKE_PUB */

    (void)rng;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    SAVE_VECTOR_REGISTERS(return _svr_ret;);

#ifdef HAVE_ECC_MAKE_PUB
    /* if ecc_point passed in then use it as output for public key point */
    if (pubOut != NULL) {
        pub = pubOut;
    }
    else {
        /* caching public key making it a ECC_PRIVATEKEY instead of
           ECC_PRIVATEKEY_ONLY */
        pub = &key->pubkey;
        key->type = ECC_PRIVATEKEY_ONLY;
    }

    if ((err == MP_OKAY) && (mp_iszero(ecc_get_k(key)) ||
            mp_isneg(ecc_get_k(key)) ||
            (mp_cmp(ecc_get_k(key), curve->order) != MP_LT))) {
        err = ECC_PRIV_KEY_E;
    }

    if (err == MP_OKAY) {
        err = mp_init_multi(pub->x, pub->y, pub->z, NULL, NULL, NULL);
    }

    { /* BEGIN: Software Crypto */
    /* Single-Precision Math (optimized for specific curves) */
    if (err != MP_OKAY) {
    }
    else
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        err = sp_ecc_mulmod_base_384(ecc_get_k(key), pub, 1, key->heap);
    }
    else

        err = WC_KEY_SIZE_E;
    } /* END: Software Crypto */

    if (err != MP_OKAY
    ) {
        /* clean up if failed */
        mp_clear(pub->x);
        mp_clear(pub->y);
        mp_clear(pub->z);
    }

#else
    /* Using hardware crypto, that does not support ecc_make_pub_ex */
    (void)curve;
    err = NOT_COMPILED_IN;
#endif /* HAVE_ECC_MAKE_PUB */

    /* change key state if public part is cached */
    if (key->type == ECC_PRIVATEKEY_ONLY && pubOut == NULL) {
        key->type = ECC_PRIVATEKEY;
    }

    RESTORE_VECTOR_REGISTERS();

    return err;
}


/* create the public ECC key from a private key
 *
 * key     an initialized private key to generate public part from
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 *
 * returns MP_OKAY on success
 */

/* create the public ECC key from a private key - mask timing use random z
 *
 * key     an initialized private key to generate public part from
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 *
 * returns MP_OKAY on success
 */













/**
 Make a new ECC key
 rng          An active RNG state
 keysize      The keysize for the new key (in octets from 20 to 65 bytes)
 key          [out] Destination of the newly created key
 return       MP_OKAY if successful,
 upon error all allocated memory will be freed
 */

/* Setup dynamic pointers if using normal math for proper freeing */
WOLFSSL_ABI
int wc_ecc_init_ex(ecc_key* key, void* heap, int devId)
{
    int ret      = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }


    XMEMSET(key, 0, sizeof(ecc_key));
    key->state = ECC_STATE_NONE;

    (void)devId;

    ret = mp_init_multi(key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                      NULL, NULL
                        );
    if (ret != MP_OKAY) {
        return MEMORY_E;
    }

    key->heap = heap;






    return ret;
}





static int wc_ecc_get_curve_order_bit_count(const ecc_set_type* dp)
{
    int err = MP_OKAY;
    int orderBits;
    DECLARE_CURVE_SPECS(1);

    ALLOC_CURVE_SPECS(1, err);
    if (err == MP_OKAY) {
        err = wc_ecc_curve_load(dp, &curve, ECC_CURVE_FIELD_ORDER);
    }

    if (err != 0) {
       FREE_CURVE_SPECS();
       return err;
    }
    orderBits = mp_count_bits(curve->order);

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    return orderBits;
}



/**
  Free an ECC key from memory
  key   The key you wish to free
*/
WOLFSSL_ABI
int wc_ecc_free(ecc_key* key)
{
    if (key == NULL) {
        return 0;
    }










    mp_clear(key->pubkey.x);
    mp_clear(key->pubkey.y);
    mp_clear(key->pubkey.z);

        mp_forcezero(key->k);



    return 0;
}




/* verify
 *
 * w  = s^-1 mod n
 * u1 = xw
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
 Verify an ECC signature
 sig         The signature to verify
 siglen      The length of the signature (octets)
 hash        The hash (message digest) that was signed
 hashlen     The length of the hash (octets)
 res         Result of signature, 1==valid, 0==invalid
 key         The corresponding public ECC key
 return      MP_OKAY if successful (even if the signature is not valid)
             Caller should check the *res value to determine if the signature
             is valid or invalid. Other negative values are returned on error.
 */


static int wc_ecc_check_r_s_range(ecc_key* key, mp_int* r, mp_int* s)
{
    int err = MP_OKAY;
    DECLARE_CURVE_SPECS(1);

    ALLOC_CURVE_SPECS(1, err);
    if (err == MP_OKAY) {
        err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ORDER);
    }
    if (err != 0) {
        FREE_CURVE_SPECS();
        return err;
    }

    if (mp_iszero(r) || mp_iszero(s)) {
        err = MP_ZERO_E;
    }
    if ((err == 0) && (mp_cmp(r, curve->order) != MP_LT)) {
        err = MP_VAL;
    }
    if ((err == 0) && (mp_cmp(s, curve->order) != MP_LT)) {
        err = MP_VAL;
    }

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    return err;
}

#if defined(HAVE_ECC_VERIFY_HELPER) && !defined(WOLFSSL_MICROCHIP)
static int ecc_verify_hash_sp(mp_int *r, mp_int *s, const byte* hash,
    word32 hashlen, int* res, ecc_key* key)
{
    (void)r;
    (void)s;
    (void)hash;
    (void)hashlen;
    (void)res;
    (void)key;


    if (key->idx == ECC_CUSTOM_IDX || (1
         && ecc_sets[key->idx].id != ECC_SECP384R1
        )) {
        return WC_KEY_SIZE_E;
    }

    if (key->idx != ECC_CUSTOM_IDX) {
        if (ecc_sets[key->idx].id == ECC_SECP384R1) {
            {
                int ret;
                SAVE_VECTOR_REGISTERS(return _svr_ret;);
                ret = sp_ecc_verify_384(hash, hashlen, key->pubkey.x,
                    key->pubkey.y, key->pubkey.z, r, s, res, key->heap);
                RESTORE_VECTOR_REGISTERS();
                return ret;
            }
        }
    }

    return NOT_COMPILED_IN;
}

#endif /* HAVE_ECC_VERIFY_HELPER */

/**
   Verify an ECC signature
   r           The signature R component to verify
   s           The signature S component to verify
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   res         Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
               Caller should check the *res value to determine if the signature
               is valid or invalid. Other negative values are returned on error.
*/
int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key)
{
   int           err;
   word32        keySz = 0;
   byte hashIsZero = 0;
   word32 zIdx;
   int curveLoaded = 0;
   DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);

   if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL)
       return ECC_BAD_ARG_E;

    /* Check hash length */
    if ((hashlen > WC_MAX_DIGEST_SIZE) ||
        (hashlen < WC_MIN_DIGEST_SIZE)) {
        return BAD_LENGTH_E;
    }

    /* reject all 0's hash */
    for (zIdx = 0; zIdx < hashlen; zIdx++)
        hashIsZero |= hash[zIdx];
    if (hashIsZero == 0)
        return ECC_BAD_ARG_E;

   /* default to invalid signature */
   *res = 0;

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) == 0 || key->dp == NULL) {
      return ECC_BAD_ARG_E;
   }

   err = wc_ecc_check_r_s_range(key, r, s);
   if (err != MP_OKAY) {
      return err;
   }

   keySz = (word32)key->dp->size;


#ifndef HAVE_ECC_VERIFY_HELPER

    /* Extract R and S with front zero padding (if required),
     * SE050 does this in port layer  */
    XMEMSET(sigRS, 0, sizeof(sigRS));
    err = mp_to_unsigned_bin(r, sigRS +
                                (keySz - mp_unsigned_bin_size(r)));
    if (err != MP_OKAY) {
        return err;
    }
    err = mp_to_unsigned_bin(s, sigRS + keySz +
                                (keySz - mp_unsigned_bin_size(s)));
    if (err != MP_OKAY) {
        return err;
    }


#else
  /* checking if private key with no public part */
  if (key->type == ECC_PRIVATEKEY_ONLY) {
      WOLFSSL_MSG("Verify called with private key, generating public part");
      ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT, err);
      if (err != MP_OKAY) {
          return err;
      }
      err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ALL);
      if (err != MP_OKAY) {
          FREE_CURVE_SPECS();
          return err;
      }
      err = ecc_make_pub_ex(key, curve, NULL, NULL);
      if (err != MP_OKAY) {
           WOLFSSL_MSG("Unable to extract public key");
           wc_ecc_curve_free(curve);
           FREE_CURVE_SPECS();
           return err;
      }
      curveLoaded = 1;
  }

  err = ecc_verify_hash_sp(r, s, hash, hashlen, res, key);
  if (err != WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
      if (curveLoaded) {
           wc_ecc_curve_free(curve);
           FREE_CURVE_SPECS();
      }
      return err;
  }


   (void)curveLoaded;
   wc_ecc_curve_free(curve);
   FREE_CURVE_SPECS();
#endif /* HAVE_ECC_VERIFY_HELPER */

   (void)keySz;
   (void)hashlen;

   return err;
}

/* import point from der
 * if shortKeySize != 0 then keysize is always (inLen-1)>>1 */

/* function for backwards compatibility with previous implementations */



/* is ecc point on curve described by dp ? */
static int _ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime)
{
   (void)a;
   (void)b;

   if (mp_count_bits(prime) == 384) {
       return sp_ecc_is_point_384(ecp->x, ecp->y);
   }
   return WC_KEY_SIZE_E;
}


#ifdef HAVE_ECC_CHECK_PUBKEY_ORDER

#if (FIPS_VERSION_GE(5,0) || defined(WOLFSSL_VALIDATE_ECC_KEYGEN) ||  (defined(WOLFSSL_VALIDATE_ECC_IMPORT) && !defined(WOLFSSL_SP_MATH))) &&  !defined(WOLFSSL_KCAPI_ECC) || defined(WOLFSSL_CAAM)
/* validate privkey * generator == pubkey, 0 on success */
static int ecc_check_privkey_gen(ecc_key* key, mp_int* a, mp_int* prime)
{
    int        err;
    ecc_point* base = NULL;
    ecc_point* res  = NULL;
    ecc_point lcl_base;
    ecc_point lcl_res;
    DECLARE_CURVE_SPECS(3);

    if (key == NULL)
        return BAD_FUNC_ARG;

    ALLOC_CURVE_SPECS(3, err);
    if (err != MP_OKAY) {
        WOLFSSL_MSG("ALLOC_CURVE_SPECS failed");
        return err;
    }

    res = &lcl_res;
    err = wc_ecc_new_point_ex(&res, key->heap);

    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        if (err == MP_OKAY) {
            err = sp_ecc_mulmod_base_384(ecc_get_k(key), res, 1, key->heap);
        }
    }
    else
    {
        if (err == MP_OKAY) {
            base = &lcl_base;
            err = wc_ecc_new_point_ex(&base, key->heap);
        }

        if (err == MP_OKAY) {
            /* load curve info */
            err = wc_ecc_curve_load(key->dp, &curve, (ECC_CURVE_FIELD_GX |
                                   ECC_CURVE_FIELD_GY | ECC_CURVE_FIELD_ORDER));
        }

        /* set up base generator */
        if (err == MP_OKAY)
            err = mp_copy(curve->Gx, base->x);
        if (err == MP_OKAY)
            err = mp_copy(curve->Gy, base->y);
        if (err == MP_OKAY)
            err = mp_set(base->z, 1);

        if (err == MP_OKAY)
            err = wc_ecc_mulmod_ex2(ecc_get_k(key), base, res, a, prime,
                                          curve->order, key->rng, 1, key->heap);
    }

    if (err == MP_OKAY) {
        /* compare result to public key */
        if (mp_cmp(res->x, key->pubkey.x) != MP_EQ ||
            mp_cmp(res->y, key->pubkey.y) != MP_EQ ||
            mp_cmp(res->z, key->pubkey.z) != MP_EQ) {
            /* didn't match */
            err = ECC_PRIV_KEY_E;
        }
    }

    wc_ecc_curve_free(curve);
    wc_ecc_del_point_ex(res, key->heap);
    wc_ecc_del_point_ex(base, key->heap);
    FREE_CURVE_SPECS();

    return err;
}
#endif /* FIPS_VERSION_GE(5,0) || WOLFSSL_VALIDATE_ECC_KEYGEN || * (!WOLFSSL_SP_MATH && WOLFSSL_VALIDATE_ECC_IMPORT) */

#if (FIPS_VERSION_GE(5,0) || defined(WOLFSSL_VALIDATE_ECC_KEYGEN)) &&  !defined(WOLFSSL_KCAPI_ECC) && defined(HAVE_ECC_DHE)

/* check privkey generator helper, creates prime needed */
static int ecc_check_privkey_gen_helper(ecc_key* key)
{
    int    err;
    DECLARE_CURVE_SPECS(2);

    if (key == NULL)
        return BAD_FUNC_ARG;

    ALLOC_CURVE_SPECS(2, err);

    /* load curve info */
    if (err == MP_OKAY)
        err = wc_ecc_curve_load(key->dp, &curve,
            (ECC_CURVE_FIELD_PRIME | ECC_CURVE_FIELD_AF));

    if (err == MP_OKAY)
        err = ecc_check_privkey_gen(key, curve->Af, curve->prime);

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();


    return err;
}

/* Performs a Pairwise Consistency Test on an ECC key pair. */
static int _ecc_pairwise_consistency_test(ecc_key* key, WC_RNG* rng)
{
    int err = 0;
    word32 flags = key->flags;

    /* If flags not set default to cofactor and dec/sign */
    if ((flags & (WC_ECC_FLAG_COFACTOR | WC_ECC_FLAG_DEC_SIGN)) == 0) {
        flags = (WC_ECC_FLAG_COFACTOR | WC_ECC_FLAG_DEC_SIGN);
    }

    if (flags & WC_ECC_FLAG_COFACTOR) {
        err = ecc_check_privkey_gen_helper(key);
    }

    if (!err && (flags & WC_ECC_FLAG_DEC_SIGN)) {
        #define SIG_SZ ((MAX_ECC_BYTES * 2) + SIG_HEADER_SZ + ECC_MAX_PAD_SZ)
        byte sig[SIG_SZ + WC_SHA256_DIGEST_SIZE];
        byte* digest;
        word32 sigLen, digestLen;
        int dynRng = 0, res = 0;

        sigLen = (word32)wc_ecc_sig_size(key);
        digestLen = WC_SHA256_DIGEST_SIZE;
        WC_ALLOC_VAR_EX(sig, byte, sigLen+digestLen, key->heap,
            DYNAMIC_TYPE_ECC, return MEMORY_E);
        digest = sig + sigLen;

        if (rng == NULL) {
            dynRng = 1;
            rng = wc_rng_new(NULL, 0, key->heap);
            if (rng == NULL) {
                WC_FREE_VAR_EX(sig, key->heap, DYNAMIC_TYPE_ECC);
                return MEMORY_E;
            }
        }

        err = wc_RNG_GenerateBlock(rng, digest, digestLen);

        if (!err)
            err = wc_ecc_sign_hash(digest, WC_SHA256_DIGEST_SIZE, sig, &sigLen,
                    rng, key);
        if (!err)
            err = wc_ecc_verify_hash(sig, sigLen,
                    digest, WC_SHA256_DIGEST_SIZE, &res, key);

        if (res == 0)
            err = ECC_PCT_E;

        if (dynRng) {
            wc_rng_free(rng);
        }
        ForceZero(sig, sigLen + digestLen);
        WC_FREE_VAR_EX(sig, key->heap, DYNAMIC_TYPE_ECC);
    }
    (void)rng;

    if (err != 0)
        err = ECC_PCT_E;

    return err;
}
#endif /* (FIPS v5 or later || WOLFSSL_VALIDATE_ECC_KEYGEN) && \ !WOLFSSL_KCAPI_ECC && HAVE_ECC_DHE */

#endif /* HAVE_ECC_CHECK_PUBKEY_ORDER */




/* Validate the public key per SP 800-56Ar3 section 5.6.2.3.3,
 * ECC Full Public Key Validation Routine. If the parameter
 * partial is set, then it follows section 5.6.2.3.4, the ECC
 * Partial Public Key Validation Routine.
 * If the parameter priv is set, add in a few extra
 * checks on the bounds of the private key. */
static int _ecc_validate_public_key(ecc_key* key, int partial, int priv)
{
    int err = MP_OKAY;

    ASSERT_SAVED_VECTOR_REGISTERS();

    if (key == NULL)
        return BAD_FUNC_ARG;

#ifndef HAVE_ECC_CHECK_PUBKEY_ORDER
    /* consider key check success on HW crypto
     * ex: ATECC508/608A, CryptoCell and Silabs
     *
     * consider key check success on most Crypt Cb only builds
     */
    err = MP_OKAY;

#else

    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        return sp_ecc_check_key_384(key->pubkey.x, key->pubkey.y,
            key->type == ECC_PRIVATEKEY ? ecc_get_k(key) : NULL, key->heap);
    }

    /* The single precision math curve is not available */
    err = WC_KEY_SIZE_E;
#endif /* HAVE_ECC_CHECK_PUBKEY_ORDER */

    (void)partial;
    (void)priv;
    return err;
}


/* perform sanity checks on ecc key validity, 0 on success */


/* Software-only import of public ECC key in ANSI X9.63 format.
 * This internal helper avoids recursion when called from the SETKEY path. */
static int _ecc_import_x963_ex2(const byte* in, word32 inLen, ecc_key* key,
                                int curve_id, int untrusted)
{
    int err = MP_OKAY;
    int keysize = 0;
    byte pointType;

    if (in == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    /* must be odd */
    if ((inLen & 1) == 0) {
        return ECC_BAD_ARG_E;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    /* init key */
        err = mp_init_multi(key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                      NULL, NULL
                            );
    if (err != MP_OKAY)
        return MEMORY_E;

    SAVE_VECTOR_REGISTERS(return _svr_ret;);

    /* check for point type (4, 2, or 3) */
    pointType = in[0];
    if (pointType != ECC_POINT_UNCOMP && pointType != ECC_POINT_COMP_EVEN &&
                                         pointType != ECC_POINT_COMP_ODD) {
        err = ASN_PARSE_E;
    }

    if (pointType == ECC_POINT_COMP_EVEN || pointType == ECC_POINT_COMP_ODD) {
        err = NOT_COMPILED_IN;
    }

    /* adjust to skip first byte */
    inLen -= 1;
    in += 1;


    if (err == MP_OKAY) {

        /* determine key size */
        keysize = (int)(inLen>>1);
        /* NOTE: FIPS v6.0.0 or greater, no restriction on imported keys, only
         *       on created keys or signatures */
        err = wc_ecc_set_curve(key, keysize, curve_id);
        key->type = ECC_PUBLICKEY;
    }

    /* read data */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(key->pubkey.x, in, (word32)keysize);


    if (err == MP_OKAY) {
        {
            err = mp_read_unsigned_bin(key->pubkey.y, in + keysize,
                (word32)keysize);
        }
    }
    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);

    if ((err == MP_OKAY) && untrusted) {
        /* Reject point at infinity. */
        if (wc_ecc_point_is_at_infinity(&key->pubkey)) {
            err = ECC_INF_E;
        }
        /* Verify the point lies on the curve (y^2 = x^3 + ax + b mod p) */
        if ((err == MP_OKAY) && (key->idx != ECC_CUSTOM_IDX)) {
            if (ecc_sets[key->idx].id == ECC_SECP384R1) {
                err = sp_ecc_is_point_384(key->pubkey.x, key->pubkey.y);
            }
            else
            {
                err = wc_ecc_point_is_on_curve(&key->pubkey, key->idx);
            }
        }
    }
    (void)untrusted;


    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_forcezero(key->k);
    }

    RESTORE_VECTOR_REGISTERS();

    return err;
}

/* import public ECC key in ANSI X9.63 format */

/* import public ECC key in ANSI X9.63 format */



/* Software-only import of private key, public part optional.
 * This internal helper avoids recursion when called from the SETKEY path. */
static int _ecc_import_private_key_ex(const byte* priv, word32 privSz,
                                      const byte* pub, word32 pubSz,
                                      ecc_key* key, int curve_id)
{
    int ret;

    if (key == NULL || priv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* public optional, NULL if only importing private */
    if (pub != NULL) {
        (void)pubSz;
        ret = NOT_COMPILED_IN;
    }
    else {
        /* make sure required variables are reset */
        wc_ecc_reset(key);

        /* set key size */
        /* NOTE: FIPS v6.0.0 or greater, no restriction on imported keys, only
         *       on created keys or signatures */
        ret = wc_ecc_set_curve(key, (int)privSz, curve_id);
        key->type = ECC_PRIVATEKEY_ONLY;
    }

    if (ret != 0)
        return ret;



    ret = mp_read_unsigned_bin(key->k, priv, privSz);





    return ret;
}

/* import private key, public part optional if (pub) passed as NULL */

/* ecc private key import, public key in ANSI X9.63 format, private raw */


/* Software-only import of raw ECC key material.
 * This internal helper avoids recursion when called from the SETKEY path. */
static int _ecc_import_raw_private(ecc_key* key, const char* qx,
          const char* qy, const char* d, int curve_id, int encType)
{
    int err = MP_OKAY;

    /* if d is NULL, only import as public key using Qx,Qy */
    if (key == NULL || qx == NULL || qy == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    /* set curve type and index */
    /* NOTE: FIPS v6.0.0 or greater, no restriction on imported keys, only
     *       on created keys or signatures */
    err = wc_ecc_set_curve(key, 0, curve_id);
    if (err != 0) {
        return err;
    }

    /* init key */
    err = mp_init_multi(key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                      NULL, NULL
                        );
    if (err != MP_OKAY)
        return MEMORY_E;

    /* read Qx */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.x, qx, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.x, (const byte*)qx,
                (word32)key->dp->size);

        if (mp_isneg(key->pubkey.x)) {
            WOLFSSL_MSG("Invalid Qx");
            err = BAD_FUNC_ARG;
        }
        if (mp_unsigned_bin_size(key->pubkey.x) > key->dp->size) {
            err = BAD_FUNC_ARG;
        }
    }

    /* read Qy */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.y, qy, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.y, (const byte*)qy,
                (word32)key->dp->size);

        if (mp_isneg(key->pubkey.y)) {
            WOLFSSL_MSG("Invalid Qy");
            err = BAD_FUNC_ARG;
        }
        if (mp_unsigned_bin_size(key->pubkey.y) > key->dp->size) {
            err = BAD_FUNC_ARG;
        }
    }

    if (err == MP_OKAY) {
        if (mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y)) {
            WOLFSSL_MSG("Invalid Qx and Qy");
            err = ECC_INF_E;
        }
    }

    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);



    /* import private key */
    if (err == MP_OKAY) {
        if (d != NULL) {
            key->type = ECC_PRIVATEKEY;
            if (encType == WC_TYPE_HEX_STR)
                err = mp_read_radix(key->k, d, MP_RADIX_HEX);
            else {
                {
                    err = mp_read_unsigned_bin(key->k, (const byte*)d,
                        (word32)key->dp->size);
                }
            }

            if (err == MP_OKAY) {
                if (mp_iszero(key->k) || mp_isneg(key->k)) {
                    WOLFSSL_MSG("Invalid private key");
                    err = BAD_FUNC_ARG;
                }
            }
        } else {
            key->type = ECC_PUBLICKEY;
        }
    }




    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_forcezero(key->k);
    }

    return err;
}

static int wc_ecc_import_raw_private(ecc_key* key, const char* qx,
          const char* qy, const char* d, int curve_id, int encType)
{

    /* if d is NULL, only import as public key using Qx,Qy */
    if (key == NULL || qx == NULL || qy == NULL) {
        return BAD_FUNC_ARG;
    }


    return _ecc_import_raw_private(key, qx, qy, d, curve_id, encType);
}

/**
   Import raw ECC key
   key       The destination ecc_key structure
   qx        x component of the public key, as ASCII hex string
   qy        y component of the public key, as ASCII hex string
   d         private key, as ASCII hex string, optional if importing public
             key only
   curve_id  The id of the curve.
   @return    MP_OKAY on success
*/

/* Import x, y and optional private (d) as unsigned binary */
int wc_ecc_import_unsigned(ecc_key* key, const byte* qx, const byte* qy,
                   const byte* d, int curve_id)
{
    return wc_ecc_import_raw_private(key, (const char*)qx, (const char*)qy,
        (const char*)d, curve_id, WC_TYPE_UNSIGNED_BIN);
}

/**
   Import raw ECC key
   key       The destination ecc_key structure
   qx        x component of the public key, as ASCII hex string
   qy        y component of the public key, as ASCII hex string
   d         private key, as ASCII hex string, optional if importing public
             key only
   curveName ECC curve name, from ecc_sets[]
   return    MP_OKAY on success
*/


/* key size in octets */

/* maximum signature size based on key size */

/* maximum signature size based on actual key curve */














