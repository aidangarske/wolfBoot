/* sha512.c
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
 * SHA-512/384 Build Options:
 *
 * Core:
 * WOLFSSL_SHA512:           Enable SHA-512 support                default: off
 * WOLFSSL_SHA384:           Enable SHA-384 support                default: off
 * WOLFSSL_NOSHA512_224:     Disable SHA-512/224 variant           default: off
 * WOLFSSL_NOSHA512_256:     Disable SHA-512/256 variant           default: off
 *
 * Performance:
 * USE_SLOW_SHA512:          Disable SHA-512 loop unrolling        default: off
 * USE_SLOW_SHA2:            Disable SHA-2 loop unrolling          default: off
 * WOLFSSL_HASH_FLAGS:       Enable hash flags for state tracking  default: off
 * WOLFSSL_HASH_KEEP:        Keep hash input data for reuse        default: off
 * WOLFSSL_SMALL_STACK_CACHE: Cache hash state on small stack      default: off
 * WC_NO_INTERNAL_FUNCTION_POINTERS: Disable internal func ptrs   default: off
 *
 * Hardware Acceleration (SHA-512-specific):
 * WC_ASYNC_ENABLE_SHA512:   Enable async SHA-512 operations       default: off
 * WC_ASYNC_ENABLE_SHA384:   Enable async SHA-384 operations       default: off
 * WOLFSSL_KCAPI_HASH:       Linux kernel crypto API for hashing  default: off
 * WOLFSSL_SE050_HASH:       SE050 hardware hashing               default: off
 * WOLFSSL_SILABS_SHA384:    Silicon Labs SHA-384 acceleration    default: off
 * WOLFSSL_SILABS_SHA512:    Silicon Labs SHA-512 acceleration    default: off
 * NO_IMX6_CAAM_HASH:        Disable i.MX6 CAAM hash             default: off
 * NO_WOLFSSL_ESP32_CRYPT_HASH: Disable ESP32 hash acceleration   default: off
 * WOLFSSL_ARMASM_CRYPTO_SHA512: ARM crypto SHA-512 instructions  default: off
 * STM32_HASH_SHA384:        STM32 hardware SHA-384               default: off
 * STM32_HASH_SHA512:        STM32 hardware SHA-512               default: off
 * WOLFSSL_SHA512_HASHTYPE:  SHA-512 hash type for hw dispatch    default: off
 * MAX3266X_SHA:             MAX3266X hardware SHA                 default: off
 * PSOC6_HASH_SHA2:          PSoC6 hardware SHA-2                 default: off
 * WOLFSSL_RENESAS_RSIP:     Renesas RSIP SHA acceleration        default: off
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>


/* determine if we are using Espressif SHA hardware acceleration */
#undef WOLFSSL_USE_ESP32_CRYPT_HASH_HW
    #undef WOLFSSL_USE_ESP32_CRYPT_HASH_HW


#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/hash.h>



/* deprecated USE_SLOW_SHA2 (replaced with USE_SLOW_SHA512) */

    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha512_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000015 };
    int wolfCrypt_FIPS_SHA512_sanity(void)
    {
        return 0;
    }
#endif











static int InitSha512(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
    sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[4] = W64LIT(0x510e527fade682d1);
    sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[7] = W64LIT(0x5be0cd19137e2179);

    sha512->buffLen = 0;
    XMEMSET(sha512->buffer, 0, sizeof(sha512->buffer));
    sha512->loLen   = 0;
    sha512->hiLen   = 0;


#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)

    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed. */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512);
#endif

    return 0;
}

#if !defined(WOLFSSL_NOSHA512_224) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)

/**
 * Initialize given wc_Sha512 structure with value specific to sha512/224.
 * Note that sha512/224 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static int InitSha512_224(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x8c3d37c819544da2);
    sha512->digest[1] = W64LIT(0x73e1996689dcd4d6);
    sha512->digest[2] = W64LIT(0x1dfab7ae32ff9c82);
    sha512->digest[3] = W64LIT(0x679dd514582f9fcf);
    sha512->digest[4] = W64LIT(0x0f6d2b697bd44da8);
    sha512->digest[5] = W64LIT(0x77e36f7304c48942);
    sha512->digest[6] = W64LIT(0x3f9d85a86a1d36c8);
    sha512->digest[7] = W64LIT(0x1112e6ad91d692a1);

    sha512->buffLen = 0;
    XMEMSET(sha512->buffer, 0, sizeof(sha512->buffer));
    sha512->loLen   = 0;
    sha512->hiLen   = 0;


#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed.
    **
    ** Note for original ESP32, there's no HW for SHA512/224
    */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512_224);
#endif

    return 0;
}
#endif /* !WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
/**
 * Initialize given wc_Sha512 structure with value specific to sha512/256.
 * Note that sha512/256 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static int InitSha512_256(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x22312194fc2bf72c);
    sha512->digest[1] = W64LIT(0x9f555fa3c84c64c2);
    sha512->digest[2] = W64LIT(0x2393b86b6f53b151);
    sha512->digest[3] = W64LIT(0x963877195940eabd);
    sha512->digest[4] = W64LIT(0x96283ee2a88effe3);
    sha512->digest[5] = W64LIT(0xbe5e1e2553863992);
    sha512->digest[6] = W64LIT(0x2b0199fc2c85b8aa);
    sha512->digest[7] = W64LIT(0x0eb72ddc81c52ca2);

    sha512->buffLen = 0;
    XMEMSET(sha512->buffer, 0, sizeof(sha512->buffer));
    sha512->loLen   = 0;
    sha512->hiLen   = 0;


#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed.
    **
    ** Note for original ESP32, there's no HW for SHA512/2256.
    */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512_256);
#endif

    return 0;
}
#endif /* !WOLFSSL_NOSHA512_256 && !FIPS... */


/* Hardware Acceleration */
    #define Transform_Sha512(sha512) _Transform_Sha512(sha512)



static int InitSha512_Family(wc_Sha512* sha512, void* heap, int devId,
                             int (*initfp)(wc_Sha512*))
{
    int ret = 0;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(sha512, 0, sizeof(*sha512));

    sha512->heap = heap;


    /* call the initialization function pointed to by initfp */
    ret = initfp(sha512);

    (void)devId;


    return ret;
} /* InitSha512_Family */


#if !defined(WOLFSSL_NOSHA512_224) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int wc_InitSha512_224_ex(wc_Sha512* sha512, void* heap, int devId)
{
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* No SHA512/224 HW support is available, set to SW. */
    sha512->ctx.mode = ESP32_SHA_SW; /* no SHA224 HW, so always SW */
#endif
    return InitSha512_Family(sha512, heap, devId, InitSha512_224);
}
#endif /* !WOLFSSL_NOSHA512_224 ... */

#if !defined(WOLFSSL_NOSHA512_256) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int wc_InitSha512_256_ex(wc_Sha512* sha512, void* heap, int devId)
{
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* No SHA512/256 HW support is available on ESP32, set to SW. */
    sha512->ctx.mode = ESP32_SHA_SW;
#endif
    return InitSha512_Family(sha512, heap, devId, InitSha512_256);
}
#endif /* !WOLFSSL_NOSHA512_256 ... */



static const word64 K512[80] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

#define blk0(i) (W[i] = sha512->buffer[i])

#define blk2(i) ( W[ (i)     & 15] +=  s1(W[((i)-2)  & 15])+  W[((i)-7)  & 15] +  s0(W[((i)-15) & 15])   )

#define Ch(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))

#define a(i) T[(0-(i)) & 7]
#define b(i) T[(1-(i)) & 7]
#define c(i) T[(2-(i)) & 7]
#define d(i) T[(3-(i)) & 7]
#define e(i) T[(4-(i)) & 7]
#define f(i) T[(5-(i)) & 7]
#define g(i) T[(6-(i)) & 7]
#define h(i) T[(7-(i)) & 7]

#define S0(x) (rotrFixed64(x,28) ^ rotrFixed64(x,34) ^ rotrFixed64(x,39))
#define S1(x) (rotrFixed64(x,14) ^ rotrFixed64(x,18) ^ rotrFixed64(x,41))
#define s0(x) (rotrFixed64(x,1)  ^ rotrFixed64(x,8)  ^ ((x)>>7))
#define s1(x) (rotrFixed64(x,19) ^ rotrFixed64(x,61) ^ ((x)>>6))

#define R(i)  h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[(i)+j] + (j ? blk2(i) : blk0(i));  d(i) += h(i);  h(i) += S0(a(i)) + Maj(a(i),b(i),c(i))

static int _Transform_Sha512(wc_Sha512* sha512)
{
    const word64* K = K512;
    word32 j;
    word64 T[8];

    word64 W[16];

    /* Copy digest to working vars */
    XMEMCPY(T, sha512->digest, sizeof(T));

    /* 80 operations, partially loop unrolled */
    for (j = 0; j < 80; j += 16) {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }

    /* Add the working vars back into digest */
    sha512->digest[0] += a(0);
    sha512->digest[1] += b(0);
    sha512->digest[2] += c(0);
    sha512->digest[3] += d(0);
    sha512->digest[4] += e(0);
    sha512->digest[5] += f(0);
    sha512->digest[6] += g(0);
    sha512->digest[7] += h(0);

    /* Wipe variables */
    ForceZero(W, sizeof(word64) * 16);
    ForceZero(T, sizeof(T));


    return 0;
}


static WC_INLINE void AddLength(wc_Sha512* sha512, word32 len)
{
    word64 tmp = sha512->loLen;
    if ( (sha512->loLen += len) < tmp)
        sha512->hiLen++;                       /* carry low to high */
}

static WC_INLINE int Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    int ret = 0;
    /* do block size increments */
    byte* local = (byte*)sha512->buffer;

    /* check that internal buffLen is valid */
    if (sha512->buffLen >= WC_SHA512_BLOCK_SIZE)
        return BUFFER_E;

    if (len == 0)
        return 0;

    AddLength(sha512, len);

    if (sha512->buffLen > 0) {
        word32 add = min(len, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        if (add > 0) {
            XMEMCPY(&local[sha512->buffLen], data, add);

            sha512->buffLen += add;
            data            += add;
            len             -= add;
        }

        if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
            {
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
            }
            ret = Transform_Sha512(sha512);
            if (ret == 0)
                sha512->buffLen = 0;
            else
                len = 0;
        }
    }

    {
        while (len >= WC_SHA512_BLOCK_SIZE) {
            XMEMCPY(local, data, WC_SHA512_BLOCK_SIZE);

            data += WC_SHA512_BLOCK_SIZE;
            len  -= WC_SHA512_BLOCK_SIZE;
            ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                       WC_SHA512_BLOCK_SIZE);
            ret = Transform_Sha512(sha512);
            if (ret != 0)
                break;
        } /* while (len >= WC_SHA512_BLOCK_SIZE) */
    }

    if (ret == 0 && len > 0) {
        XMEMCPY(local, data, len);
        sha512->buffLen = len;
    }

    return ret;
}


int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }


    return Sha512Update(sha512, data, len);
}





static WC_INLINE int Sha512Final(wc_Sha512* sha512)
{
    int ret;
    byte* local;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha512->buffer;

    /* we'll add a 0x80 byte at the end,
    ** so make sure we have appropriate buffer length. */
    if (sha512->buffLen > WC_SHA512_BLOCK_SIZE - 1) {
        return BAD_STATE_E;
    } /* buffLen check */

    local[sha512->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha512->buffLen > WC_SHA512_PAD_SIZE) {
        if (sha512->buffLen < WC_SHA512_BLOCK_SIZE ) {
            XMEMSET(&local[sha512->buffLen], 0,
                WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        }

        sha512->buffLen += WC_SHA512_BLOCK_SIZE - sha512->buffLen;
        {

            ByteReverseWords64(sha512->buffer,sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
        }

    #if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
        if (sha512->ctx.mode == ESP32_SHA_INIT) {
            esp_sha_try_hw_lock(&sha512->ctx);
        }
        if (sha512->ctx.mode == ESP32_SHA_SW) {
            ByteReverseWords64(sha512->buffer,sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
            ret = Transform_Sha512(sha512);
        }
        else {
            ret = esp_sha512_process(sha512);
        }
    #else
        ret = Transform_Sha512(sha512);
    #endif
        if (ret != 0) {
            return ret;
        }

        sha512->buffLen = 0;
    } /* (sha512->buffLen > WC_SHA512_PAD_SIZE) pad with zeros */

    XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_PAD_SIZE - sha512->buffLen);

    /* put lengths in bits */
    sha512->hiLen = (sha512->loLen >> (8 * sizeof(sha512->loLen) - 3)) +
                                                         (sha512->hiLen << 3);
    sha512->loLen = sha512->loLen << 3;

    /* store lengths */
            ByteReverseWords64(sha512->buffer, sha512->buffer, WC_SHA512_PAD_SIZE);
    /* ! length ordering dependent on digest endian type ! */

    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;


    ret = Transform_Sha512(sha512);

    if (ret != 0)
        return ret;

        ByteReverseWords64(sha512->digest, sha512->digest,
            WC_SHA512_DIGEST_SIZE);


    return 0;
}




static int Sha512FinalRaw(wc_Sha512* sha512, byte* hash, word32 digestSz)
{
    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((digestSz & 0x7) == 0)
        ByteReverseWords64((word64 *)hash, sha512->digest, digestSz);
    else {
        ByteReverseWords64(sha512->digest, sha512->digest,
                           WC_SHA512_DIGEST_SIZE);
        XMEMCPY(hash, sha512->digest, digestSz);
    }

    return 0;
}


static int Sha512_Family_Final(wc_Sha512* sha512, byte* hash, size_t digestSz,
                               int (*initfp)(wc_Sha512*))
{
    int ret;

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }


    ret = Sha512Final(sha512);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha512->digest, digestSz);

    /* initialize Sha512 structure for the next use */
    return initfp(sha512);
}




void wc_Sha512Free(wc_Sha512* sha512)
{

    if (sha512 == NULL)
        return;









    ForceZero(sha512, sizeof(*sha512));
}



/* -------------------------------------------------------------------------- */
/* SHA384 */
/* -------------------------------------------------------------------------- */


static int InitSha384(wc_Sha384* sha384)
{
    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }


    sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[1] = W64LIT(0x629a292a367cd507);
    sha384->digest[2] = W64LIT(0x9159015a3070dd17);
    sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[4] = W64LIT(0x67332667ffc00b31);
    sha384->digest[5] = W64LIT(0x8eb44a8768581511);
    sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);

    sha384->buffLen = 0;
    XMEMSET(sha384->buffer, 0, sizeof(sha384->buffer));
    sha384->loLen   = 0;
    sha384->hiLen   = 0;


#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW)  &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed. */
    esp_sha_init(&(sha384->ctx), WC_HASH_TYPE_SHA384);
#endif




    return 0;
}

int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
{

    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }


    return Sha512Update((wc_Sha512*)sha384, data, len);
}



int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
{
    int ret;

    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }


    ret = Sha512Final((wc_Sha512*)sha384);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);

    return InitSha384(sha384);  /* reset state */
}

int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
{
    int ret;

    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha384->heap = heap;
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW)  &&  !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    if (sha384->ctx.mode != ESP32_SHA_INIT) {
        ESP_LOGV(TAG, "Set ctx mode from prior value: "
                           "%d", sha384->ctx.mode);
    }
    /* We know this is a fresh, uninitialized item, so set to INIT */
    sha384->ctx.mode = ESP32_SHA_INIT;
#endif


    ret = InitSha384(sha384);
    if (ret != 0) {
        return ret;
    }

    (void)devId;
    return ret;
}



void wc_Sha384Free(wc_Sha384* sha384)
{

    if (sha384 == NULL)
        return;










    ForceZero(sha384, sizeof(*sha384));
}




static int Sha512_Family_GetHash(wc_Sha512* sha512, byte* hash,
                                 int (*finalfp)(wc_Sha512*, byte*))
{
    int ret;
    WC_DECLARE_VAR(tmpSha512, wc_Sha512, 1, 0);

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    WC_CALLOC_VAR_EX(tmpSha512, wc_Sha512, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    /* copy this sha512 into tmpSha */
    ret = wc_Sha512Copy(sha512, tmpSha512);
    if (ret == 0) {
        ret = finalfp(tmpSha512, hash);
        wc_Sha512Free(tmpSha512);
    }

    WC_FREE_VAR_EX(tmpSha512, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}





#if !defined(WOLFSSL_NOSHA512_224) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)

int wc_InitSha512_224(wc_Sha512* sha)
{
    return wc_InitSha512_224_ex(sha, NULL, INVALID_DEVID);
}
int wc_Sha512_224Update(wc_Sha512* sha, const byte* data, word32 len)
{
    return wc_Sha512Update(sha, data, len);
}
int wc_Sha512_224FinalRaw(wc_Sha512* sha, byte* hash)
{
    return Sha512FinalRaw(sha, hash, WC_SHA512_224_DIGEST_SIZE);
}

int wc_Sha512_224Final(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_Final(sha512, hash, WC_SHA512_224_DIGEST_SIZE,
                               InitSha512_224);
}

void wc_Sha512_224Free(wc_Sha512* sha)
{
    wc_Sha512Free(sha);
}

int wc_Sha512_224GetHash(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_GetHash(sha512, hash, wc_Sha512_224Final);
}

int wc_Sha512_224Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}




#endif /* !WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) &&  (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int wc_InitSha512_256(wc_Sha512* sha)
{
    return wc_InitSha512_256_ex(sha, NULL, INVALID_DEVID);
}
int wc_Sha512_256Update(wc_Sha512* sha, const byte* data, word32 len)
{
    return wc_Sha512Update(sha, data, len);
}
int wc_Sha512_256FinalRaw(wc_Sha512* sha, byte* hash)
{
    return Sha512FinalRaw(sha, hash, WC_SHA512_256_DIGEST_SIZE);
}

int wc_Sha512_256Final(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_Final(sha512, hash, WC_SHA512_256_DIGEST_SIZE,
                               InitSha512_256);
}

void wc_Sha512_256Free(wc_Sha512* sha)
{
    wc_Sha512Free(sha);
}

int wc_Sha512_256GetHash(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_GetHash(sha512, hash, wc_Sha512_256Final);
}
int wc_Sha512_256Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}




#endif /* !WOLFSSL_NOSHA512_256 && !FIPS ... */









