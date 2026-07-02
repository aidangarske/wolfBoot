/* image.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
/**
 * @file image.c
 * @brief This file contains functions related to image handling and
 * verification.
 */
#include <wolfssl/wolfcrypt/settings.h> /* for wolfCrypt hash/sign routines */


#include <stddef.h>
#include <string.h>

#include "loader.h"
#include "image.h"
#include "wolfboot/wolfboot.h"
#include "hal.h"
#include "spi_drv.h"
#include "printf.h"
#include <wolfssl/wolfcrypt/sha512.h>

/* Globals */
static uint8_t digest[WOLFBOOT_SHA_DIGEST_SIZE] XALIGNED(4);

int NOINLINEFUNCTION image_CT_compare(
    const uint8_t *expected, const uint8_t *actual, uint32_t len)
{
    volatile uint32_t diff = 0U;
    uint32_t i;

    for (i = 0; i < len; i++) {
        diff |= (uint32_t)(expected[i] ^ actual[i]);
    }

    return (diff != 0U) ? 1 : 0;
}


/* TPM based verify */

/* wolfCrypt software verify */




#include <wolfssl/wolfcrypt/ecc.h>

    #define ECC_KEY_TYPE ECC_SECP384R1

/**
 * @brief Verify the signature of the image using the provided key slot
 * and signature.
 *
 * @param key_slot The key slot ID to use for verification.
 * @param img The image to verify.
 * @param sig The signature to use for verification.
 */
static void wolfBoot_verify_signature_ecc(uint8_t key_slot,
        struct wolfBoot_image *img, uint8_t *sig)
{
    int ret, verify_res = 0;
    ecc_key ecc;
    mp_int  r, s;
    uint8_t* pubkey    = keystore_get_buffer(key_slot);
    int      pubkey_sz = keystore_get_size(key_slot);
    int      point_sz  = pubkey_sz / 2;

    if (pubkey == NULL || pubkey_sz <= 0) {
        return;
    }

    ret = wc_ecc_init_ex(&ecc, NULL, WOLFBOOT_DEVID_PUBKEY);

    if (ret == 0) {
        /* Import public key */
        ret = wc_ecc_import_unsigned(&ecc, pubkey, pubkey + point_sz, NULL,
            ECC_KEY_TYPE);
        if (ret == 0 && ecc.type == ECC_PUBLICKEY) {
            /* Import signature into r,s */
            mp_init(&r);
            mp_init(&s);
            mp_read_unsigned_bin(&r, sig, point_sz);
            mp_read_unsigned_bin(&s, sig + point_sz, point_sz);
            VERIFY_FN(img, &verify_res, wc_ecc_verify_hash_ex, &r, &s,
                img->sha_hash, WOLFBOOT_SHA_DIGEST_SIZE, &verify_res, &ecc);
        }
    }
    wc_ecc_free(&ecc);
}









/**
 * @brief Get the specified header type from the external flash image.
 *
 * @param img The image to retrieve the header from.
 * @param type The type of header to retrieve.
 * @param ptr A pointer to the header data.
 * @return The size of the header if found, otherwise 0.
 */
static uint16_t get_header_ext(struct wolfBoot_image *img, uint16_t type,
        uint8_t **ptr);

/**
 * @brief This function searches for the TLV entry in the header and provides
 * a pointer to the corresponding data.
 *
 * @param img The image to retrieve the data from.
 * @param type The type of header to retrieve.
 * @param ptr A pointer to store the position of the header.
 * @return The size of the data if found, otherwise 0.
 */
#define get_header wolfBoot_get_header /* internal reference to function */
uint16_t wolfBoot_get_header(struct wolfBoot_image *img, uint16_t type,
        uint8_t **ptr)
{
    if (PART_IS_EXT(img))
        return get_header_ext(img, type, ptr);
    else
        return wolfBoot_find_header(img->hdr + IMAGE_HEADER_OFFSET, type, ptr);
}

/**
 * @brief Get a block of data to be hashed.
 *
 * @param img The image to retrieve the data from.
 * @param offset The offset to start reading the data from.
 * @return A pointer to the data block.
 */
static uint8_t *get_sha_block(struct wolfBoot_image *img, uint32_t offset)
{
    if (offset > img->fw_size)
        return NULL;
        return (uint8_t *)(img->fw_base + offset);
}

#   define fetch_hdr_cpy(i) ((uint8_t *)0)
static uint16_t get_header_ext(struct wolfBoot_image *img, uint16_t type,
    uint8_t **ptr)
{
    (void)img; (void)type; (void)ptr;
    return 0;
}

static uint8_t *get_img_hdr(struct wolfBoot_image *img)
{
    if (PART_IS_EXT(img))
        return fetch_hdr_cpy(img);
    else
        return (uint8_t *)(img->hdr);
}


#include <wolfssl/wolfcrypt/sha512.h>

/* Initialize and hash the header part */
static int header_sha384(wc_Sha384 *sha384_ctx, struct wolfBoot_image *img)
{
    uint16_t stored_sha_len;
    uint8_t *stored_sha, *end_sha;
    uint8_t* p;
    if (!img)
        return -1;

    p = get_img_hdr(img);
    stored_sha_len = get_header(img, HDR_SHA384, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    end_sha = stored_sha - (2 * sizeof(uint16_t)); /* Subtract 2 Type + 2 Len */
    (void)wc_InitSha384_ex(sha384_ctx, NULL, WOLFBOOT_DEVID_HASH);
    {
        int blksz;
        while (p < end_sha) {
            blksz = WOLFBOOT_SHA_BLOCK_SIZE;
            if (end_sha - p < blksz)
                blksz = end_sha - p;
            wc_Sha384Update(sha384_ctx, p, blksz);
            p += blksz;
        }
    }
    return 0;
}


/**
 * @brief Calculate SHA-384 hash of the image.
 *
 * This function calculates the SHA-384 hash of the given image.
 *
 * @param img The pointer to the wolfBoot_image structure representing the image.
 * @param hash The buffer to store the SHA-384 hash (48 bytes).
 * @return 0 on success, -1 on error.
 */
static int image_sha384(struct wolfBoot_image *img, uint8_t *hash)
{
    wc_Sha384 sha384_ctx;

    if (header_sha384(&sha384_ctx, img) != 0)
        return -1;
    {
        uint32_t position = 0;
        uint8_t* p;
        int      blksz;
        do {
            p = get_sha_block(img, position);
            if (p == NULL)
                break;
            blksz = WOLFBOOT_SHA_BLOCK_SIZE;
            if (position + blksz > img->fw_size)
                blksz = img->fw_size - position;
            wc_Sha384Update(&sha384_ctx, p, blksz);
            position += blksz;
        } while (position < img->fw_size);
    }

    wc_Sha384Final(&sha384_ctx, hash);
    wc_Sha384Free(&sha384_ctx);
    return 0;
}


/**
 * @brief Calculate SHA-384 hash of a public key in the keystore.
 *
 * This function calculates the SHA-384 hash of the public key stored in
 * the keystore at the specified key slot.
 *
 * @param key_slot The key slot ID where the public key is stored in the
 * keystore.
 * @param hash The buffer to store the SHA-384 hash (48 bytes).
 * @return None.
 */
static void key_sha384(uint8_t key_slot, uint8_t *hash)
{
    uint8_t *pubkey = keystore_get_buffer(key_slot);
    int pubkey_sz = keystore_get_size(key_slot);
    wc_Sha384 sha384_ctx;

    memset(hash, 0, SHA384_DIGEST_SIZE);
    if (!pubkey || (pubkey_sz < 0))
        return;

    (void)wc_InitSha384_ex(&sha384_ctx, NULL, WOLFBOOT_DEVID_HASH);
    wc_Sha384Update(&sha384_ctx, pubkey, (word32)pubkey_sz);
    wc_Sha384Final(&sha384_ctx, hash);
    wc_Sha384Free(&sha384_ctx);
}


/**
 * @brief Convert a 32-bit integer from little-endian to native byte order.
 *
 * This function converts a 32-bit integer from little-endian byte order to
 * the native byte order of the machine.
 *
 * @param val The 32-bit integer value in little-endian byte order.
 * @return The 32-bit integer value in native byte order.
 */
static inline uint32_t im2n(uint32_t val)
{
  return val;
}

/**
 * @brief Get the size of the image from the image header.
 *
 * This function retrieves the size of the image from the image header.
 *
 * @param image The pointer to the image header.
 * @return The size of the image in bytes.
 */
uint32_t wolfBoot_image_size(uint8_t *image)
{
    uint32_t *size = (uint32_t *)(image + sizeof (uint32_t));
    return im2n(*size);
}

/**
 * @brief Open an image using the provided image address.
 *
 * This function opens an image using the provided image address and initializes
 * the wolfBoot_image structure.
 * Note that this function initializes the members of the wolfBoot_image structure
 * but does not initialize the structure itself.  It is expected that the wolfBoot_image
 * struct is memset to 0 before being passed in, with img->hdr optionally set.
 *
 * @param img The pointer to the wolfBoot_image structure to be initialized.
 * @param image The pointer to the image address.
 * @return 0 on success, -1 on error.
 */
int wolfBoot_open_image_address(struct wolfBoot_image *img, uint8_t *image)
{
    uint32_t *magic = (uint32_t *)(image);
    if (*magic != WOLFBOOT_MAGIC) {
        wolfBoot_printf("Partition %d header magic 0x%08x invalid at %p\n",
            img->part, (unsigned int)*magic, img->hdr);
        return -1;
    }
    img->fw_size = wolfBoot_image_size(image);

    if (img->fw_size > (WOLFBOOT_PARTITION_SIZE - IMAGE_HEADER_SIZE)) {
        wolfBoot_printf("Image size %u > max %u\n",
            (unsigned int)img->fw_size,
            (unsigned int)(WOLFBOOT_PARTITION_SIZE - IMAGE_HEADER_SIZE));
        img->fw_size = WOLFBOOT_PARTITION_SIZE - IMAGE_HEADER_SIZE;
        return -1;
    }
    if (!img->hdr_ok) {
        img->hdr = image;
    }
    img->trailer = img->hdr + WOLFBOOT_PARTITION_SIZE;
    img->hdr_ok = 1;
    img->fw_base = img->hdr + IMAGE_HEADER_SIZE;

    wolfBoot_printf("%s partition: %p (sz %d, ver 0x%x, type 0x%x)\n",
        (img->part == PART_BOOT) ? "Boot" : "Update",
        img->hdr, (unsigned int)img->fw_size,
        wolfBoot_get_blob_version(image),
        wolfBoot_get_blob_type(image));

    return 0;
}



/**
 * @brief Open an image in a specified partition.
 *
 * This function opens an image in the specified partition and initializes
 * the wolfBoot_image structure.
 *
 * @param img The pointer to the wolfBoot_image structure to be initialized.
 * @param part The partition ID (PART_BOOT, PART_UPDATE, PART_SWAP, etc.).
 * @return 0 on success, -1 on error.
 */
int wolfBoot_open_image(struct wolfBoot_image *img, uint8_t part)
{
    int ret;
    uint8_t *image;
    if (!img)
        return -1;


    memset(img, 0, sizeof(struct wolfBoot_image));
    img->part = part;
    if (part == PART_SWAP) {
        img->hdr = (void*)WOLFBOOT_PARTITION_SWAP_ADDRESS;
        img->hdr_ok = 1;
        img->fw_base = img->hdr;
        img->fw_size = WOLFBOOT_SECTOR_SIZE;
        return 0;
    }
    if (part == PART_BOOT) {
        img->hdr = (void*)WOLFBOOT_PARTITION_BOOT_ADDRESS;
    }
    else if (part == PART_UPDATE) {
        img->hdr = (void*)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
    }
    else {
        return -1;
    }

    /* fetch header address
     * (or copy from external device to a local buffer via fetch_hdr_cpy)
     */
    if (PART_IS_EXT(img))
        image = fetch_hdr_cpy(img);
    else
        image = (uint8_t *)img->hdr;
    img->hdr_ok = 1;
    ret = wolfBoot_open_image_address(img, image);
    if (ret != 0)
        img->hdr_ok = 0;
    return ret;
}





/**
 * @brief Verify the integrity of the image using the stored SHA hash.
 *
 * This function verifies the integrity of the image by calculating its SHA hash
 * and comparing it with the stored hash.
 *
 * @param img The pointer to the wolfBoot_image structure representing the image.
 * @return 0 on success, -1 on error.
 */
int wolfBoot_verify_integrity(struct wolfBoot_image *img)
{
    uint8_t *stored_sha;
    uint16_t stored_sha_len;
    stored_sha_len = get_header(img, WOLFBOOT_SHA_HDR, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    if (image_hash(img, digest) != 0)
        return -1;
    if (image_CT_compare(digest, stored_sha, stored_sha_len) != 0)
        return -1;
    img->sha_ok = 1;
    img->sha_hash = stored_sha;
    return 0;
}


int wolfBoot_verify_authenticity(struct wolfBoot_image *img)
{
    uint8_t *stored_signature;
    uint16_t stored_signature_size;
    uint8_t *pubkey_hint;
    uint16_t pubkey_hint_size;
    uint8_t *image_type_buf;
    uint16_t image_type;
    uint16_t image_type_size;
    uint32_t key_mask = 0U;
    uint32_t image_part = 1U;
    int key_slot;

    stored_signature_size = get_header(img, HDR_SIGNATURE, &stored_signature);
    pubkey_hint_size = get_header(img, HDR_PUBKEY, &pubkey_hint);
    if (pubkey_hint_size == WOLFBOOT_SHA_DIGEST_SIZE) {
        key_slot = keyslot_id_by_sha(pubkey_hint);
        if (key_slot < 0) {
            return -1; /* Key was not found */
        }

    }
    else {
        return -1; /* Invalid hash size for public key hint */
    }
    image_type_size = get_header(img, HDR_IMG_TYPE, &image_type_buf);
    if (image_type_size != sizeof(uint16_t))
        return -1;
    image_type = (uint16_t)(image_type_buf[0] + (image_type_buf[1] << 8));
    if ((image_type & HDR_IMG_TYPE_AUTH_MASK) != HDR_IMG_TYPE_AUTH)
        return -1;
    if ((img->sha_hash == NULL) || (img->sha_ok != 1U)) {
        if (wolfBoot_verify_integrity(img) != 0)
            return -1;
    }
    image_part = image_type & HDR_IMG_TYPE_PART_MASK;
    key_mask = keystore_get_mask(key_slot);

    /* Check if the key permission mask matches the current partition id */
    if (((1U << image_part) & key_mask) != (1U << image_part)) {
        return -1; /* Key not allowed to verify this partition id */
    }

    CONFIRM_MASK_VALID(image_part, key_mask);


    if (stored_signature_size == 0 || stored_signature == NULL) {
        return -1;
    }
    if (stored_signature_size != ECC_IMAGE_SIGNATURE_SIZE)
        return -1;

    /* wolfBoot_verify_signature_ecc() does not return the result directly.
     * A call to wolfBoot_image_confirm_signature_ok() is required in order to
     * confirm that the signature verification is OK.
     *
     * only a call to wolfBoot_image_confirm_signature_ok() sets
     * img->signature_ok to 1.
     *
     */
    wolfBoot_verify_signature_primary(key_slot, img, stored_signature);

#define SIG_OK(imgp) ((imgp)->signature_ok == 1)

    if (SIG_OK(img)) {
        return 0;
    }
    return -2;
#undef SIG_OK
}

/**
 * @brief Peek at the content of the image at a specific offset.
 *
 * This function allows peeking at the content of the image at a specific offset
 * without modifying the image.
 *
 * @param img The pointer to the wolfBoot_image structure representing the image.
 * @param offset The offset within the image to peek at.
 * @param sz Optional pointer to store the size of the peeked data.
 * @return The pointer to the peeked data, or NULL if the offset is out of bounds.
 */


/* Compare fixed-size key hints without early exit to avoid leaking hash prefix
 * matches through lookup timing. */
static int keyslot_CT_hint_matches(const uint8_t *expected,
    const uint8_t *actual)
{
    volatile uint8_t diff = 0;
    uint32_t i;

    for (i = 0; i < WOLFBOOT_SHA_DIGEST_SIZE; i++) {
        diff |= expected[i] ^ actual[i];
    }

    return diff == 0;
}

/**
 * @brief Get the key slot ID by SHA hash.
 *
 * This function retrieves the key slot ID from the keystore that matches the
 * provided SHA hash.
 *
 * @param hint The SHA hash of the public key to search for.
 * @return The key slot ID if found, -1 if the key was not found.
 */
int keyslot_id_by_sha(const uint8_t *hint)
{
    int id;
    int match_id = -1;

    for (id = 0; id < keystore_num_pubkeys(); id++) {
        int match;
        key_hash(id, digest);
        match = keyslot_CT_hint_matches(digest, hint);
        if (match && (match_id < 0))
            match_id = id;
    }
    return match_id;
}
