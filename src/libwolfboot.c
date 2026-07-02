/* libwolfboot.c
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
 * @file libwolfboot.c
 *
 * @brief wolfBoot library implementation.
 *
 * This file contains the implementation of the wolfBoot library.
 */
#include <stdint.h>

#include "hal.h"
#include "wolfboot/wolfboot.h"
#include "image.h"
#include "printf.h"

/**
 * @def unit_dbg
 * @brief Empty macro for unit_dbg in non-test builds.
 *
 * Empty macro for unit_dbg in non-test builds.
 */
#   define unit_dbg(...) do{}while(0)

#ifndef TRAILER_SKIP
/**
 * @def TRAILER_SKIP
 * @brief Trailer skip value for partition encryption.
 *
 * Trailer skip value for partition encryption, defaults to 0 if not defined.
 */
#   define TRAILER_SKIP 0
#endif

#include <stddef.h> /* for size_t */


    #define wolfBoot_initialize_encryption() (0)



    #define ENCRYPT_TMP_SECRET_OFFSET (WOLFBOOT_PARTITION_SIZE - (TRAILER_SKIP))
    #define SECTOR_FLAGS_SIZE (WOLFBOOT_SECTOR_SIZE - (4 + 1))
    /* MAGIC (4B) + PART_FLAG (1B) */


#ifndef NULL
#   define NULL (void *)0
#endif

#ifndef NVM_CACHE_SIZE
#define NVM_CACHE_SIZE WOLFBOOT_SECTOR_SIZE
#endif




#define WOLFSSL_MISC_INCLUDED /* allow misc.c code to be inlined */
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfcrypt/src/misc.c> /* for ByteReverseWord32 */

static const uint32_t wolfboot_magic_trail = WOLFBOOT_MAGIC_TRAIL;

/* Top addresses for FLAGS field
 *  - PART_BOOT_ENDFLAGS = top of flags for BOOT partition
 *  - PART_UPDATE_ENDFLAGS = top of flags for UPDATE_PARTITION
 */

#ifndef PART_BOOT_ENDFLAGS
#define PART_BOOT_ENDFLAGS   (WOLFBOOT_PARTITION_BOOT_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#endif
#define FLAGS_BOOT_EXT() PARTN_IS_EXT(PART_BOOT)

/* FLAGS are at the end of each partition */
#define PART_UPDATE_ENDFLAGS (WOLFBOOT_PARTITION_UPDATE_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#define FLAGS_UPDATE_EXT() PARTN_IS_EXT(PART_UPDATE)

#   define trailer_write(part,addr, val) hal_flash_write(addr, (void *)&val, 1)
#   define partition_magic_write(part,addr) hal_flash_write(addr,  (void*)&wolfboot_magic_trail, sizeof(uint32_t));

/**
 * @brief Get the trailer at a specific address
 *
 * This function retrieves the trailer at a specific address in external or
 * internal flash
 *
 * @param[in] part Partition number.
 * @param[in] at Address offset.
 * @return Pointer to the trailer at the specified address.
 */
static uint8_t* RAMFUNCTION get_trailer_at(uint8_t part, uint32_t at)
{
    uint8_t *ret = NULL;
    uint32_t sel_sec = 0;

    if (part == PART_BOOT) {
        {
            /* only internal flash should be writeonce */
            ret = (void *)(PART_BOOT_ENDFLAGS -
                    (WOLFBOOT_SECTOR_SIZE * sel_sec + (sizeof(uint32_t) + at)));
        }
    }
    else if (part == PART_UPDATE) {
        {
            /* only internal flash should be writeonce */
            ret = (void *)(PART_UPDATE_ENDFLAGS -
                    (WOLFBOOT_SECTOR_SIZE * sel_sec + (sizeof(uint32_t) + at)));
        }
    }
    return ret;
}

/**
 * @brief Set the trailer at a specific address
 *
 * This function sets the trailer at a specific address in external or
 * internal flash.
 *
 * @param[in] part Partition number.
 * @param[in] at Address offset.
 * @param[in] val New value to set in the trailer.
 */
static void RAMFUNCTION set_trailer_at(uint8_t part, uint32_t at, uint8_t val)
{
    if (part == PART_BOOT) {
        {
            trailer_write(part, PART_BOOT_ENDFLAGS - (sizeof(uint32_t) + at), val);
        }
    }
    else if (part == PART_UPDATE) {
        {
            trailer_write(part, PART_UPDATE_ENDFLAGS - (sizeof(uint32_t) + at), val);
        }
    }
}

/**
 * @brief Set the partition magic trailer
 *
 * This function sets the partition magic trailer in external or internal flash.
 *
 * @param[in] part Partition number.
 */
static void RAMFUNCTION set_partition_magic(uint8_t part)
{
    if (part == PART_BOOT) {
        {
            partition_magic_write(part, PART_BOOT_ENDFLAGS - sizeof(uint32_t));
        }
    }
    else if (part == PART_UPDATE) {
        {
            partition_magic_write(part, PART_UPDATE_ENDFLAGS - sizeof(uint32_t));
        }
    }
}



/**
 * @brief Get the magic trailer of a partition.
 *
 * This function retrieves the magic trailer of a fixed partition.
 *
 * @param[in] part Partition number.
 * @return Pointer to the magic trailer of the partition.
 */
static uint32_t* RAMFUNCTION get_partition_magic(uint8_t part)
{
    return (uint32_t *)get_trailer_at(part, 0);
}

static uint8_t* RAMFUNCTION get_partition_state(uint8_t part)
{
    return (uint8_t *)get_trailer_at(part, 1);
}


static void RAMFUNCTION set_partition_state(uint8_t part, uint8_t val)
{
    set_trailer_at(part, 1, val);
}

/**
 * @brief Set the flags of an update sector.
 *
 * This function sets the flags of an update sector in a fixed partition.
 *
 * @param[in] pos Update sector position.
 * @param[in] val New flags value to set.
 * @return 0 on success, -1 on failure.
 */
static void RAMFUNCTION set_update_sector_flags(uint32_t pos, uint8_t val)
{
    set_trailer_at(PART_UPDATE, 2 + pos, val);
}

/**
 * @brief Get the flags of an update sector.
 *
 * This function retrieves the flags of an update sector in a fixed partition.
 *
 * @param[in] pos Update sector position.
 * @return Pointer to the flags of the update sector.
 */
static uint8_t* RAMFUNCTION get_update_sector_flags(uint32_t pos)
{
    return (uint8_t *)get_trailer_at(PART_UPDATE, 2 + pos);
}

/**
 * @brief Set the state of a partition.
 *
 * This function sets the state of a fixed partition.
 *
 * @param[in] part Partition number.
 * @param[in] newst New state value to set.
 * @return 0 on success, -1 on failure.
 */
int RAMFUNCTION wolfBoot_set_partition_state(uint8_t part, uint8_t newst)
{
    uint32_t *magic;
    uint8_t *state;
    if (part == PART_NONE)
        return -1;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        set_partition_magic(part);
    state = get_partition_state(part);
    if (*state != newst)
        set_partition_state(part, newst);
    return 0;
}

/**
 * @brief Set the flag for sector
 *
 * This function sets the sector flag for update partition.
 *
 * @param[in] sector Sector number.
 * @param[in] newflag Nibble (4-bits) for sector flag
 * @return 0 on success, -1 on failure.
 */
int RAMFUNCTION wolfBoot_set_update_sector_flag(uint16_t sector,
    uint8_t newflag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint8_t fl_value;
    uint32_t pos = sector >> 1;

    magic = get_partition_magic(PART_UPDATE);
    if (*magic != wolfboot_magic_trail)
        set_partition_magic(PART_UPDATE);

    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        fl_value = (*flags & 0xF0) | (newflag & 0x0F);
    else
        fl_value = ((newflag & 0x0F) << 4) | (*flags & 0x0F);
    if (fl_value != *flags)
        set_update_sector_flags(pos, fl_value);
    return 0;
}

/**
 * @brief Get the state of a partition.
 *
 * This function retrieves the state of a fixed partition.
 *
 * @param[in] part Partition number.
 * @param[out] st Pointer to store the partition state.
 * @return 0 on success, -1 on failure.
 */
int RAMFUNCTION wolfBoot_get_partition_state(uint8_t part, uint8_t *st)
{
    uint32_t *magic;
    uint8_t *state;
    if (part == PART_NONE)
        return -1;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    state = get_partition_state(part);
    *st = *state;
    return 0;
}

/**
 * @brief Get the flag for sector
 *
 * This function retrieves the sector flag for update partition.
 *
 * User may override this is function for cases where the update partition
 * flags are not at the end of partition
 *
 * @param[in] sector Sector number.
 * @param[out] flag Nibble (4-bits) for sector flags
 * @return 0 on success, -1 on failure.
 */
int wolfBoot_get_update_sector_flag(uint16_t sector, uint8_t *flag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint32_t pos = sector >> 1;
    magic = get_partition_magic(PART_UPDATE);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        *flag = *flags & 0x0F;
    else
        *flag = (*flags & 0xF0) >> 4;
    return 0;
}

/**
 * @brief Erase a partition.
 *
 * This function erases a partition.
 *
 * @param[in] part Partition number.
 */
void RAMFUNCTION wolfBoot_erase_partition(uint8_t part)
{
    uint32_t address = 0;
    int size = 0;

    switch (part) {
        case PART_BOOT:
            address = (uint32_t)WOLFBOOT_PARTITION_BOOT_ADDRESS;
            size = WOLFBOOT_PARTITION_SIZE;
            break;
        case PART_UPDATE:
            address = (uint32_t)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
            size = WOLFBOOT_PARTITION_SIZE;
            break;
        case PART_SWAP:
            address = (uint32_t)WOLFBOOT_PARTITION_SWAP_ADDRESS;
            size = WOLFBOOT_SECTOR_SIZE;
            break;
        default:
            break;
    }

    if (size > 0) {
        if (PARTN_IS_EXT(part)) {
            ext_flash_unlock();
            ext_flash_erase(address, size);
            ext_flash_lock();
        } else {
            hal_flash_erase(address, size);
        }
    }
}

/**
 * @brief Update trigger function.
 *
 * This function updates the boot partition state to "IMG_STATE_UPDATING".
 * If the FLAGS_HOME macro is defined, it erases the last sector of the boot
 * partition before updating the partition state. It also checks FLAGS_UPDATE_EXT
 * and calls the appropriate flash unlock and lock functions before
 * updating the partition state.
 */
void RAMFUNCTION wolfBoot_update_trigger(void)
{
    uint8_t st = IMG_STATE_UPDATING;
    uintptr_t lastSector = ((PART_UPDATE_ENDFLAGS - 1) / WOLFBOOT_SECTOR_SIZE) * WOLFBOOT_SECTOR_SIZE;

    /* erase the sector flags */
    if (FLAGS_UPDATE_EXT()) {
        ext_flash_unlock();
    } else {
        hal_flash_unlock();
    }

    /* NVM_FLASH_WRITEONCE needs erased flags since it selects the fresh
     * partition based on how many flags are non-erased
     * FLAGS_INVERT needs erased flags because the bin-assemble's fill byte may
     * not match what's in wolfBoot */
    if (FLAGS_UPDATE_EXT()) {
        ext_flash_erase(lastSector, WOLFBOOT_SECTOR_SIZE);
        wolfBoot_set_partition_state(PART_UPDATE, st);
    } else {
        hal_flash_erase(lastSector, WOLFBOOT_SECTOR_SIZE);
        wolfBoot_set_partition_state(PART_UPDATE, st);
    }

    if (FLAGS_UPDATE_EXT()) {
        ext_flash_lock();
    } else {
        hal_flash_lock();
    }
}

/**
 * @brief Success function.
 *
 * This function updates the boot partition state to "IMG_STATE_SUCCESS".
 * If the FLAGS_BOOT_EXT macro is defined, it calls the appropriate flash unlock
 * and lock functions before updating the partition state. If the EXT_ENCRYPTED
 * macro is defined, it calls wolfBoot_erase_encrypt_key function.
 */
void RAMFUNCTION wolfBoot_success(void)
{
    uint8_t st = IMG_STATE_SUCCESS;
    if (FLAGS_BOOT_EXT()) {
        ext_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        ext_flash_lock();
    } else {
        hal_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        hal_flash_lock();
    }
}

/**
 * @brief Find header function.
 *
 * This function searches for a specific header type in the given buffer.
 * It returns the length of the header and sets the 'ptr' parameter to the
 * position of the header if found.
 * @param haystack Pointer to the buffer to search for the header.
 * @param type The type of header to search for.
 * @param ptr Pointer to store the position of the header.
 *
 * @return uint16_t The length of the header found, or 0 if not found.
 *
 */
uint16_t wolfBoot_find_header(uint8_t *haystack, uint16_t type, uint8_t **ptr)
{
    uint8_t *p;
    uint16_t len, htype;
    uintptr_t p_addr, max_addr;

    *ptr = NULL;

    if (haystack == NULL) {
        unit_dbg("Illegal address (NULL)\n");
        return 0;
    }

    p_addr = (uintptr_t)haystack;
    if (p_addr < IMAGE_HEADER_OFFSET) {
        unit_dbg("Illegal address (too low)\n");
        return 0;
    }

    max_addr = p_addr - IMAGE_HEADER_OFFSET;
    if (max_addr > (UINTPTR_MAX - IMAGE_HEADER_SIZE)) {
        unit_dbg("Illegal address (overflow)\n");
        return 0;
    }
    max_addr += IMAGE_HEADER_SIZE;

    if (p_addr > max_addr) {
        unit_dbg("Illegal address (too high)\n");
        return 0;
    }

    while (p_addr < max_addr) {
        if ((max_addr - p_addr) < 4U) {
            break;
        }
        p = (uint8_t *)p_addr;
        htype = p[0] | (p[1] << 8);
        if (htype == 0) {
            unit_dbg("Explicit end of options reached\n");
            break;
        }
        /* skip unaligned half-words and padding bytes */
        if ((p[0] == HDR_PADDING) || ((p_addr & 0x01U) != 0U)) {
            p_addr++;
            continue;
        }

        len = p[2] | (p[3] << 8);
        /* check len */
        if ((4U + len) > (uint16_t)(IMAGE_HEADER_SIZE - IMAGE_HEADER_OFFSET)) {
            unit_dbg("This field is too large (bigger than the space available "
                     "in the current header)\n");
            unit_dbg("%u %u %u\n", (unsigned int)len,
                     (unsigned int)IMAGE_HEADER_SIZE,
                     (unsigned int)IMAGE_HEADER_OFFSET);
            break;
        }
        /* check max pointer */
        if ((max_addr - p_addr) < (uintptr_t)(4U + len)) {
            unit_dbg("This field is too large and would overflow the image "
                     "header\n");
            break;
        }

        if (htype == type) {
            /* found, return pointer to data portion */
            *ptr = (uint8_t *)(p_addr + 4U);
            return len;
        }
        p_addr += (uintptr_t)(4U + len);
    }
    return 0;
}


/**
 * @brief Convert little-endian to native-endian (uint32_t).
 *
 * This function converts a little-endian 32-bit value to the native-endian format.
 * It is used to handle endianness differences when reading data from memory.
 *
 * @param val The value to convert.
 *
 * @return The converted value.
 */
static inline uint32_t im2n(uint32_t val)
{
  return val;
}

/**
 * @brief Convert little-endian to native-endian (uint16_t).
 *
 * This function converts a little-endian 16-bit value to the native-endian format.
 * It is used to handle endianness differences when reading data from memory.
 *
 * @param val The value to convert.
 * @return uint16_t The converted value.

 */
static inline uint16_t im2ns(uint16_t val)
{
  return val;
}



/**
 * @brief Get blob version.
 *
 * This function retrieves the version number from the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the version field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The version number of the blob, or 0 if the blob is invalid.
 *
 */
uint32_t wolfBoot_get_blob_version(uint8_t *blob)
{
    uint32_t *volatile version_field = NULL;
    uint32_t *magic = NULL;
    uint8_t *img_bin = blob;
    if (blob == NULL)
        return 0;
    magic = (uint32_t *)img_bin;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(img_bin + IMAGE_HEADER_OFFSET, HDR_VERSION,
            (void *)&version_field) != sizeof(uint32_t))
        return 0;
    if (version_field)
        return im2n(*version_field);
    return 0;
}

/**
 * @brief Get blob type.
 *
 * This function retrieves the type of the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the type field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The type of the blob, or 0 if the blob is invalid.
 */
uint16_t wolfBoot_get_blob_type(uint8_t *blob)
{
    uint16_t *volatile type_field = NULL;
    uint32_t *magic = NULL;
    uint8_t *img_bin = blob;
    magic = (uint32_t *)img_bin;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(img_bin + IMAGE_HEADER_OFFSET, HDR_IMG_TYPE,
            (void *)&type_field) != sizeof(uint16_t))
        return 0;
    if (type_field)
        return im2ns(*type_field);

    return 0;
}

/**
 * @brief Get blob difference base version.
 *
 * This function retrieves the difference base version from the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the difference base field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The difference base version of the blob, or 0 if not found
 * or the blob is invalid.
 *
 */



/**
 * @brief Get image pointer from a partition.
 *
 * This function retrieves the pointer to the image in the specified partition.
 * It handles both regular and extended partitions by reading from memory or
 * external flash if needed.
 *
 * @param part The partition to get the image pointer for.
 *
 * @return uint8_t* Pointer to the image in the specified partition, or
 * NULL if the partition is invalid or empty.
 *
 */
static uint8_t* wolfBoot_get_image_from_part(uint8_t part)
{
    uint8_t *image = (uint8_t *)0x00000000; /* default to 0x0 base */

    if (part == PART_BOOT) {
        image = (uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS;
    }
    else if (part == PART_UPDATE) {
        image = (uint8_t *)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
    }

    return image;
}


/**
 * @brief Get image version for a partition.
 *
 * This function retrieves the version number of the image in the specified
 * partition. It uses the 'wolfBoot_get_blob_version' function to extract the
 * version from the image blob.
 *
 * @param part The partition to get the image version for.
 *
 * @return The version number of the image in the partition,
 * or 0 if the partition is invalid or empty.
 *
 */

uint32_t wolfBoot_get_image_version(uint8_t part)
{
    /* Don't check image against NULL to allow using address 0x00000000 */
    return wolfBoot_get_blob_version(wolfBoot_get_image_from_part(part));
}

/**
 * @brief Get difference base version for a partition.
 *
 * This function retrieves the difference base version from the image in the
 * specified partition. It uses the 'wolfBoot_get_blob_diffbase_version'
 * function to extract the difference base version from the image blob.
 *
 * @param part The partition to get the difference base version for.
 *
 * @return The difference base version of the image in the partition, or
 * 0 if not found or the partition is invalid or empty.
 *
 */

/**
 * @brief Get image type for a partition.
 *
 * This function retrieves the image type from the image in the specified
 * partition. It uses the 'wolfBoot_get_blob_type' function to extract the image
 * type from the image blob.
 *
 * @param part The partition to get the image type for.
 *
 * @return uint16_t The image type of the image in the partition, or
 * 0 if the partition is invalid or empty.
 *
 */
uint16_t wolfBoot_get_image_type(uint8_t part)
{
    uint8_t *image = wolfBoot_get_image_from_part(part);
    if (image) {
        return wolfBoot_get_blob_type(image);
    }
    return 0;
}



