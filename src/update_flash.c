/* update_flash.c
 *
 * Implementation for Flash based updater
 *
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

#include <string.h>
#include "loader.h"
#include "image.h"
#include "hal.h"
#include "hooks.h"
#include "spi_flash.h"
#include "target.h"
#include "wolfboot/wolfboot.h"

#include "delta.h"
#include "printf.h"
static void wolfBoot_zeroize(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len-- > 0) {
        *p++ = 0;
    }
}

static int wolfBoot_local_constant_compare(const uint8_t* a, const uint8_t* b,
    uint32_t len)
{
    uint32_t i;
    volatile uint8_t diff = 0;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff;
}




extern unsigned int _start_text;
static volatile const uint32_t __attribute__((used)) wolfboot_version = WOLFBOOT_VERSION;


static void RAMFUNCTION wolfBoot_erase_bootloader(uint32_t len)
{
    (void)len;
    len = WOLFBOOT_PARTITION_BOOT_ADDRESS - ARCH_FLASH_OFFSET;
    hal_flash_erase(ARCH_FLASH_OFFSET, len);
}

#include <string.h>


static void RAMFUNCTION wolfBoot_self_update(struct wolfBoot_image *src)
{
    uintptr_t pos = 0;
    uintptr_t src_offset = IMAGE_HEADER_SIZE;
    uintptr_t start_text = (uintptr_t)&_start_text; /* save off before erase */

    hal_flash_unlock();
    wolfBoot_erase_bootloader(src->fw_size);
    {
        while (pos < src->fw_size) {
            if (src_offset + pos < (src->fw_size + IMAGE_HEADER_SIZE + FLASHBUFFER_SIZE))  {
                uint8_t *orig = (uint8_t*)(src->hdr + src_offset + pos);
                hal_flash_write(pos + start_text, orig, FLASHBUFFER_SIZE);
            }
            pos += FLASHBUFFER_SIZE;
        }
    }


    hal_flash_lock();
    arch_reboot();
}

void RAMFUNCTION wolfBoot_check_self_update(void)
{
    uint8_t st;
    struct wolfBoot_image update;

    /* Check for self update in the UPDATE partition */
    if ((wolfBoot_get_partition_state(PART_UPDATE, &st) == 0) && (st == IMG_STATE_UPDATING) &&
            (wolfBoot_open_image(&update, PART_UPDATE) == 0) &&
            wolfBoot_get_image_type(PART_UPDATE) == (HDR_IMG_TYPE_WOLFBOOT | HDR_IMG_TYPE_AUTH)) {
        uint32_t update_version = wolfBoot_update_firmware_version();
        if (update_version <= wolfboot_version) {
            hal_flash_unlock();
            wolfBoot_erase_partition(PART_UPDATE);
            hal_flash_lock();
            return;
        }
        if (wolfBoot_verify_integrity(&update) < 0)
            return;
        if (wolfBoot_verify_authenticity(&update) < 0)
            return;
        PART_SANITY_CHECK(&update);
        wolfBoot_self_update(&update);
    }
}

/* The swap-based update machinery (wolfBoot_copy_sector, wolfBoot_update, etc.)
 * is not used in monolithic self-update mode. */

static int RAMFUNCTION wolfBoot_copy_sector(struct wolfBoot_image *src,
    struct wolfBoot_image *dst, uint32_t sector)
{
    int ret = 0;
    uint32_t pos = 0;
    uint32_t src_sector_offset = (sector * WOLFBOOT_SECTOR_SIZE);
    uint32_t dst_sector_offset = src_sector_offset;

    if (src == dst)
        return 0;

    wolfBoot_printf("Copy sector %d (part %d->%d)\n",
        sector, src->part, dst->part);

    if (src->part == PART_SWAP)
        src_sector_offset = 0;
    if (dst->part == PART_SWAP)
        dst_sector_offset = 0;


    wb_flash_erase(dst, dst_sector_offset, WOLFBOOT_SECTOR_SIZE);
    while (pos < WOLFBOOT_SECTOR_SIZE) {
        if (src_sector_offset + pos < (src->fw_size + IMAGE_HEADER_SIZE +
            FLASHBUFFER_SIZE))  {
            uint8_t *orig = (uint8_t*)(src->hdr + src_sector_offset + pos);
            wb_flash_write(dst, dst_sector_offset + pos, orig, FLASHBUFFER_SIZE);
        }
        pos += FLASHBUFFER_SIZE;
    }
    ret = pos;
    return ret;
}

#define wolfBoot_backup_last_boot_sector(sec) wolfBoot_copy_sector(boot, swap, sec)


#   define TRAILER_OFFSET_WORDS 0

/**
 * @brief Performs the final swap and erase operations during a secure update,
 * ensuring that if power is lost during the update, the process can be resumed
 * on next boot. Not supported with CUSTOM_PARTITION_TRAILER
 *
 * This function handles the final phase of the three-way swap update process.
 * It ensures that the update is atomic and power-fail safe by:
 * 1. Saving the sector at tmpBootPos (staging sector) to the swap area
 * 2. Setting a magic trailer value to mark the swap as in progress
 * 3. Erasing the last sector(s) of the boot partition (where partition state is stored)
 * 4. Restoring the saved staging sector from swap back to boot
 * 5. Setting the boot partition state to TESTING
 * 6. Erasing the last sector(s) of the update partition
 *
 * The staging sector (tmpBootPos) is positioned right before the final sectors
 * that will be erased. This sector is preserved and used to store a magic trailer
 * that indicates a swap operation is in progress.
 *
 * The function can be called in two modes:
 * - Normal mode (resume=0): Initiates the swap and erase process
 * - Resume mode (resume=1): Checks if a swap was interrupted and completes it
 *
 * @param resume If 1, checks for interrupted swap and resumes it; if 0, starts
 * new swap
 * @return 0 on success, negative value if no swap needed or on error
 */
static int RAMFUNCTION wolfBoot_swap_and_final_erase(int resume)
{
    struct wolfBoot_image boot[1];
    struct wolfBoot_image update[1];
    struct wolfBoot_image swap[1];
    uint8_t updateState = IMG_STATE_NEW;
    int eraseLen = (WOLFBOOT_SECTOR_SIZE
    );
    int swapDone = 0;
    /* Calculate position of staging sector - just before the final sectors
     * that store partition state */
    uintptr_t tmpBootPos = WOLFBOOT_PARTITION_SIZE - eraseLen -
        WOLFBOOT_SECTOR_SIZE;
    uint32_t tmpBuffer[TRAILER_OFFSET_WORDS + 1];
    int ret = 0;

    /* open partitions (ignore failure) */
    wolfBoot_open_image(boot, PART_BOOT);
    wolfBoot_open_image(update, PART_UPDATE);
    wolfBoot_open_image(swap, PART_SWAP);
    wolfBoot_get_partition_state(PART_UPDATE, &updateState);

    /* Read the trailer from the staging sector to check if we're resuming an
     * interrupted operation */
#if defined(EXT_FLASH) && PARTN_IS_EXT(PART_BOOT)
    ext_flash_read((uintptr_t)(boot->hdr + tmpBootPos), (void*)tmpBuffer,
        sizeof(tmpBuffer));
#else
    memcpy(tmpBuffer, boot->hdr + tmpBootPos, sizeof(tmpBuffer));
#endif

    /* Check if the magic trailer exists - indicates an interrupted swap
     * operation */
    /* final swap and erase flag is WOLFBOOT_MAGIC_TRAIL */
    if (tmpBuffer[TRAILER_OFFSET_WORDS] == WOLFBOOT_MAGIC_TRAIL) {
        swapDone = 1;
    }
    /* If we're in resume mode but no swap was in progress, return */
    if ((resume == 1) && (swapDone == 0) &&
        (updateState != IMG_STATE_FINAL_FLAGS)
    ) {
        return -1;
    }

    hal_flash_unlock();

    /* If update state isn't set to FINAL_FLAGS, this is the first run of the function */
    /* IMG_STATE_FINAL_FLAGS allows re-entry without blowing away swap */
    if (updateState != IMG_STATE_FINAL_FLAGS) {
        /* First, backup the staging sector (sector at tmpBootPos) into swap partition */
        /* This sector will be modified with the magic trailer, so we need to preserve it */
        wolfBoot_backup_last_boot_sector(tmpBootPos / WOLFBOOT_SECTOR_SIZE);
        wolfBoot_printf("Copied boot sector to swap\n");
        /* Mark update as being in final swap phase to allow resumption if power fails */
        wolfBoot_set_partition_state(PART_UPDATE, IMG_STATE_FINAL_FLAGS);
    }
    /* Erase the last sector(s) of boot partition (where partition state is stored) */
    wb_flash_erase(boot, WOLFBOOT_PARTITION_SIZE - eraseLen, eraseLen);

    /* Restore the original contents of the staging sector (with the magic trailer if encrypted) */
    if (tmpBootPos < boot->fw_size + IMAGE_HEADER_SIZE) {
        wolfBoot_printf("Restoring last boot sector from swap\n");
        wolfBoot_copy_sector(swap, boot, tmpBootPos / WOLFBOOT_SECTOR_SIZE);
    }
    else {
        wb_flash_erase(boot, tmpBootPos, WOLFBOOT_SECTOR_SIZE);
    }

    /* Mark boot partition as TESTING - this tells bootloader to fallback if update fails */
    wolfBoot_set_partition_state(PART_BOOT, IMG_STATE_TESTING);

    /* Erase the last sector(s) of update partition */
    /* This resets the update partition state to IMG_STATE_NEW */
    wb_flash_erase(update, WOLFBOOT_PARTITION_SIZE - eraseLen, eraseLen);

    hal_flash_lock();

    wolfBoot_zeroize(tmpBuffer, sizeof(tmpBuffer));
    (void)ret;
    return 0;
}




/* Max firmware size: partition must hold header + fw + trailer sector(s) */
    #define MAX_UPDATE_SIZE (size_t)((WOLFBOOT_PARTITION_SIZE -  IMAGE_HEADER_SIZE - WOLFBOOT_SECTOR_SIZE))
static uint32_t wolfBoot_get_total_size(struct wolfBoot_image* boot,
    struct wolfBoot_image* update)
{
    uint32_t total_size = 0;

    /* Use biggest size for the swap */
    total_size = boot->fw_size + IMAGE_HEADER_SIZE;
    if ((update->fw_size + IMAGE_HEADER_SIZE) > total_size)
        total_size = update->fw_size + IMAGE_HEADER_SIZE;

    return total_size;
}

static int RAMFUNCTION wolfBoot_update(int fallback_allowed)
{
    uint32_t total_size = 0;
    const uint32_t sector_size = WOLFBOOT_SECTOR_SIZE;
    uint32_t sector = 0;
    int ret = 0;
    /* we need to pre-set flag to SECT_FLAG_NEW in case magic hasn't been set
     * on the update partition as part of the delta update direction check. if
     * magic has not been set flag will have an un-determined value when we go
     * to check it */
    uint8_t flag = SECT_FLAG_NEW;
    struct wolfBoot_image boot, update;
    struct wolfBoot_image swap;
    uint16_t update_type;
    uint32_t fw_size;
    uint32_t size;
    int fallback_image = 0;
    int rollback_needed = 0;
    int bootStateRet = -1;
    uint8_t bootState = 0;
    uint32_t cur_ver, upd_ver;

    wolfBoot_printf("Starting Update (fallback allowed %d)\n",
        fallback_allowed);

    /* No Safety check on open: we might be in the middle of a broken update */
    {
        int update_open;
        update_open = wolfBoot_open_image(&update, PART_UPDATE);
        if (update_open < 0)
            return -1;
        wolfBoot_open_image(&boot, PART_BOOT);
        wolfBoot_open_image(&swap, PART_SWAP);

    }

    /* get total size */
    total_size = wolfBoot_get_total_size(&boot, &update);
    if (total_size <= IMAGE_HEADER_SIZE) {
        wolfBoot_printf("Image total size %u invalid!\n", total_size);
        return -1;
    }
    /* In case this is a new update, do the required
     * checks on the firmware update
     * before starting the swap
     */
    update_type = wolfBoot_get_image_type(PART_UPDATE);

    cur_ver = wolfBoot_current_firmware_version();
    upd_ver = wolfBoot_update_firmware_version();
    bootStateRet = wolfBoot_get_partition_state(PART_BOOT, &bootState);
    if ((bootStateRet == 0) && (bootState == IMG_STATE_TESTING) &&
        (fallback_allowed != 0) && (cur_ver >= upd_ver)) {
        rollback_needed = 1;
    }

    wolfBoot_get_update_sector_flag(0, &flag);
    /* Check the first sector to detect interrupted update */
    if (flag == SECT_FLAG_NEW) {
        if (((update_type & HDR_IMG_TYPE_PART_MASK) != HDR_IMG_TYPE_APP) ||
            ((update_type & HDR_IMG_TYPE_AUTH_MASK) != HDR_IMG_TYPE_AUTH)) {
            wolfBoot_printf("Update type invalid 0x%x!=0x%x\n",
                update_type, HDR_IMG_TYPE_AUTH);
            return -1;
        }
        if (update.fw_size > MAX_UPDATE_SIZE - 1) {
            wolfBoot_printf("Invalid update size %u\n", update.fw_size);
            return -1;
        }
        if (!fallback_image) {
            if (!update.hdr_ok
                    || (wolfBoot_verify_integrity(&update) < 0)
                    || (wolfBoot_verify_authenticity(&update) < 0)) {
                wolfBoot_printf("Update verify failed: Hdr %d, Hash %d, Sig %d\n",
                    update.hdr_ok, update.sha_ok, update.signature_ok);
                return -1;
            }
        } else {
            if (!update.hdr_ok
                    || (wolfBoot_verify_integrity(&update) < 0)
                    || (wolfBoot_verify_authenticity(&update) < 0)) {
                wolfBoot_printf("Update verify failed: Hdr %d, Hash %d, Sig %d\n",
                    update.hdr_ok, update.sha_ok, update.signature_ok);
                return -1;
            }
        }
        PART_SANITY_CHECK(&update);


        wolfBoot_printf("Versions: Current 0x%x, Update 0x%x\n",
            cur_ver, upd_ver);

        {
            uint32_t fb_ok = (fallback_allowed == 1);
            VERIFY_VERSION_ALLOWED(fb_ok);
            (void)fb_ok;
        }
        if ((fallback_allowed == 0) && (cur_ver >= upd_ver)) {
            wolfBoot_printf("Update version not allowed\n");
            return -1;
        }
    }


    /* Interruptible swap */

    hal_flash_unlock();
    /* Interruptible swap
     * The status is saved in the sector flags of the update partition.
     * If something goes wrong, the operation will be resumed upon reboot.
     */
    while ((sector * sector_size) < total_size) {
        flag = SECT_FLAG_NEW;
        wolfBoot_get_update_sector_flag(sector, &flag);
        switch (flag) {
            case SECT_FLAG_NEW:
               flag = SECT_FLAG_SWAPPING;
               wolfBoot_copy_sector(&update, &swap, sector);
               if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
                   wolfBoot_set_update_sector_flag(sector, flag);
                /* FALL THROUGH */
            case SECT_FLAG_SWAPPING:
                size = total_size - (sector * sector_size);
                if (size > sector_size)
                    size = sector_size;
                flag = SECT_FLAG_BACKUP;
                {
                    wolfBoot_copy_sector(&boot, &update, sector);
                }
                if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
                    wolfBoot_set_update_sector_flag(sector, flag);
                /* FALL THROUGH */
            case SECT_FLAG_BACKUP:
                size = total_size - (sector * sector_size);
                if (size > sector_size)
                    size = sector_size;
                flag = SECT_FLAG_UPDATED;
                wolfBoot_copy_sector(&swap, &boot, sector);
                if (((sector + 1) * sector_size) < WOLFBOOT_PARTITION_SIZE)
                    wolfBoot_set_update_sector_flag(sector, flag);
                break;
            case SECT_FLAG_UPDATED:
                /* FALL THROUGH */
            default:
                break;
        }
        sector++;

        /* headers that can be in different positions depending on when the
         * power fails are now in a known state, re-read and swap fw_size
         * because the locations are correct but the metadata is now swapped
         * also recalculate total_size since it could be invalid */
        if (sector == 1) {
            wolfBoot_open_image(&boot, PART_BOOT);
            wolfBoot_open_image(&update, PART_UPDATE);

            /* swap the fw_size since they're now swapped */
            fw_size = boot.fw_size;
            boot.fw_size = update.fw_size;
            update.fw_size = fw_size;

            /* get total size */
            total_size = wolfBoot_get_total_size(&boot, &update);
        }
    }

    /* Erase remainder of partition */
    /* calculate number of remaining bytes */
    /* reserve 1 sector for status (2 sectors for NV write once) */
    size = WOLFBOOT_PARTITION_SIZE - (sector * sector_size) - sector_size;

    wolfBoot_printf("Erasing remainder of partition (%d sectors)...\n",
        size/sector_size);

    /* Iterate over every remaining sector and erase individually. */
    /* This loop is smallest code size */
    while ((sector * sector_size) < WOLFBOOT_PARTITION_SIZE -
        sector_size
    ) {
        wb_flash_erase(&boot, sector * sector_size, sector_size);
        wb_flash_erase(&update, sector * sector_size, sector_size);
        sector++;
    }

    /* encryption key was not erased, will be erased by success */
    hal_flash_lock();

    /* start re-entrant final erase, return code is only for resumption in
     * wolfBoot_start */
    ret = wolfBoot_swap_and_final_erase(0);
    if (ret != 0)
        return ret;
    if (rollback_needed) {
        hal_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, IMG_STATE_SUCCESS);
        hal_flash_lock();
    }

    return ret;
}

void RAMFUNCTION wolfBoot_start(void)
{
    int bootRet;
    int updateRet;
    int resumedFinalErase;
    uint8_t bootState;
    uint8_t updateState;
    struct wolfBoot_image boot;
    BENCHMARK_DECLARE();


    wolfBoot_check_self_update();




    bootRet =   wolfBoot_get_partition_state(PART_BOOT, &bootState);
    updateRet = wolfBoot_get_partition_state(PART_UPDATE, &updateState);


    /* resume the final erase in case the power failed before it finished */
    resumedFinalErase = wolfBoot_swap_and_final_erase(1);
    if ((resumedFinalErase != 0) ||
        ((bootRet == 0) && (bootState == IMG_STATE_TESTING)))
    {
        /* Check if the BOOT partition is still in TESTING,
         * to trigger fallback.
         */
        if ((bootRet == 0) && (bootState == IMG_STATE_TESTING)) {
            if (updateRet != 0) {
                hal_flash_unlock();
                wolfBoot_set_partition_state(PART_UPDATE, IMG_STATE_UPDATING);
                hal_flash_lock();
                updateRet = 0;
                updateState = IMG_STATE_UPDATING;
            }
            wolfBoot_update(1);
        }

        /* Check for new updates in the UPDATE partition or if we were
         * interrupted during the flags setting */
        else if ((updateRet == 0) && (updateState == IMG_STATE_UPDATING)) {
            /* Check for new updates in the UPDATE partition */
            wolfBoot_update(0);
        }
    }


    bootRet = wolfBoot_open_image(&boot, PART_BOOT);
    wolfBoot_printf("Booting version: 0x%x\n",
        wolfBoot_get_blob_version(boot.hdr));

    if (bootRet >= 0) {
        wolfBoot_printf("Checking integrity...");
        BENCHMARK_START();
        bootRet = wolfBoot_verify_integrity(&boot);
        if (bootRet >= 0)
            BENCHMARK_END("done");
    }
    if (bootRet >= 0) {
        wolfBoot_printf("Verifying signature...");
        BENCHMARK_START();
        bootRet = wolfBoot_verify_authenticity(&boot);
        if (bootRet >= 0)
            BENCHMARK_END("done");
    }
    if (bootRet < 0) {
        wolfBoot_printf("Boot failed: Hdr %d, Hash %d, Sig %d\n",
            boot.hdr_ok, boot.sha_ok, boot.signature_ok);
        wolfBoot_printf("Trying emergency update\n");
        if (likely(wolfBoot_update(1) < 0)) {
            /* panic: no boot option available. */
            wolfBoot_printf("Boot failed! No boot option available!\n");
            wolfBoot_panic();
        } else {
            /* Emergency update successful, try to re-open boot image */
            if (unlikely(((wolfBoot_open_image(&boot, PART_BOOT) < 0) ||
                    (wolfBoot_verify_integrity(&boot) < 0)  ||
                    (wolfBoot_verify_authenticity(&boot) < 0)
                    ))) {
                wolfBoot_printf("Boot (try 2) failed: Hdr %d, Hash %d, Sig %d\n",
                    boot.hdr_ok, boot.sha_ok, boot.signature_ok);
                /* panic: something went wrong after the emergency update */
                wolfBoot_panic();
            }
        }
    }
    if ((boot.hdr_ok != 1U) || (boot.sha_ok != 1U) ||
        (boot.signature_ok != 1U)) {
        wolfBoot_panic();
    }
    PART_SANITY_CHECK(&boot);






    if (hal_flash_protect(WOLFBOOT_ORIGIN, BOOTLOADER_PARTITION_SIZE) < 0) {
        wolfBoot_printf("Error protecting bootloader flash region\n");
        wolfBoot_panic();
    }
    hal_prepare_boot();

    PART_SANITY_CHECK(&boot);
    do_boot((void *)boot.fw_base);
}
