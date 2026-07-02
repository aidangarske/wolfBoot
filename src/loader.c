/* loader.c
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
 * @file loader.c
 *
 * @brief Loader implementation for wolfBoot.
 *
 * This file contains the implementation of the loader for wolfBoot. It includes
 * functions to initialize the hardware, probe SPI flash,
 * initialize UART (if applicable), initialize TPM2 (if applicable), and
 * start the wolfBoot process.
 */

#include "loader.h"
#include "image.h"
#include "hal.h"
#include "hooks.h"
#include "spi_flash.h"
#include "wolfboot/wolfboot.h"


/**
 * @brief Start address of the text section in RAM code.
 */
extern unsigned int _start_text;
/**
 * @brief wolfBoot version number (used in RAM code).
 */
static volatile const uint32_t __attribute__((used)) wolfboot_version = WOLFBOOT_VERSION;
/**
 * @brief RAM Interrupt Vector table.
 */
extern void (** const IV_RAM)(void);

int main(void)
{


    hal_init();
    spi_flash_probe();
    wolfBoot_start();


    /* wolfBoot_start should never return. */
    wolfBoot_panic();

    return 0;
}
