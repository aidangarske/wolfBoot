/* app_stm32n6.c
 *
 * Test bare-metal application for NUCLEO-N657X0-Q.
 *
 * Copyright (C) 2025 wolfSSL Inc.
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

#include <stdio.h>
#include <stdint.h>
#include "system.h"
#include "hal.h"
#include "wolfboot/wolfboot.h"
#include "target.h"

/* UART: uart_write() provided by hal/stm32n6.c (linked as stm32n6_ns.o) */
extern void uart_write(const char *buf, unsigned int len);

/* --- GPIO / LEDs --- */
/* With TZEN=1, test-app is compiled with -DNONSECURE_APP and runs in
 * non-secure state. Use non-secure peripheral aliases (0x46xxx). */
#ifdef NONSECURE_APP
#define RCC_BASE        (0x46028000UL)
#define PWR_BASE        (0x46024800UL)
#define GPIOG_BASE      (0x46021800UL)
#else
#define RCC_BASE        (0x56028000UL)
#define PWR_BASE        (0x56024800UL)
#define GPIOG_BASE      (0x56021800UL)
#endif

#define RCC_AHB4ENR     (*(volatile uint32_t *)(RCC_BASE + 0x25C))
#define RCC_AHB4ENR_GPIOGEN  (1 << 6)
#define RCC_AHB4ENR_PWREN    (1 << 18)

#define PWR_SVMCR3      (*(volatile uint32_t *)(PWR_BASE + 0x3C))
#define PWR_SVMCR3_VDDIO2SV  (1 << 8)
#define PWR_SVMCR3_VDDIO3SV  (1 << 9)

#define GPIO_MODER(base)    (*(volatile uint32_t *)((base) + 0x00))
#define GPIO_BSRR(base)     (*(volatile uint32_t *)((base) + 0x18))

/* User LEDs: active LOW on Port G (LD6=PG0 green, LD7=PG8 blue, LD5=PG10 red) */
#define LED_GREEN_PIN   0
#define LED_BLUE_PIN    8
#define LED_RED_PIN     10

static void led_init(void)
{
    uint32_t reg;

    RCC_AHB4ENR |= RCC_AHB4ENR_GPIOGEN | RCC_AHB4ENR_PWREN;
    DMB();

    PWR_SVMCR3 |= PWR_SVMCR3_VDDIO2SV | PWR_SVMCR3_VDDIO3SV;
    DMB();

    /* Set PG0, PG8, PG10 to output mode */
    reg = GPIO_MODER(GPIOG_BASE);
    reg &= ~(0x3 << (LED_GREEN_PIN * 2));
    reg |= (0x1 << (LED_GREEN_PIN * 2));
    reg &= ~(0x3 << (LED_BLUE_PIN * 2));
    reg |= (0x1 << (LED_BLUE_PIN * 2));
    reg &= ~(0x3 << (LED_RED_PIN * 2));
    reg |= (0x1 << (LED_RED_PIN * 2));
    GPIO_MODER(GPIOG_BASE) = reg;
}

static void led_on(uint32_t gpio_base, int pin)
{
    GPIO_BSRR(gpio_base) = (1 << (pin + 16)); /* active LOW */
}

static void led_off(uint32_t gpio_base, int pin)
{
    GPIO_BSRR(gpio_base) = (1 << pin);
}

/* --- SysTick delay --- */
#define SYSTICK_BASE    (0xE000E010UL)
#define SYSTICK_CSR     (*(volatile uint32_t *)(SYSTICK_BASE + 0x00))
#define SYSTICK_RVR     (*(volatile uint32_t *)(SYSTICK_BASE + 0x04))
#define SYSTICK_CVR     (*(volatile uint32_t *)(SYSTICK_BASE + 0x08))
#define HCLK_FREQ       200000000UL /* IC2(400MHz) / AHB prescaler 2 */
#define SYSTICK_COUNTFLAG (1 << 16)

static void systick_init(void)
{
    SYSTICK_RVR = (HCLK_FREQ / 1000) - 1;
    SYSTICK_CVR = 0;
    SYSTICK_CSR = 0x5; /* enable, processor clock, no interrupt */
}

static void delay_ms(uint32_t ms)
{
    while (ms > 0) {
        while (!(SYSTICK_CSR & SYSTICK_COUNTFLAG))
            ;
        ms--;
    }
}

/* --- Helpers --- */
static const char* state_name(uint8_t state)
{
    switch (state) {
        case IMG_STATE_NEW:      return "NEW";
        case IMG_STATE_UPDATING: return "UPDATING";
        case IMG_STATE_TESTING:  return "TESTING";
        case IMG_STATE_SUCCESS:  return "SUCCESS";
        default:                 return "UNKNOWN";
    }
}

static void print_partition_info(void)
{
    uint32_t boot_ver, update_ver;
    uint8_t boot_state = 0, update_state = 0;

    boot_ver = wolfBoot_current_firmware_version();
    update_ver = wolfBoot_update_firmware_version();
    wolfBoot_get_partition_state(PART_BOOT, &boot_state);
    wolfBoot_get_partition_state(PART_UPDATE, &update_state);

    printf("Partition Info\r\n");
    printf("  Boot:   version %lu, state %s\r\n",
           (unsigned long)boot_ver, state_name(boot_state));
    printf("  Update: version %lu, state %s\r\n",
           (unsigned long)update_ver, state_name(update_state));
}

/* Note: keystore API (keystore_num_pubkeys, etc.) is in src/keystore.o
 * which is not linked into the test-app. Keystore info is printed by
 * wolfBoot itself when DEBUG=1. */

/* --- Main --- */
void main(void)
{
    uint32_t version;
    uint8_t boot_state = 0;

    /* hal_init() not called -- XSPI2 already configured by wolfBoot for XIP */
    led_init();
    led_on(GPIOG_BASE, LED_GREEN_PIN);

    version = wolfBoot_current_firmware_version();

    printf("\r\n=== STM32N6 wolfBoot Test App ===\r\n");
    printf("Firmware Version: %lu\r\n", (unsigned long)version);
    print_partition_info();

    /* Auto-handle boot state */
    wolfBoot_get_partition_state(PART_BOOT, &boot_state);
    if (boot_state == IMG_STATE_TESTING) {
        printf("State TESTING -> marking success\r\n");
        wolfBoot_success();
    } else if (boot_state != IMG_STATE_SUCCESS) {
        printf("Calling wolfBoot_success()\r\n");
        wolfBoot_success();
    }
    printf("Boot OK (state: %s)\r\n", state_name(boot_state));

    /* Enable icache for XIP performance (hal_prepare_boot disables it) */
    {
        #define SCB_CCR_REG     (*(volatile uint32_t *)(0xE000ED14UL))
        #define SCB_ICIALLU_REG (*(volatile uint32_t *)(0xE000EF50UL))
        __asm__ volatile("dsb; isb");
        SCB_ICIALLU_REG = 0;
        __asm__ volatile("dsb; isb");
        SCB_CCR_REG |= (1 << 17); /* IC bit */
        __asm__ volatile("dsb; isb");
    }

    systick_init();

    /* Blink LED based on version: blue for v1, red for v>1 */
    printf("Blinking %s LED\r\n", (version > 1) ? "red" : "blue");
    {
        int led_pin = (version > 1) ? LED_RED_PIN : LED_BLUE_PIN;
        while (1) {
            led_on(GPIOG_BASE, led_pin);
            delay_ms(500);
            led_off(GPIOG_BASE, led_pin);
            delay_ms(500);
        }
    }
}

/* --- Syscalls for printf --- */
int _write(int file, char *ptr, int len)
{
    (void)file;
    uart_write(ptr, (unsigned int)len);
    return len;
}

int _read(int file, char *ptr, int len)
{
    (void)file; (void)ptr; (void)len;
    return -1;
}

int _close(int file)
{
    (void)file;
    return -1;
}

int _lseek(int file, int ptr, int dir)
{
    (void)file; (void)ptr; (void)dir;
    return 0;
}

int _isatty(int file)
{
    (void)file;
    return 1;
}

int _fstat(int file, void *st)
{
    (void)file; (void)st;
    return 0;
}

void *_sbrk(int incr)
{
    extern char _end; /* defined by linker */
    static char *heap_end = 0;
    char *prev;

    if (heap_end == 0)
        heap_end = &_end;
    prev = heap_end;
    heap_end += incr;
    return prev;
}

int _getpid(void)
{
    return 1;
}

int _kill(int pid, int sig)
{
    (void)pid; (void)sig;
    return -1;
}

void _exit(int status)
{
    (void)status;
    while (1) {}
}
