/* string.h
 *
 * Implementations of standard library functions to eliminate external dependencies.
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


/* Enable %llu/%llx support only on platforms where the 64-bit divide
 * is either native (64-bit CPUs) or backed by linked libgcc helpers
 * (PPC32 toolchain). The auto-enable deliberately excludes 32-bit
 * bare-metal targets (Cortex-M, x86 stage1) -- those would link-fail
 * on __aeabi_uldivmod / __udivmoddi4 because they don't pull in libgcc.
 * Such targets can still opt-in by defining PRINTF_LONG_LONG manually. */

#include <stddef.h>
size_t strlen(const char *s); /* forward declaration */

    #include "printf.h"
    #include <stdarg.h>

/* for RAMFUNCTION */
#include "image.h"

/* allow using built-in libc if WOLFBOOT_USE_STDLIBC is defined */






void *memset(void *s, int c, size_t n)
{
    unsigned char *d = (unsigned char *)s;

    while (n--) {
        *d++ = (unsigned char)c;
    }

    return s;
}











size_t strlen(const char *s)
{
    size_t i = 0;

    while (s[i] != 0)
        i++;

    return i;
}

/* some of the hal_flash_ functions need this during updates */
void RAMFUNCTION *memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    const char *s = (const char *)src;
    char *d = (char *)dst;

    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    size_t i;
    if (dst == src)
        return dst;
    if (src < dst)  {
        const char *s = (const char *)src;
        char *d = (char *)dst;
        size_t aligned_n = 0;
        for (i = n; i > aligned_n; i--) {
            d[i - 1] = s[i - 1];
        }
        return dst;
    } else {
        return memcpy(dst, src, n);
    }
}

/* Shared digit table -- avoids duplicating the literal in each width's
 * formatting loop. */
static const char uart_writenum_digits[] = "0123456789ABCDEF";

/* Shared tail for both widths: applies zeropad spacing, slides the digit
 * run into place, and emits to UART. Caller has filled digits at the
 * tail of `buf` and counted them in `sz`; `i` is the prefix length
 * (sign character only). */
static void uart_writenum_emit(char *buf, int bufsize, int i, int sz,
    int zeropad, int maxdigits)
{
    if (zeropad && sz < maxdigits) {
        i += maxdigits - sz;
    }
    memmove(&buf[i], &buf[bufsize - sz], sz);
    uart_write(buf, i + sz);
}

void uart_writenum(int num, int base, int zeropad, int maxdigits)
{
    int i = 0, sz = 0;
    /* Sized for decimal (3 chars/byte) plus sign -- wider than hex. */
    char buf[sizeof(unsigned int) * 3 + 2];
    unsigned int val = (unsigned int)num;
    if (maxdigits == 0)
        maxdigits = 8;
    memset(buf, 0, sizeof(buf));
    if (base == 10 && num < 0) {
        buf[i++] = '-';
        /* Negate in unsigned space so INT_MIN does not overflow. */
        val = 0U - (unsigned int)num;
    }
    /* Clamp after reserving the sign slot so zero-pad can't run past buf. */
    if (maxdigits > (int)sizeof(buf) - i)
        maxdigits = (int)sizeof(buf) - i;
    if (zeropad) {
        memset(&buf[i], '0', maxdigits);
    }
    /* 32-bit divide: stays out of libgcc 64-bit helpers, which aren't
     * linked into freestanding stage1 / Cortex-M builds. */
    do {
        buf[sizeof(buf) - sz - 1] =
            uart_writenum_digits[(val % (unsigned)base)];
        sz++;
        val /= (unsigned)base;
    } while (val > 0U);
    uart_writenum_emit(buf, sizeof(buf), i, sz, zeropad, maxdigits);
}

#ifdef PRINTF_LONG_LONG
/* 64-bit core for %llu/%lld/%llx. Pulls in libgcc 64-bit divide
 * (__udivmoddi4 / __aeabi_uldivmod) so it's only compiled when needed
 * and only called from the long-long printf paths -- never from the
 * 32-bit uart_writenum() fast path above. */
static void uart_writenum_ll(unsigned long long val, int is_negative,
    int base, int zeropad, int maxdigits)
{
    int i = 0, sz = 0;
    /* Sized for decimal (3 chars/byte) plus sign -- wider than hex. */
    char buf[sizeof(unsigned long long) * 3 + 2];
    if (maxdigits == 0)
        maxdigits = 8;
    memset(buf, 0, sizeof(buf));
    if (is_negative) {
        buf[i++] = '-';
    }
    /* Clamp after reserving the sign slot so zero-pad can't run past buf. */
    if (maxdigits > (int)sizeof(buf) - i)
        maxdigits = (int)sizeof(buf) - i;
    if (zeropad) {
        memset(&buf[i], '0', maxdigits);
    }
    do {
        buf[sizeof(buf) - sz - 1] =
            uart_writenum_digits[(val % (unsigned)base)];
        sz++;
        val /= (unsigned)base;
    } while (val > 0ULL);
    uart_writenum_emit(buf, sizeof(buf), i, sz, zeropad, maxdigits);
}
#endif /* PRINTF_LONG_LONG */

void uart_vprintf(const char* fmt, va_list argp)
{
    char* fmtp = (char*)fmt;
    int zeropad, maxdigits, precision, leftjust, islong;
    while (fmtp != NULL && *fmtp != '\0') {
        /* print non formatting characters */
        if (*fmtp != '%') {
            uart_write(fmtp++, 1);
            continue;
        }
        fmtp++; /* skip % */

        /* find formatters */
        zeropad = maxdigits = leftjust = islong = 0;
        precision = -1; /* -1 = not specified */
        /* check for left-justify flag */
        if (*fmtp == '-') {
            leftjust = 1;
            fmtp++;
        }
        while (*fmtp != '\0') {
            if (*fmtp == '*') {
                /* width from argument */
                maxdigits = va_arg(argp, int);
                fmtp++;
            }
            else if (*fmtp >= '0' && *fmtp <= '9') {
                /* length formatter */
                if (*fmtp == '0' && maxdigits == 0) {
                    zeropad = 1;
                }
                maxdigits *= 10;
                maxdigits += (*fmtp - '0');
                fmtp++;
            }
            else if (*fmtp == '.') {
                /* precision */
                fmtp++;
                if (*fmtp == '*') {
                    precision = va_arg(argp, int);
                    fmtp++;
                } else {
                    precision = 0;
                    while (*fmtp >= '0' && *fmtp <= '9') {
                        precision = precision * 10 + (*fmtp - '0');
                        fmtp++;
                    }
                }
            }
            else if (*fmtp == 'l') {
                islong++;
                fmtp++;
            }
            else if (*fmtp == 'z') {
                /* auto type - skip */
                fmtp++;
            }
            else {
                break;
            }
        }

        switch (*fmtp) {
            case '%':
                uart_write(fmtp, 1);
                break;
            case 'u':
            case 'i':
            case 'd':
            {
            #ifdef PRINTF_LONG_LONG
                if (islong >= 2) {
                    /* %llu / %lld: full 64-bit value */
                    int is_neg = 0;
                    unsigned long long val;
                    if (*fmtp != 'u') {
                        long long sll = va_arg(argp, long long);
                        if (sll < 0) {
                            is_neg = 1;
                            /* Negate in unsigned space so LLONG_MIN
                             * does not overflow. */
                            val = 0ULL - (unsigned long long)sll;
                        }
                        else {
                            val = (unsigned long long)sll;
                        }
                    }
                    else {
                        val = va_arg(argp, unsigned long long);
                    }
                    uart_writenum_ll(val, is_neg, 10, zeropad, maxdigits);
                }
                else
            #endif
                {
                    int n = (int)va_arg(argp, int);
                    uart_writenum(n, 10, zeropad, maxdigits);
                }
                break;
            }
            case 'p':
                uart_write("0x", 2);
                /* fall through */
            case 'x':
            case 'X':
            {
            #ifdef PRINTF_LONG_LONG
                if (islong >= 2) {
                    /* %llx: full 64-bit value */
                    unsigned long long val =
                        va_arg(argp, unsigned long long);
                    uart_writenum_ll(val, 0, 16, zeropad, maxdigits);
                }
                else
            #endif
                {
                    int n = (int)va_arg(argp, int);
                    uart_writenum(n, 16, zeropad, maxdigits);
                }
                break;
            }
            case 's':
            {
                char* str = (char*)va_arg(argp, char*);
                int slen = (int)strlen(str);
                if (leftjust) {
                    uart_write(str, slen);
                    while (slen < maxdigits) {
                        uart_write(" ", 1);
                        slen++;
                    }
                } else {
                    while (slen < maxdigits) {
                        uart_write(" ", 1);
                        slen++;
                    }
                    uart_write(str, (uint32_t)strlen(str));
                }
                break;
            }
            case 'c':
            {
                char c = (char)va_arg(argp, int);
                uart_write(&c, 1);
                break;
            }
            default:
                break;
        }
        fmtp++;
    };
}
void uart_printf(const char* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    uart_vprintf(fmt, argp);
    va_end(argp);
}
