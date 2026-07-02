/* port.c
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
wolfCrypt Porting Build Options:

Threading/Mutex options:
 * SINGLE_THREADED:     No-op mutex/threading implementations   default: off
 * WOLFSSL_PTHREADS:    Use pthread-based mutex/threading       default: off
 *                      (auto-detected on most POSIX systems)
 * WOLFSSL_MUTEX_INITIALIZER: Use static mutex initialization   default: off
 * WC_MUTEX_OPS_INLINE: Use inlined mutex operations            default: off
 * WOLFSSL_USER_MUTEX:  User-provided mutex implementation      default: off
 * WOLFSSL_COND:        Enable condition variable support       default: off
 * WOLFSSL_USE_RWLOCK:  Enable reader-writer lock support       default: off
 * WOLFSSL_THREAD_NO_JOIN: Create threads without join          default: off
 * WOLFSSL_ALGO_HW_MUTEX: Per-algorithm hardware mutex locks    default: off
 *                      Controls AES, hash, PK, and RNG mutexes.
 * WOLFSSL_CRYPT_HW_MUTEX: Cryptography hardware mutex          default: off
 *                      Master control for all HW mutex init.
 * NO_AES_MUTEX:        Disable AES hardware mutex              default: off
 * NO_HASH_MUTEX:       Disable hash hardware mutex             default: off
 * NO_PK_MUTEX:         Disable public-key hardware mutex       default: off
 * NO_RNG_MUTEX:        Disable RNG hardware mutex              default: off
 *
 * Memory options:
 * USE_WOLFSSL_MEMORY:  Enable custom memory allocation hooks   default: on
 * WOLFSSL_STATIC_MEMORY: Use static memory pools instead of    default: off
 *                      dynamic allocation.
 * WOLFSSL_TRACK_MEMORY: Enable memory allocation tracking      default: off
 * WOLFSSL_TRACK_MEMORY_VERBOSE: Verbose memory tracking output default: off
 * WOLFSSL_FORCE_MALLOC_FAIL_TEST: Force malloc failures for    default: off
 *                      testing error handling paths.
 * WOLFSSL_MEM_FAIL_COUNT: Count malloc failures for testing    default: off
 * WOLFSSL_CHECK_MEM_ZERO: Verify sensitive memory is zeroed    default: off
 *                      on free. Debug tool for key material.
 *
 * Filesystem options:
 * NO_FILESYSTEM:       Disable all filesystem operations       default: off
 * NO_WOLFSSL_DIR:      Disable directory listing/iteration     default: off
 *
 * Time options:
 * WOLFSSL_GMTIME:      Provide custom gmtime implementation    default: off
 * HAVE_TIME_T_TYPE:    Platform provides time_t                default: auto
 * TIME_OVERRIDES:      Application provides custom time funcs  default: off
 * USER_TICKS:          Application provides tick counter       default: off
 * USE_WOLF_TM:         Use wolfSSL struct tm definition        default: off
 *
 * String function options:
 * STRING_USER:         User provides all string functions      default: off
 * USE_WOLF_STRTOK:     Use wolfSSL strtok implementation       default: off
 * USE_WOLF_STRSEP:     Use wolfSSL strsep implementation       default: off
 * USE_WOLF_STRLCPY:    Use wolfSSL strlcpy implementation      default: off
 * USE_WOLF_STRLCAT:    Use wolfSSL strlcat implementation      default: off
 * USE_WOLF_STRCASECMP: Use wolfSSL strcasecmp implementation   default: off
 * USE_WOLF_STRNCASECMP:Use wolfSSL strncasecmp implementation  default: off
 * USE_WOLF_STRDUP:     Use wolfSSL strdup implementation       default: off
 *
 * Atomic operation options:
 * WOLFSSL_ATOMIC_OPS:  Enable atomic operations for thread     default: off
 *                      safety without full mutexes.
 * WOLFSSL_USER_DEFINED_ATOMICS: User-provided atomic impl     default: off
 * WOLFSSL_HAVE_ATOMIC_H: Has C11 atomic.h header              default: off
 *
 * General options:
 * WOLFCRYPT_ONLY:      Exclude TLS/SSL, wolfCrypt only build   default: off
 * WOLFSSL_LEANPSK:     Lean PSK build, minimal features        default: off
 * WOLF_C89:            C89 compatibility mode                  default: off
 * WOLFSSL_SMALL_STACK: Reduce stack usage by allocating from   default: off
 *                      heap instead. Slower but needed for
 *                      constrained environments.
 * DEBUG_WOLFSSL_VERBOSE: Enable verbose debug logging           default: off
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>


#include <wolfssl/wolfcrypt/cpuid.h>
    #include <wolfssl/wolfcrypt/ecc.h>








#include <wolfssl/wolfcrypt/memory.h>














/* prevent multiple mutex initializations */
    wolfSSL_Atomic_Int initRefCount = WOLFSSL_ATOMIC_INITIALIZER(0);


/* Used to initialize state for wolfcrypt
   return 0 on success
 */


/* return success value is the same as wolfCrypt_Init */




/* String token (delim) search. If str is null use nextp. */















/* ---------------------------------------------------------------------------*/
/* Mutex Ports */
/* ---------------------------------------------------------------------------*/
















/* custom memory wrappers */






