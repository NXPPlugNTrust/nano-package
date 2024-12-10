/** @file sm_port.h
 *  @brief Platform specific content.
 *
 * Copyright 2021-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SM_PORT_H_INC
#define SM_PORT_H_INC

/* ********************** Include files ********************** */
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "fsl_debug_console.h"

/* ********************** Defines ********************** */

#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_RESET "\033[0m"

#define SMLOG_I(...)     \
    PRINTF(COLOR_BLUE);  \
    PRINTF(__VA_ARGS__); \
    PRINTF("\r\n");      \
    PRINTF(COLOR_RESET)
#define SMLOG_E(...)     \
    PRINTF(COLOR_RED);   \
    PRINTF(__VA_ARGS__); \
    PRINTF("\r\n");      \
    PRINTF(COLOR_RESET)
#define SMLOG_W(...)      \
    PRINTF(COLOR_YELLOW); \
    PRINTF(__VA_ARGS__);  \
    PRINTF("\r\n");       \
    PRINTF(COLOR_RESET)

#ifdef SMLOG_DEBUG_MESSAGES
#define SMLOG_D(...)     \
    printf(COLOR_GREEN); \
    printf(__VA_ARGS__); \
    printf(COLOR_RESET)
#define SMLOG_AU8_D(BUF, LEN)                               \
    printf(COLOR_GREEN);                                    \
    printf(" :");                                           \
    for (size_t bufIndex = 0; bufIndex < LEN; bufIndex++) { \
        printf("%02x ", BUF[bufIndex]);                     \
    }                                                       \
    printf(COLOR_RESET);                                    \
    printf("\r\n")
#define SMLOG_MAU8_D(MSG, BUF, LEN)                         \
    printf(COLOR_GREEN);                                    \
    printf(MSG);                                            \
    printf(" :");                                           \
    for (size_t bufIndex = 0; bufIndex < LEN; bufIndex++) { \
        printf("%02x ", BUF[bufIndex]);                     \
    }                                                       \
    printf(COLOR_RESET);                                    \
    printf("\r\n")
#else
#define SMLOG_D(...)
#define SMLOG_AU8_D(BUF, LEN)
#define SMLOG_MAU8_D(MSG, BUF, LEN)
#endif

#define sm_malloc malloc
#define sm_free free

#define SM_MUTEX_DEFINE(x)
#define SM_MUTEX_EXTERN_DEFINE(x)
#define SM_MUTEX_INIT(x)
#define SM_MUTEX_DEINIT(x)
#define SM_MUTEX_LOCK(x)
#define SM_MUTEX_UNLOCK(x)

#ifndef FALSE
#define FALSE false
#endif

#ifndef TRUE
#define TRUE true
#endif

#endif // #ifndef SM_PORT_H_INC
