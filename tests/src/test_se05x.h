/** @file test_se05x.h
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TEST_SE05x_H__
#define __TEST_SE05x_H__

#include <stdbool.h>
#include <se05x_types.h>

/* Global SE05x context */
extern Se05xSession_t se05x_session;

/* Test functions */
void *test_setup(void);
void test_teardown(void *ignore);
void test_se05x_nist256(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
void test_se05x_nist256_ecdsa(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
void test_se05x_bin_objects(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
void test_se05x_aes(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
void test_se05x_misc(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
void test_se05x_nist256_ecdh(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);

/* Helper functions */
bool se05x_object_exists(pSe05xSession_t session_ctx, uint32_t keyID);

#endif // __TEST_SE05x_H__
