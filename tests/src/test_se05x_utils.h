/** @file test_se05x_utils.h
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "sm_port.h"

/* ********************** Defines ********************** */
#define SE05X_TEST_FAIL 0
#define SE05X_TEST_PASS 1
#define SE05X_TEST_IGNORE 2

#define TEST_ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE)                 \
    if (!(CONDITION)) {                                                         \
        SMLOG_E("Error in function - %s, Line - %d  ", __FUNCTION__, __LINE__); \
        SMLOG_I("%s, FAILED \n", __FUNCTION__);                                 \
        return RETURN_VALUE;                                                    \
    }

#define TEST_ENSURE_OR_GOTO_EXIT(CONDITION)                                     \
    if (!(CONDITION)) {                                                         \
        SMLOG_E("Error in function - %s, Line - %d  ", __FUNCTION__, __LINE__); \
        goto exit;                                                              \
    }

#define IGNORE_SE05X_TEST()                     \
    {                                           \
        SMLOG_I("%s, IGNORE \n", __FUNCTION__); \
        return SE05X_TEST_IGNORE;               \
    }

#define PASS_SE05X_TEST()                       \
    {                                           \
        SMLOG_I("%s, PASSED \n", __FUNCTION__); \
        return SE05X_TEST_PASS;                 \
    }

/* ********************** Functions Prototypes ********************** */

/* Check if the keyID exists in se05x */
bool se05x_object_exists(pSe05xSession_t session_ctx, uint32_t keyID);

/* ********************** Functions ********************** */

static void UPDATE_RESULT(uint8_t ret, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    (ret == SE05X_TEST_PASS) ? ((*pass)++) : ((ret == SE05X_TEST_FAIL) ? ((*fail)++) : ((*ignore)++));
}
