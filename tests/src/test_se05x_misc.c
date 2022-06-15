/** @file test_se05x_misc.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x.h"
#include "test_se05x_utils.h"

/* ********************** Defines ********************** */
#define TEST_SE05X_MISC_OBJ_ID_BASE (0x7B000300)

uint8_t test_get_version(pSe05xSession_t session_ctx)
{
    uint8_t version[64];
    size_t version_len = sizeof(version);
    smStatus_t status;
    /*Gets the applet version information.*/
    status = Se05x_API_GetVersion(session_ctx, version, &version_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_GetVersion \n");
        goto exit;
    }
    SMLOG_I("Applet Version %d.%d.%d \n", version[0], version[1], version[2]);
    PASS_SE05X_TEST();

exit:
    return SE05X_TEST_FAIL;
}

/* ********************** Functions ********************** */

void test_se05x_misc(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    UPDATE_RESULT(test_get_version(session_ctx), pass, fail, ignore);
    return;
}
