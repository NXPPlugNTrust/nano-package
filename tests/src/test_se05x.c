/** @file test_se05x.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"
#include "test_se05x.h"

/* ********************** Global variables ********************** */
Se05xSession_t se05x_session = {
    0,
};

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

extern void test_fail(void);

/* ********************** Functions ********************** */

bool se05x_object_exists(pSe05xSession_t session_ctx, uint32_t keyID)
{
    SE05x_Result_t result;
    smStatus_t status;

    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return FALSE;
    }

    if (result != kSE05x_Result_SUCCESS) {
        return FALSE;
    }

    return TRUE;
}

static void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL;
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

void test_setup(void)
{
    smStatus_t status;

    SMLOG_I("Starting se05x tests ... \n");

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        test_fail();
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return;
    }
}

void test_teardown(void)
{
    smStatus_t status;

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        test_fail();
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return;
    }
}
