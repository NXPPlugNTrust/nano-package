/** @file test_se05x.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"

/* ********************** Global variables ********************** */
/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

/* ********************** Extern functions ********************** */
extern void test_se05x_nist256(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
extern void test_se05x_nist256_ecdsa(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
extern void test_se05x_bin_objects(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
extern void test_se05x_aes(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
extern void test_se05x_misc(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);
extern void test_se05x_nist256_ecdh(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore);

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

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL;
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

void test_se05x(uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    Se05xSession_t se05x_session = {
        0,
    };
    smStatus_t status;

    SMLOG_I("Starting se05x tests ... \n");

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return;
    }

    test_se05x_nist256(&se05x_session, pass, fail, ignore);
    test_se05x_nist256_ecdsa(&se05x_session, pass, fail, ignore);
    test_se05x_bin_objects(&se05x_session, pass, fail, ignore);
    test_se05x_aes(&se05x_session, pass, fail, ignore);
    test_se05x_misc(&se05x_session, pass, fail, ignore);
    test_se05x_nist256_ecdh(&se05x_session, pass, fail, ignore);

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return;
    }
}
