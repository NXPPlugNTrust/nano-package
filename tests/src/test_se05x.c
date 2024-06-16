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

/**** EC Auth Key ****/
/* clang-format off */
uint8_t ec_auth_key[] = {                                                 \
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,                   \
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,                   \
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,                   \
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,                   \
        0x01, 0x01, 0x04, 0x20,                                           \
        0x6D, 0x2F, 0x43, 0x2F, 0x8A, 0x2F, 0x45, 0xEC,                   \
        0xD5, 0x82, 0x84, 0x7E, 0xC0, 0x83, 0xBB, 0xEB,                   \
        0xC2, 0x3F, 0x1D, 0xF4, 0xF0, 0xDD, 0x2A, 0x6F,                   \
        0xB8, 0x1A, 0x24, 0xE7, 0xB6, 0xD5, 0x4C, 0x7F,                   \
        0xA1, 0x44, 0x03, 0x42, 0x00,                                     \
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,                   \
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,                   \
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,                   \
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,                   \
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,                   \
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,                   \
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,                   \
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,                   \
        0xC4                                                              \
    };
/* clang-format on */

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

void ex_set_ec_auth_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pEc_auth_key    = &ec_auth_key[0];
    session_ctx->ec_auth_key_len = sizeof(ec_auth_key);
    return;
}

void test_setup(void)
{
    smStatus_t status;

    SMLOG_I("Starting se05x tests ... \n");

    ex_set_scp03_keys(&se05x_session);
    ex_set_ec_auth_keys(&se05x_session);

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
