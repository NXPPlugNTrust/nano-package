/** @file ex_se05x_sign.c
 *  @brief se05x sign example
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

uint8_t input[32];
uint8_t signature[128] = {
    0,
};
Se05xSession_t se05x_session = {
    0,
};

/* ********************** Functions ********************** */

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL; //DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

int ex_se05x_sign(void)
{
    smStatus_t status;
    uint32_t keyID = 0x7B000100;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    size_t input_len        = sizeof(input);
    size_t signature_len    = sizeof(signature);

    for (int i = 0; i < input_len; i++) {
        input[i] = i;
    }

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    status = Se05x_API_CheckObjectExists(&se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 1;
    }

    if (result == kSE05x_Result_SUCCESS) {
        curveID = kSE05x_ECCurve_NA;
    }

    SMLOG_I("Generate ecc key \n");
    status = Se05x_API_WriteECKey(
        &se05x_session, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        return 1;
    }

    SMLOG_I("Sign Data \n");
    status = Se05x_API_ECDSASign(
        &se05x_session, keyID, kSE05x_ECSignatureAlgo_SHA_256, input, input_len, signature, &signature_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        return 1;
    }

    SMLOG_MAU8_D("Signature ==> \n", signature, signature_len);

    status = Se05x_API_DeleteSecureObject(&se05x_session, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        return 1;
    }

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_I("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}
