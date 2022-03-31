/** @file ex_se05x_sign.c
 *  @brief se05x sign example
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"
#include "se05x_scp03.h"
#include "phNxpEse_Api.h"
#include "smCom.h"

/* ********************** Global variables ********************** */
/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

static Se05xSession_t se05x_session = {
    0,
};

static uint8_t scp03_dyn_enc[16] = {0};
static size_t scp03_dyn_enc_len  = sizeof(scp03_dyn_enc);
static uint8_t scp03_dyn_mac[16] = {0};
static size_t scp03_dyn_mac_len  = sizeof(scp03_dyn_mac);
static uint8_t scp03_dyn_dek[16] = {0};
static size_t scp03_dyn_dek_len  = sizeof(scp03_dyn_dek);
static uint8_t scp03_dyn_ctr[16] = {0};
static size_t scp03_dyn_ctr_len  = sizeof(scp03_dyn_ctr);
static uint8_t scp03_dyn_mcv[16] = {0};
static size_t scp03_dyn_mcv_len  = sizeof(scp03_dyn_mcv);

#include "ex_common.h"

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

int ex_establish_scp03(void)
{
    smStatus_t status;
    uint8_t appletVersion[32] = {0};
    size_t appletVersionLen   = sizeof(appletVersion);

    ex_set_scp03_keys(&se05x_session);

    se05x_session.session_resume = 0;

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen %d\n", __LINE__);
        return 1;
    }

    status = Se05x_API_GetVersion(&se05x_session, appletVersion, &appletVersionLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_GetVersion %d\n", __LINE__);
        return 1;
    }

    /* Retrieved sesion keys / values */

    status = Se05x_API_SCP03_GetSessionKeys(&se05x_session,
        scp03_dyn_enc,
        &scp03_dyn_enc_len,
        scp03_dyn_mac,
        &scp03_dyn_mac_len,
        scp03_dyn_dek,
        &scp03_dyn_dek_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SCP03_GetSessionKeys %d\n", __LINE__);
        return 1;
    }

    status = Se05x_API_SCP03_GetMcvCounter(
        &se05x_session, scp03_dyn_ctr, &scp03_dyn_ctr_len, scp03_dyn_mcv, &scp03_dyn_mcv_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SCP03_GetMcvCounter %d\n", __LINE__);
        return 1;
    }

    if (0 != saveScp03StateToFile()) {
        SMLOG_E("Failed to write SCP03 state to file");
        return 1;
    }

    if (SM_OK != smComT1oI2C_ComReset(se05x_session.conn_context)) {
        SMLOG_E("Failed to close I2C");
    }

    return 0;
}
