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

int ex_resume_scp03(void)
{
    smStatus_t status;
    uint8_t appletVersion[32] = {0};
    size_t appletVersionLen   = sizeof(appletVersion);

    if (0 != readScp03StateToFile()) {
        SMLOG_E("Failed to read SCP03 state from file");
        return 1;
    }

    /* Open session again, skipping applet select and ATR */
    se05x_session.session_resume     = 1;
    se05x_session.skip_applet_select = 1;
    se05x_session.conn_context       = NULL;
    se05x_session.scp03_session      = 1;
    memset(appletVersion, 0, sizeof(appletVersion));

    status = Se05x_API_SCP03_SetSessionKeys(&se05x_session,
        scp03_dyn_enc,
        scp03_dyn_enc_len,
        scp03_dyn_mac,
        scp03_dyn_mac_len,
        scp03_dyn_dek,
        scp03_dyn_dek_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SCP03_SetSessionKeys %d\n", __LINE__);
        return 1;
    }

    status = Se05x_API_SCP03_SetMcvCounter(
        &se05x_session, scp03_dyn_ctr, scp03_dyn_ctr_len, scp03_dyn_mcv, scp03_dyn_mcv_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SCP03_SetMcvCounter %d\n", __LINE__);
        return 1;
    }

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
