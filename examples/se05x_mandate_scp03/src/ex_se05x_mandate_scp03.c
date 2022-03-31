/** @file ex_se05x_mandate_scp03.c
 *  @brief Mandate SCP03 example
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"

/* ********************** functions prototypes ********************** */

smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    const uint8_t *userId,
    size_t userIdLen,
    const SE05x_AttestationType_t attestation_type);
smStatus_t Se05x_API_CreateSession(
    pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *session_ctxIdLen);
smStatus_t Se05x_API_VerifySessionUserID(pSe05xSession_t session_ctx, const uint8_t *userId, size_t userIdLen);
smStatus_t Se05x_API_SetPlatformSCPRequest(pSe05xSession_t session_ctx, SE05x_PlatformSCPRequest_t platformSCPRequest);
smStatus_t Se05x_API_CloseAppletSession(pSe05xSession_t session_ctx);

/* ********************** Defines ********************** */
/** An authentication object which allows the user to change the
* platform SCP requirements, i.e. make platform SCP mandatory or
* not, using SetPlatformSCPRequest. Mandatory means full security,
* i.e. command & response MAC and encryption. Only SCP03 will be
* sufficient. */
#define kSE05x_AppletResID_PLATFORM_SCP (0x7FFF0207)
/* clang-format off */
#define MandateSCP_UserID_VALUE                 \
    {                                           \
        'N', 'E', 'E', 'D', 'S', 'C', 'P'       \
    }
/* clang-format ON */


/* ********************** Global variables ********************** */

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

uint8_t se05x_applet_session_value[8] = {0,};



/* ********************** Functions ********************** */

smStatus_t se05x_open_userid_session(pSe05xSession_t session_ctx)
{
    SE05x_Result_t exists = kSE05x_Result_FAILURE;
    smStatus_t status     = SM_NOT_OK;
    size_t sessionIdLen   = sizeof(se05x_applet_session_value);
    uint8_t keyVal[] = MandateSCP_UserID_VALUE;
    size_t keyValLen = sizeof(keyVal);

    status = Se05x_API_CheckObjectExists(session_ctx, kSE05x_AppletResID_PLATFORM_SCP, &exists);
    if (status != SM_OK) {
        return status;
    }

    if (exists == kSE05x_Result_FAILURE) {
        SMLOG_I("UserID is not Provisioned!!!");
        #ifdef WITH_PlatformSCPRequest_REQUIRED
            /* Set user-id at location kSE05x_AppletResID_PLATFORM_SCP */
            SMLOG_I("Writing User id \n");
            status = Se05x_API_WriteUserID(session_ctx,
                NULL,
                0,
                kSE05x_AppletResID_PLATFORM_SCP,
                keyVal,
                sizeof(keyVal),
                kSE05x_AttestationType_AUTH);
            if (status != SM_OK) {
                SMLOG_E("Error in Se05x_API_WriteUserID \n");
                return status;
            }
        #else
            return SM_NOT_OK;
        #endif
    }

    status = Se05x_API_CreateSession(session_ctx, kSE05x_AppletResID_PLATFORM_SCP, &se05x_applet_session_value[0], &sessionIdLen);
    if (status == SM_OK)
    {
        status = Se05x_API_VerifySessionUserID(session_ctx, keyVal, keyValLen);
    }

    return status;
}


void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key = NULL; // DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

int ex_se05x_mandate_scp03(void)
{
    smStatus_t status;
    Se05xSession_t se05x_session = {0,};

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    status = se05x_open_userid_session(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in se05x_open_userid_session \n");
        return 1;
    }

#ifdef WITH_PlatformSCPRequest_REQUIRED
    SMLOG_I("Sending PlatformSCPRequest_REQUIRED command \n");
    status = Se05x_API_SetPlatformSCPRequest(&se05x_session, kSE05x_PlatformSCPRequest_REQUIRED);
#elif WITH_PlatformSCPRequest_NOT_REQUIRED
    SMLOG_I("Sending PlatformSCPRequest_NOT_REQUIRED command \n");
    status = Se05x_API_SetPlatformSCPRequest(&se05x_session, kSE05x_PlatformSCPRequest_NOT_REQUIRED);
#else
    #error "Build with either 'WITH_PlatformSCPRequest_REQUIRED' or 'WITH_PlatformSCPRequest_NOT_REQUIRED'. "
#endif
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SetPlatformSCPRequest \n");
        return 1;
    }

    status = Se05x_API_CloseAppletSession(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CloseAppletSession \n");
        return 1;
    }

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}
