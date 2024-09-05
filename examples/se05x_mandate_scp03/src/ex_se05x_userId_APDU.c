/** @file ex_se05x_userId_APDU.c
 *  @brief APDU functions required to set up user-id session
 *
 * Copyright 2021-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#ifdef WITH_PlatformSCPRequest_NOT_REQUIRED
// SCP03 functions are required only to send PlatformSCPRequest_NOT_REQUIRED command
#include "se05x_scp03.h"
#include "se05x_scp03_crypto.h"
#endif

/* ********************** Global variables ********************** */
extern uint8_t se05x_applet_session_value[8];
uint8_t se05x_applet_session = 0;

/* ********************** Functions prototypes ********************** */
#ifdef WITH_PlatformSCPRequest_NOT_REQUIRED
smStatus_t ex_se05x_scp03_encrypt_data(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *inBuf,
    size_t inBufLen,
    uint8_t *outBuf,
    size_t *poutBufLen,
    uint8_t hasle);
smStatus_t ex_se05x_scp03_decrypt_data(
    pSe05xSession_t session_ctx, uint8_t *inBuf, size_t inBufLen, uint8_t *outBuf, size_t *pOutBufLen);
#endif //#ifdef WITH_PlatformSCPRequest_NOT_REQUIRED

/* ********************** Functions ********************** */

/* Refer 4.5.1.3 ProcessSessionCmd in se05x apdu spec doc */
smStatus_t ex_se05x_process_session_command(const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *out,
    size_t *outLen,
    size_t hasle)
{
    smStatus_t retStatus = SM_NOT_OK;
    size_t SCmd_Lc       = (cmdBufLen == 0) ? 0 : (((cmdBufLen < 0xFF) && !hasle) ? 1 : 3);
    size_t STag1_Len     = 0 /* cla ins */ + 4 + SCmd_Lc + cmdBufLen;
    size_t i             = 0;

    ENSURE_OR_GO_CLEANUP(hdr != NULL);
    ENSURE_OR_GO_CLEANUP(cmdBuf != NULL);
    ENSURE_OR_GO_CLEANUP(out_hdr != NULL);
    ENSURE_OR_GO_CLEANUP(out != NULL);
    ENSURE_OR_GO_CLEANUP(outLen != NULL);

    out_hdr->hdr[0] = 0x80 /*kSE05x_CLA*/;
    out_hdr->hdr[1] = kSE05x_INS_PROCESS;
    out_hdr->hdr[2] = kSE05x_P1_DEFAULT;
    out_hdr->hdr[3] = kSE05x_P2_DEFAULT;

    /* Add session id */
    ENSURE_OR_GO_CLEANUP(i + (1 + 1 + sizeof(se05x_applet_session_value)) < (*outLen)) /* Tag + lenght + 8 */
    out[i++] = kSE05x_TAG_SESSION_ID;
    out[i++] = sizeof(se05x_applet_session_value);
    memcpy(&out[i], se05x_applet_session_value, sizeof(se05x_applet_session_value));
    i += sizeof(se05x_applet_session_value);

    /* Add actual command with kSE05x_TAG_1 tag */
    ENSURE_OR_GO_CLEANUP(i < (*outLen));
    out[i++] = kSE05x_TAG_1;
    if (STag1_Len <= 0x7Fu) {
        ENSURE_OR_GO_CLEANUP(i < (*outLen));
        out[i++] = (uint8_t)STag1_Len;
    }
    else if (STag1_Len <= 0xFFu) {
        ENSURE_OR_GO_CLEANUP(i + 1 < (*outLen));
        out[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        out[i++] = (uint8_t)((STag1_Len >> 0 * 8) & 0xFF);
    }
    else if (STag1_Len <= 0xFFFFu) {
        ENSURE_OR_GO_CLEANUP(i + 2 < (*outLen));
        out[i++] = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        out[i++] = (uint8_t)((STag1_Len >> 8) & 0xFF);
        out[i++] = (uint8_t)((STag1_Len) & 0xFF);
    }
    ENSURE_OR_GO_CLEANUP(i + sizeof(*hdr) < (*outLen));
    memcpy(&out[i], hdr, sizeof(*hdr));
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        if ((cmdBufLen < 0xFF) && !hasle) {
            ENSURE_OR_GO_CLEANUP(i < (*outLen));
            out[i++] = (uint8_t)cmdBufLen;
        }
        else {
            ENSURE_OR_GO_CLEANUP(i + 2 < (*outLen));
            out[i++] = 0x00;
            out[i++] = 0xFFu & (cmdBufLen >> 8);
            out[i++] = 0xFFu & (cmdBufLen);
        }
    }
    if (cmdBufLen > 0) {
        ENSURE_OR_GO_CLEANUP(i + cmdBufLen < (*outLen));
        memcpy(&out[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }

    retStatus = SM_OK;
    *outLen   = i;
cleanup:
    return retStatus;
}

/********* SE05X APDU function ****************/

smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    const uint8_t *userId,
    size_t userIdLen,
    const SE05x_AttestationType_t attestation_type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{0x80 /*kSE05x_CLA*/, kSE05x_INS_WRITE | attestation_type, kSE05x_P1_UserID, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = NULL;
    int tlvRet       = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - Se05x_API_WriteUserID [] \n");

    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_MaxAttemps("maxAttempt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_MAX_ATTEMPTS, maxAttempt);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("userId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, userId, userIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_VerifySessionUserID(pSe05xSession_t session_ctx, const uint8_t *userId, size_t userIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{0x80 /*kSE05x_CLA*/, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_UserID}};
    size_t cmdbufLen     = 0;
    uint8_t cmdbuf[64]   = {
        0,
    };
    uint8_t *pCmdbuf   = &cmdbuf[0];
    uint8_t tmpBuf[64] = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    tlvHeader_t hdr1 = {
        0,
    };
    int tlvRet       = 0;
    uint8_t *rspBuf  = NULL;
    size_t rspLength = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    rspBuf    = &session_ctx->apdu_buffer[0];
    rspLength = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_VerifySessionUserID [] \n");

    tlvRet = TLVSET_u8bufOptional("userId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, userId, userIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = ex_se05x_process_session_command(&hdr, &cmdbuf[0], cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

#ifdef WITH_PlatformSCPRequest_REQUIRED
    retStatus = DoAPDUTx(session_ctx, &hdr1, &tmpBuf[0], tmpBufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
#elif WITH_PlatformSCPRequest_NOT_REQUIRED
    cmdbufLen = sizeof(cmdbuf);
    retStatus = ex_se05x_scp03_encrypt_data(session_ctx, &hdr1, tmpBuf, tmpBufLen, &cmdbuf[0], &cmdbufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    tmpBufLen = sizeof(tmpBuf);
    retStatus = (smStatus_t)smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdbuf, cmdbufLen, tmpBuf, &tmpBufLen);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    retStatus = ex_se05x_scp03_decrypt_data(session_ctx, tmpBuf, tmpBufLen, rspBuf, &rspLength);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
#else
#error "Build with either 'WITH_PlatformSCPRequest_REQUIRED' or 'WITH_PlatformSCPRequest_NOT_REQUIRED'. "
#endif

    se05x_applet_session = 1;
cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetPlatformSCPRequest(pSe05xSession_t session_ctx, SE05x_PlatformSCPRequest_t platformSCPRequest)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{0x80 /*kSE05x_CLA*/, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SCP}};
    size_t cmdbufLen     = 0;
    uint8_t cmdbuf[64]   = {
        0,
    };
    uint8_t *pCmdbuf   = &cmdbuf[0];
    uint8_t tmpBuf[64] = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    tlvHeader_t hdr1 = {
        0,
    };
    int tlvRet       = 0;
    uint8_t *rspBuf  = NULL;
    size_t rspLength = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    rspBuf    = &session_ctx->apdu_buffer[0];
    rspLength = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_SetPlatformSCPRequest [] \n");

    tlvRet = TLVSET_U8("platf scp req", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, platformSCPRequest);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = ex_se05x_process_session_command(&hdr, &cmdbuf[0], cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

#ifdef WITH_PlatformSCPRequest_REQUIRED
    retStatus = DoAPDUTx(session_ctx, &hdr1, &tmpBuf[0], tmpBufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
#elif WITH_PlatformSCPRequest_NOT_REQUIRED
    cmdbufLen = sizeof(cmdbuf);
    retStatus = ex_se05x_scp03_encrypt_data(session_ctx, &hdr1, tmpBuf, tmpBufLen, &cmdbuf[0], &cmdbufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    tmpBufLen = sizeof(tmpBuf);
    retStatus = (smStatus_t)smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdbuf, cmdbufLen, tmpBuf, &tmpBufLen);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    retStatus = ex_se05x_scp03_decrypt_data(session_ctx, tmpBuf, tmpBufLen, rspBuf, &rspLength);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
#else
#error "Build with either 'WITH_PlatformSCPRequest_REQUIRED' or 'WITH_PlatformSCPRequest_NOT_REQUIRED'. "
#endif

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CloseAppletSession(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{0x80 /*kSE05x_CLA*/, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CLOSE}};
    size_t cmdbufLen     = 0;
    uint8_t cmdbuf[64]   = {
        0,
    };
    uint8_t tmpBuf[64] = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    tlvHeader_t hdr1 = {
        0,
    };
    uint8_t *rspBuf  = NULL;
    size_t rspLength = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_CloseAppletSession [] \n");

    rspBuf    = &session_ctx->apdu_buffer[0];
    rspLength = sizeof(session_ctx->apdu_buffer);

    if (se05x_applet_session == 0) {
        SMLOG_I("CloseSession command is sent only if valid Session exists!!!");
        return SM_OK;
    }

    retStatus = ex_se05x_process_session_command(&hdr, &cmdbuf[0], cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);

#ifdef WITH_PlatformSCPRequest_REQUIRED
    // Cannot send close command as platformSCP03 session is not open.
#elif WITH_PlatformSCPRequest_NOT_REQUIRED
    cmdbufLen = sizeof(cmdbuf);
    retStatus = ex_se05x_scp03_encrypt_data(session_ctx, &hdr1, tmpBuf, tmpBufLen, &cmdbuf[0], &cmdbufLen, 0);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    tmpBufLen = sizeof(tmpBuf);
    retStatus = (smStatus_t)smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdbuf, cmdbufLen, tmpBuf, &tmpBufLen);
    if (retStatus != SM_OK) {
        goto cleanup;
    }

    retStatus = ex_se05x_scp03_decrypt_data(session_ctx, tmpBuf, tmpBufLen, rspBuf, &rspLength);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
#else
#error "Build with either 'WITH_PlatformSCPRequest_REQUIRED' or 'WITH_PlatformSCPRequest_NOT_REQUIRED'. "
#endif

    memset(&se05x_applet_session_value[0], 0, sizeof(se05x_applet_session_value));

cleanup:
    return retStatus;
}

#ifdef WITH_PlatformSCPRequest_NOT_REQUIRED

smStatus_t ex_se05x_scp03_encrypt_data(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *inBuf,
    size_t inBufLen,
    uint8_t *outBuf,
    size_t *poutBufLen,
    uint8_t hasle)
{
    uint8_t iv[16]      = {0};
    int ret             = 0;
    int i               = 0;
    uint8_t macData[16] = {
        0,
    };
    size_t macDataLen  = 16;
    size_t se05xCmdLC  = 0;
    size_t se05xCmdLCW = 0;

    uint8_t se05x_sessionEncKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionEncKey_len                 = sizeof(se05x_sessionEncKey);
    uint8_t se05x_sessionMacKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionMacKey_len                  = sizeof(se05x_sessionMacKey);
    uint8_t se05x_sessionRmacKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionRmacKey_len = sizeof(se05x_sessionRmacKey);

    ENSURE_OR_RETURN_ON_ERROR(hdr != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(inBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(outBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(poutBufLen != NULL, SM_NOT_OK);

    if (Se05x_API_SCP03_GetSessionKeys(session_ctx,
            &se05x_sessionEncKey[0],
            &se05x_sessionEncKey_len,
            &se05x_sessionMacKey[0],
            &se05x_sessionMacKey_len,
            &se05x_sessionRmacKey[0],
            &se05x_sessionRmacKey_len) != SM_OK) {
        return SM_NOT_OK;
    }

    if (inBufLen != 0) {
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_Auth_PadCommandAPDU(inBuf, &inBufLen) == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR(
            (Se05x_API_Auth_CalculateCommandICV(se05x_sessionEncKey, session_ctx->scp03_counter, iv) == SM_OK),
            SM_NOT_OK);

        ret = hcrypto_aes_cbc_encrypt(se05x_sessionEncKey, AES_KEY_LEN_nBYTE, iv, SCP_KEY_SIZE, inBuf, inBuf, inBufLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
    }

    se05xCmdLC  = inBufLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
    se05xCmdLCW = (se05xCmdLC == 0) ? 0 : (((se05xCmdLC < 0xFF) && !(hasle)) ? 1 : 3);

    ENSURE_OR_RETURN_ON_ERROR(i + sizeof(*hdr) < (*poutBufLen), SM_NOT_OK);
    memcpy(&outBuf[i], hdr, sizeof(*hdr));
    outBuf[i] |= 0x4;
    i += sizeof(*hdr);

    if (se05xCmdLCW > 0) {
        if (se05xCmdLCW == 1) {
            ENSURE_OR_RETURN_ON_ERROR(i < (*poutBufLen), SM_NOT_OK);
            outBuf[i++] = (uint8_t)se05xCmdLC;
        }
        else {
            ENSURE_OR_RETURN_ON_ERROR(i + 2 < (*poutBufLen), SM_NOT_OK);
            outBuf[i++] = 0x00;
            outBuf[i++] = 0xFFu & (se05xCmdLC >> 8);
            outBuf[i++] = 0xFFu & (se05xCmdLC);
        }
    }

    ENSURE_OR_RETURN_ON_ERROR(i + inBufLen < (*poutBufLen), SM_NOT_OK);
    memcpy(&outBuf[i], inBuf, inBufLen);
    i += inBufLen;

    ret = Se05x_API_Auth_CalculateMacCmdApdu(
        se05x_sessionMacKey, session_ctx->scp03_mcv, outBuf, i, macData, &macDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(i + SCP_GP_IU_CARD_CRYPTOGRAM_LEN < (*poutBufLen), SM_NOT_OK);
    memcpy(&outBuf[i], macData, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    i += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    if (hasle) {
        ENSURE_OR_RETURN_ON_ERROR(i + 1 < (*poutBufLen), SM_NOT_OK);
        outBuf[i++] = 0x00;
        outBuf[i++] = 0x00;
    }

    *poutBufLen = i;
    return SM_OK;
}

smStatus_t ex_se05x_scp03_decrypt_data(
    pSe05xSession_t session_ctx, uint8_t *inBuf, size_t inBufLen, uint8_t *outBuf, size_t *pOutBufLen)
{
    smStatus_t apduStatus = SM_NOT_OK;
    uint8_t iv[16]        = {0};
    int ret               = 0;
    uint8_t macData[16]   = {
        0,
    };
    size_t macDataLen = 16;
    uint8_t sw[SCP_GP_SW_LEN];
    size_t compareoffset = 0;
    size_t actualRespLen = 0;

    uint8_t se05x_sessionEncKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionEncKey_len                 = sizeof(se05x_sessionEncKey);
    uint8_t se05x_sessionMacKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionMacKey_len                  = sizeof(se05x_sessionMacKey);
    uint8_t se05x_sessionRmacKey[AES_KEY_LEN_nBYTE] = {
        0,
    };
    size_t se05x_sessionRmacKey_len = sizeof(se05x_sessionRmacKey);

    ENSURE_OR_RETURN_ON_ERROR(inBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(outBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pOutBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR((inBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

    if (Se05x_API_SCP03_GetSessionKeys(session_ctx,
            &se05x_sessionEncKey[0],
            &se05x_sessionEncKey_len,
            &se05x_sessionMacKey[0],
            &se05x_sessionMacKey_len,
            &se05x_sessionRmacKey[0],
            &se05x_sessionRmacKey_len) != SM_OK) {
        return SM_NOT_OK;
    }

    apduStatus = inBuf[inBufLen - 2] << 8 | inBuf[inBufLen - 1];
    if (apduStatus == SM_OK) {
        memcpy(sw, &(inBuf[inBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);

        ret = Se05x_API_Auth_CalculateMacRspApdu(
            se05x_sessionRmacKey, session_ctx->scp03_mcv, inBuf, inBufLen, macData, &macDataLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

        ENSURE_OR_RETURN_ON_ERROR((inBufLen >= SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN), SM_NOT_OK);
        compareoffset = inBufLen - SCP_COMMAND_MAC_SIZE - SCP_GP_SW_LEN;
        if (memcmp(macData, &inBuf[compareoffset], SCP_COMMAND_MAC_SIZE) != 0) {
            SMLOG_E(" Response MAC did not verify \n");
            return SM_NOT_OK;
        }

        SMLOG_D("RMAC verified successfully...Decrypt Response Data \n");

        // Decrypt Response Data Field in case Reponse Mac verified OK
        if (inBufLen > (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) { // There is data payload in response
            // Calculate ICV to decrypt the response

            /* Check - cmdBufLen == 0 ? FALSE : TRUE); */
            ENSURE_OR_RETURN_ON_ERROR(
                (Se05x_API_Auth_GetResponseICV(TRUE, session_ctx->scp03_counter, se05x_sessionEncKey, iv) == SM_OK),
                SM_NOT_OK);

            ENSURE_OR_RETURN_ON_ERROR(((inBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN) <= *pOutBufLen), SM_NOT_OK);
            ret = hcrypto_aes_cbc_decrypt(se05x_sessionEncKey,
                AES_KEY_LEN_nBYTE,
                iv,
                SCP_KEY_SIZE,
                inBuf,
                outBuf,
                ((inBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)));
            ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);

            actualRespLen = (inBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN);

            ENSURE_OR_RETURN_ON_ERROR(
                (Se05x_API_Auth_RestoreSwRAPDU(outBuf, pOutBufLen, outBuf, actualRespLen, sw) == SM_OK), SM_NOT_OK);

            SMLOG_MAU8_D("Decrypted Data ==>", outBuf, *pOutBufLen);
        }
        else if (inBufLen == (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
            // There's no data payload in response
            ENSURE_OR_RETURN_ON_ERROR(SCP_GP_SW_LEN <= *pOutBufLen, SM_NOT_OK);
            memcpy(outBuf, sw, SCP_GP_SW_LEN);
            *pOutBufLen = SCP_GP_SW_LEN;
            SMLOG_MAU8_D("Decrypted Data ==>", outBuf, *pOutBufLen);
        }
    }

    Se05x_API_Auth_IncCommandCounter(session_ctx->scp03_counter);

    return apduStatus;
}

#endif //#ifdef WITH_PlatformSCPRequest_NOT_REQUIRED
