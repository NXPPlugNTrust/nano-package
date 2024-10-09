#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "phNxpEse_Api.h"
#include "sa_qi_port.h"

#define kSE05x_CLA 0x80

extern pSe05xSession_t p_aes_session_ctx;

smStatus_t Se05x_API_CheckObjectExists_AESAuth(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_EXIST}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - CheckObjectExists [] \n");

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    // retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(
        p_aes_session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
        ex_se05x_aesauth_decrypt_data(p_aes_session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(session_ctx->apdu_buffer, &rspIndex, tmpBufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == tmpBufLen) {
            retStatus = (session_ctx->apdu_buffer[rspIndex] << 8) | (session_ctx->apdu_buffer[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteECKey_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, kSE05x_P1_EC | key_part, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    uint8_t *pRspbuf = NULL;
    size_t rspbufLen = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - WriteECKey [] \n");

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
    tlvRet = TLVSET_ECCurve("curveID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("privKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, privKey, privKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("pubKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, pubKey, pubKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    SMLOG_MAU8_D("CmdBuffer", session_ctx->apdu_buffer, cmdbufLen);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(
        p_aes_session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
        ex_se05x_aesauth_decrypt_data(p_aes_session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_UpdateECKey_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, kSE05x_P1_EC | key_part, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    uint8_t *pRspbuf = NULL;
    size_t rspbufLen = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - UpdateECKey [] \n");

    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
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
    tlvRet = TLVSET_ECCurve("curveID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("privKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, privKey, privKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("pubKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, pubKey, pubKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    SMLOG_MAU8_D("CmdBuffer", session_ctx->apdu_buffer, cmdbufLen);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(
        p_aes_session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
        ex_se05x_aesauth_decrypt_data(p_aes_session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteBinary_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_BINARY, kSE05x_P2_DEFAULT}};
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = NULL;
    int tlvRet       = 0;
    uint8_t *pRspbuf = NULL;
    size_t rspbufLen = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);
    pCmdbuf   = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - WriteBinary [] \n");

    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("input data", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    SMLOG_MAU8_D("CmdBuffer", session_ctx->apdu_buffer, cmdbufLen);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(
        p_aes_session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
        ex_se05x_aesauth_decrypt_data(p_aes_session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    // /* TODO: Add code to wrap in AESKey context */

    // retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

    // /* TODO: Add code to unwrap from AESKey context */

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_UpdateBinary_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_BINARY, kSE05x_P2_DEFAULT}};
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = NULL;
    int tlvRet       = 0;
    uint8_t *pRspbuf = NULL;
    size_t rspbufLen = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);
    pCmdbuf   = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - UpdateBinary [] \n");

    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("input data", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    SMLOG_MAU8_D("CmdBuffer", session_ctx->apdu_buffer, cmdbufLen);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(
        p_aes_session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
        ex_se05x_aesauth_decrypt_data(p_aes_session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);
    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    // /* TODO: Add code to wrap in AESKey context */

    // retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

    // /* TODO: Add code to unwrap from AESKey context */

cleanup:
    return retStatus;
}
