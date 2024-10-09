/** @file se05x_APDU_impl.c
 *  @brief Se05x APDU function implementation.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "phNxpEse_Api.h"
#include <limits.h>

/* ********************** Defines ********************** */
#define kSE05x_CLA 0x80
#define CLA_ISO7816 (0x00)   //!< ISO7816-4 defined CLA byte
#define INS_GP_SELECT (0xA4) //!< Global platform defined instruction

/* clang-format off */
#define APPLET_NAME { 0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 }
#define SSD_NAME {0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03}
/* clang-format on */

/* ********************** Function Prototypes ********************** */
#if defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)
smStatus_t Se05x_API_SCP03_CreateSession(pSe05xSession_t session_ctx);
#endif //#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)

#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)
smStatus_t Se05x_API_ECKey_CreateSession(pSe05xSession_t session_ctx);
smStatus_t Se05x_API_ECKey_CloseSession(pSe05xSession_t session_ctx);
#endif //#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)

/* ********************** Functions ********************** */

bool Se05x_IsInValidRangeOfUID(uint32_t uid)
{
    // Block required keyids
    (void)uid;
    return FALSE;
}

smStatus_t Se05x_API_SessionOpen(pSe05xSession_t session_ctx)
{
    size_t buff_len            = 0;
    size_t tx_len              = 0;
    smStatus_t ret             = SM_NOT_OK;
    unsigned char appletName[] = APPLET_NAME;
#if defined(WITH_PLATFORM_SCP03)
    unsigned char ssdName[] = SSD_NAME;
#endif
    unsigned char *appSsdName = NULL;
    size_t appSsdNameLen      = 0;

    SMLOG_I("Plug and Trust nano package - version: %d.%d.%d \n", VERSION_MAJOR, VERSION_MINOR, VERSION_DEV);

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    buff_len = sizeof(session_ctx->apdu_buffer);

    ret = smComT1oI2C_Init(&session_ctx->conn_context, NULL);
    ENSURE_OR_GO_CLEANUP(SM_OK == ret);

    if (session_ctx->session_resume == 1) {
        ret = smComT1oI2C_Open(session_ctx->conn_context, ESE_MODE_RESUME, 0x00, session_ctx->apdu_buffer, &buff_len);
    }
    else {
        ret = smComT1oI2C_Open(session_ctx->conn_context, ESE_MODE_NORMAL, 0x00, session_ctx->apdu_buffer, &buff_len);
    }
    ENSURE_OR_GO_CLEANUP(SM_OK == ret);

    if (session_ctx->skip_applet_select == 1) {
#if !defined(WITH_PLATFORM_SCP03)
        return ret;
#else
        appSsdName    = &ssdName[0];
        appSsdNameLen = sizeof(ssdName);
#endif
    }
    else {
        appSsdName    = &appletName[0];
        appSsdNameLen = sizeof(appletName);
    }

    if (!session_ctx->session_resume) {
        /* Select applet / ssd */
        session_ctx->apdu_buffer[0] = CLA_ISO7816;
        session_ctx->apdu_buffer[1] = INS_GP_SELECT;
        session_ctx->apdu_buffer[2] = 4;
        session_ctx->apdu_buffer[3] = 0;

        tx_len = 1 /* CLA */ + 1 /* INS */ + 1 /* P1 */ + 1 /* P2 */;

        session_ctx->apdu_buffer[4] = appSsdNameLen;
        tx_len                      = tx_len + 1 /* Lc */ + appSsdNameLen /* Payload */ + 1 /* Le */;
        memcpy(&session_ctx->apdu_buffer[5], appSsdName, appSsdNameLen);
        session_ctx->apdu_buffer[tx_len - 1] = 0; /* Le */

        buff_len = sizeof(session_ctx->apdu_buffer);
        ret      = smComT1oI2C_TransceiveRaw(
            session_ctx->conn_context, session_ctx->apdu_buffer, tx_len, session_ctx->apdu_buffer, &buff_len);
        if (ret != SM_OK) {
            SMLOG_E("Se05x_API_SessionOpen failed");
            goto cleanup;
        }
        session_ctx->applet_version = (session_ctx->apdu_buffer[0] << 24) | (session_ctx->apdu_buffer[1] << 16) |
                                      (session_ctx->apdu_buffer[2] << 8) | session_ctx->apdu_buffer[3];
        if (ret == SM_OK && buff_len >= 2) {
            ret = session_ctx->apdu_buffer[buff_len - 2];
            ret <<= 8;
            ret |= session_ctx->apdu_buffer[buff_len - 1];
        }
        ENSURE_OR_GO_CLEANUP(SM_OK == ret);
    }

#if defined(WITH_PLATFORM_SCP03)

    if (session_ctx->session_resume) {
        SMLOG_I("Resuming Secure Channel to SE05x !\n");
    }
    else {
        SMLOG_I("Establish Secure Channel to SE05x !\n");
        ret = Se05x_API_SCP03_CreateSession(session_ctx);
        if (ret == SM_OK) {
            SMLOG_I("Created scp03 Session\n");
        }
    }

#elif defined(WITH_ECKEY_SESSION)

    ret = Se05x_API_ECKey_CreateSession(session_ctx);
    if (ret == SM_OK) {
        SMLOG_I("Created ECKey Session\n");
    }

#elif defined(WITH_ECKEY_SCP03_SESSION)

    if (session_ctx->session_resume) {
        SMLOG_I("Resuming Secure Channel to SE05x !\n");
    }
    else {
        SMLOG_I("Establish Secure Channel to SE05x !\n");
        ret = Se05x_API_SCP03_CreateSession(session_ctx);
        if (ret == SM_OK) {
            SMLOG_I("Created scp03 Session\n");
        }
        else {
            goto cleanup;
        }
    }

    ret = Se05x_API_ECKey_CreateSession(session_ctx);
    if (ret == SM_OK) {
        SMLOG_I("Created ECKey Session\n");
    }

#endif

cleanup:
    if (ret != SM_OK) {
        if (session_ctx != NULL) {
            memset(session_ctx, 0, sizeof(Se05xSession_t));
        }
    }
    return ret;
}

smStatus_t Se05x_API_SessionClose(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)
    tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CLOSE}};
#endif

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_SessionClose [] \n");

#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)
    if (session_ctx->ecKey_session == 1) {
        retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, 0, 0);
        ENSURE_OR_GO_CLEANUP(retStatus == SM_OK);
    }

    Se05x_API_ECKey_CloseSession(session_ctx);
#endif

#if defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)
    //Se05x_API_SCP03_CloseSession(session_ctx);
#endif

    retStatus = smComT1oI2C_Close(session_ctx->conn_context, 0);
    ENSURE_OR_GO_CLEANUP(retStatus == SM_OK);

    if (session_ctx != NULL) {
        memset(session_ctx, 0, sizeof(Se05xSession_t));
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteECKey(pSe05xSession_t session_ctx,
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

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    if (Se05x_IsInValidRangeOfUID(objectID)) {
        return SM_NOT_OK;
    }

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

    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadObject(
    pSe05xSession_t session_ctx, uint32_t objectID, uint16_t offset, uint16_t length, uint8_t *data, size_t *pdataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - ReadObject [] \n");

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
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 1);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

    if (retStatus == SM_ERR_ACCESS_DENIED_BASED_ON_POLICY) {
        SMLOG_I("Denied to read object %08X bases on policy.", objectID);
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetVersion(pSe05xSession_t session_ctx, uint8_t *pappletVersion, size_t *appletVersionLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_VERSION}};
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - GetVersion [] \n");

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, 0, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pappletVersion, appletVersionLen);
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - ECDSASign [] \n");

    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECSignatureAlgo("ecSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_VERIFY}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - ECDSAVerify [] \n");

    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECSignatureAlgo("ecSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CheckObjectExists(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_EXIST}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - CheckObjectExists [] \n");

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteBinary(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_BINARY, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    if (Se05x_IsInValidRangeOfUID(objectID)) {
        return SM_NOT_OK;
    }

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
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDHGenerateSharedSecret(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    uint8_t *sharedSecret,
    size_t *psharedSecretLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_EC, kSE05x_P2_DH}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU -ECDHGenerateSharedSecret [] \n");

    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("pubKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, pubKey, pubKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, sharedSecret, psharedSecretLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CipherOneShot(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CipherMode_t cipherMode,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *IV,
    size_t IVLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_Cipher_Oper_OneShot_t operation)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_CIPHER, operation}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - CipherOneShot [] \n");

    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CipherMode("cipherMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cipherMode);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("IV", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, IV, IVLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteSymmKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_KeyID_t kekID,
    const uint8_t *keyValue,
    size_t keyValueLen,
    const SE05x_INS_t ins_type,
    const SE05x_SymmKeyType_t type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, type, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    if (Se05x_IsInValidRangeOfUID(objectID)) {
        return SM_NOT_OK;
    }

    SMLOG_D("APDU - WriteSymmKey [] \n");

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
    tlvRet = TLVSET_KeyID("KEK id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, kekID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("key value", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, keyValue, keyValueLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteSecureObject(pSe05xSession_t session_ctx, uint32_t objectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_DELETE_OBJECT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_DeleteSecureObject [] \n");

    pCmdbuf = &session_ctx->apdu_buffer[0];

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateSession(
    pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{0x80 /*kSE05x_CLA*/, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CREATE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_CreateSession [] \n");

    tlvRet = TLVSET_U32("auth", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, authObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, sessionId, psessionIdLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
    uint16_t outputOffset,
    uint8_t filter,
    uint8_t *pmore,
    uint8_t *idlist,
    size_t *pidlistLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_LIST}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = &session_ctx->apdu_buffer[0];
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspIndex      = 0;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_ReadIDList [] \n");

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    tlvRet = TLVSET_U16("output offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, outputOffset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("filter", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, filter);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pmore); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf,
            &rspIndex,
            rspbufLen,
            kSE05x_TAG_2,
            idlist,
            pidlistLen); /* Byte array containing 4-byte identifiers */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_SIZE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = &session_ctx->apdu_buffer[0];
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspIndex      = 0;
    size_t rspbufLen     = 0;

    SMLOG_D("APDU - Se05x_API_ReadSize [] \n");

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_U16(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, psize); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadType(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_SecureObjectType_t *ptype,
    uint8_t *pisTransient,
    const SE05x_AttestationType_t attestation_type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr  = {{kSE05x_CLA, (uint8_t)kSE05x_INS_READ | attestation_type, kSE05x_P1_DEFAULT, kSE05x_P2_TYPE}};
    uint8_t uType    = 0;
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &session_ctx->apdu_buffer[0];
    int tlvRet       = 0;
    uint8_t *pRspbuf = NULL;
    size_t rspIndex  = 0;
    size_t rspbufLen = 0;

    SMLOG_D("APDU - Se05x_API_ReadType [] \n");

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (ptype != NULL) {
            tlvRet = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, &uType);
            *ptype = (SE05x_SecureObjectType_t)uType;
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        tlvRet = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_2, pisTransient); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CURVE, kSE05x_P2_CREATE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_CreateECCurve [] \n");

    pCmdbuf = &session_ctx->apdu_buffer[0];

    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_CURVE, kSE05x_P2_DELETE_OBJECT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    SMLOG_D("APDU - Se05x_API_DeleteECCurve [] \n");

    pCmdbuf = &session_ctx->apdu_buffer[0];

    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetECCurveParam(pSe05xSession_t session_ctx,
    SE05x_ECCurve_t curveID,
    SE05x_ECCurveParam_t ecCurveParam,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CURVE, kSE05x_P2_PARAM}};

    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = NULL;
    int tlvRet       = 0;

    SMLOG_D("APDU - Se05x_API_SetECCurveParam [] \n");

    pCmdbuf = &session_ctx->apdu_buffer[0];

    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECCurveParam("ecCurveParam", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecCurveParam);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadECCurveList(pSe05xSession_t session_ctx, uint8_t *curveList, size_t *pcurveListLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CURVE, kSE05x_P2_LIST}};
    size_t cmdbufLen     = 0;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_ReadECCurveList [] \n");

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, curveList, pcurveListLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }
cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadObject_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *pCmdapdu,
    size_t *pCmdapduLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ_With_Attestation, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};

    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &session_ctx->apdu_buffer[0];
    int tlvRet       = 0;
    size_t rspbufLen = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    SMLOG_D("APDU - Se05x_API_ReadObject_W_Attst [] \n");
    SMLOG_D(
        "NOTE: Se05x_API_ReadObject_W_Attst API will return the secure element response as is. No parsing of the TLV "
        "is done.\n");

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = *pRspBufLen;

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

    tlvRet = TLVSET_U32("attestID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, attestID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    tlvRet = TLVSET_AttestationAlgo("attestAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, attestAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }

    tlvRet = TLVSET_u8bufOptional("random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, random, randomLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    if ((pCmdapdu != NULL) && (pCmdapduLen != NULL)) {
        if (*pCmdapduLen < 6) {
            goto cleanup;
        }
        memcpy(pCmdapdu, &hdr, 4);

        //As length is extended
        pCmdapdu[4] = 0x00;
        pCmdapdu[5] = 0x00;

        if (cmdbufLen == 0) {
            goto cleanup;
        }
        if (*pCmdapduLen < (cmdbufLen + 7)) {
            goto cleanup;
        }

        pCmdapdu[6] = (uint8_t)cmdbufLen;
        memcpy(pCmdapdu + 7, &session_ctx->apdu_buffer[0], cmdbufLen);
        *pCmdapduLen = cmdbufLen + 7;
    }

    retStatus = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdbufLen, pRspBuf, &rspbufLen, 1);
    if (retStatus == SM_OK) {
        *pRspBufLen = rspbufLen;
    }
    else {
        *pRspBufLen = 0;
    }

cleanup:
    return retStatus;
}
