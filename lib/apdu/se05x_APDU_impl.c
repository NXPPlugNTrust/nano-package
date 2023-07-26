/** @file se05x_APDU_impl.c
 *  @brief Se05x APDU function implementation.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "phNxpEse_Api.h"

/* ********************** Defines ********************** */
#define kSE05x_CLA 0x80
#define CLA_ISO7816 (0x00)   //!< ISO7816-4 defined CLA byte
#define INS_GP_SELECT (0xA4) //!< Global platform defined instruction

/* clang-format off */
#define APPLET_NAME { 0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 }
#define SSD_NAME {0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03}
/* clang-format on */

/* ********************** Function Prototypes ********************** */
smStatus_t Se05x_API_SCP03_CreateSession(pSe05xSession_t session_ctx);


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
    unsigned char ssdName[] = SSD_NAME;
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
        if(!session_ctx->has_encrypted_session) {
            return ret;
        }
        appSsdName    = &ssdName[0];
        appSsdNameLen = sizeof(ssdName);
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

        if (ret == SM_OK && buff_len >= 2) {
            ret = session_ctx->apdu_buffer[buff_len - 2];
            ret <<= 8;
            ret |= session_ctx->apdu_buffer[buff_len - 1];
        }
        ENSURE_OR_GO_CLEANUP(SM_OK == ret);
    }

    if (session_ctx->has_encrypted_session) {
        if (session_ctx->session_resume) {
            SMLOG_I("Resuming Secure Channel to SE05x !\n");
        } else {
            SMLOG_I("Establish Secure Channel to SE05x !\n");
            ret = Se05x_API_SCP03_CreateSession(session_ctx);
        }
    }

cleanup:
    return ret;
}

smStatus_t Se05x_API_SessionClose(pSe05xSession_t session_ctx)
{
    SMLOG_D("APDU - Se05x_API_SessionClose [] \n");
    return smComT1oI2C_Close(session_ctx->conn_context, 0);
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

    SMLOG_D("APDU -ECDSAVerify [] \n");

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

smStatus_t Se05x_API_ReadECCurveList(pSe05xSession_t session_ctx, uint8_t *data, size_t *pdataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CURVE, kSE05x_P2_LIST}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    memset(session_ctx->apdu_buffer, 0, sizeof(session_ctx->apdu_buffer));

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_ReadECCurveList [] \n");

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
        SMLOG_I("Denied to ReadECCurveList");
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CURVE, kSE05x_P2_CREATE}};
    uint8_t *cmdbuf = session_ctx->apdu_buffer;
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    SMLOG_D("APDU - CreateECCurve [] \n");

    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, cmdbuf, cmdbufLen, 0);

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
    uint8_t *cmdbuf = session_ctx->apdu_buffer;
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    SMLOG_D("APDU - SetECCurveParam []");

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
    retStatus = DoAPDUTx(session_ctx, &hdr, cmdbuf, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_CURVE, kSE05x_P2_DELETE_OBJECT}};
    uint8_t *cmdbuf = session_ctx->apdu_buffer;
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    SMLOG_D("APDU - DeleteECCurve []");

    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, cmdbuf, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetRandom(pSe05xSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_RANDOM}};
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = session_ctx->apdu_buffer;
    int tlvRet = 0;
    uint8_t *pRspbuf = session_ctx->apdu_buffer;
    size_t rspbufLen  = sizeof(session_ctx->apdu_buffer);

    memset(session_ctx->apdu_buffer, 0, sizeof(session_ctx->apdu_buffer));

    SMLOG_D("APDU - GetRandom []");

    tlvRet = TLVSET_U16("size", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, size);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 1);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, randomData, prandomDataLen);
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

smStatus_t Se05x_API_CreateSession(
        pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CREATE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = session_ctx->apdu_buffer;
    int tlvRet = 0;
    uint8_t *pRspbuf = session_ctx->apdu_buffer;
    size_t rspbufLen =  sizeof(session_ctx->apdu_buffer);

#if VERBOSE_APDU_LOGS
    SMLOG_D("CreateSession []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("auth", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, authObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_Raw(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);

    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, sessionId, psessionIdLen);
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

smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
                                uint16_t outputOffset,
                                uint8_t filter,
                                uint8_t *pmore,
                                uint8_t *idlist,
                                size_t *pidlistLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_LIST}};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = session_ctx->apdu_buffer;
    int tlvRet                             = 0;
    uint8_t *pRspbuf                       = session_ctx->apdu_buffer;
    size_t rspbufLen                       = sizeof(session_ctx->apdu_buffer);

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadIDList []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U16("output offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, outputOffset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("filter", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, filter);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pmore); /* - */
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

smStatus_t Se05x_API_ReadType(pSe05xSession_t session_ctx,
                              uint32_t objectID,
                              SE05x_SecureObjectType_t *ptype,
                              uint8_t *pisTransient,
                              const SE05x_AttestationType_t attestation_type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ | attestation_type, kSE05x_P1_DEFAULT, kSE05x_P2_TYPE}};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = session_ctx->apdu_buffer;
    int tlvRet                             = 0;
    uint8_t *pRspbuf                       = session_ctx->apdu_buffer;
    size_t rspbufLen                       = sizeof(session_ctx->apdu_buffer);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadType []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_SecureObjectType(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, ptype); /* - */
        if (0 != tlvRet) {
            goto cleanup;
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

smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_SIZE}};
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = session_ctx->apdu_buffer;
    int tlvRet                             = 0;
    uint8_t *pRspbuf                       = session_ctx->apdu_buffer;
    size_t rspbufLen                       = sizeof(session_ctx->apdu_buffer);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadSize []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);

    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u16(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, psize); /* - */
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



#if 1
/* secp256k1 : SECG curve over a 256 bit prime field */
#define EC_PARAM_secp256k1_prime  \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
#define EC_PARAM_secp256k1_a      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define EC_PARAM_secp256k1_b      \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07
#define EC_PARAM_secp256k1_x      \
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, \
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, \
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, \
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
#define EC_PARAM_secp256k1_y      \
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, \
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, \
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, \
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
#define EC_PARAM_secp256k1_order  \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, \
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, \
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
#endif

#if 1
/* prime256v1 : X9.62/SECG curve over a 256 bit prime field */
#define EC_PARAM_prime256v1_prime  \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
#define EC_PARAM_prime256v1_a      \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
#define EC_PARAM_prime256v1_b      \
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, \
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, \
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, \
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
#define EC_PARAM_prime256v1_x      \
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, \
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, \
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, \
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
#define EC_PARAM_prime256v1_y      \
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, \
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, \
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, \
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
#define EC_PARAM_prime256v1_order  \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, \
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
#endif


#define PROCESS_ECC_CURVE(NAME)                                                                                    \
    smStatus_t Se05x_API_CreateCurve_##NAME(Se05xSession_t *pSession, uint32_t obj_id)                             \
    {                                                                                                              \
        smStatus_t status;                                                                                         \
        const uint8_t ecc_prime[]  = {EC_PARAM_##NAME##_prime};                                                    \
        const uint8_t ecc_a[]      = {EC_PARAM_##NAME##_a};                                                        \
        const uint8_t ecc_b[]      = {EC_PARAM_##NAME##_b};                                                        \
        const uint8_t ecc_G[]      = {0x04, EC_PARAM_##NAME##_x, EC_PARAM_##NAME##_y};                             \
        const uint8_t ecc_ordern[] = {EC_PARAM_##NAME##_order};                                                    \
                                                                                                                   \
        status = Se05x_API_DeleteECCurve(pSession, (SE05x_ECCurve_t)obj_id);                                       \
                                                                                                                   \
        status = Se05x_API_CreateECCurve(pSession, (SE05x_ECCurve_t)obj_id);                                       \
        if (status != SM_OK) {                                                                                     \
            return status;                                                                                         \
        }                                                                                                          \
                                                                                                                   \
        status = Se05x_API_SetECCurveParam(                                                                        \
            pSession, (SE05x_ECCurve_t)obj_id, kSE05x_ECCurveParam_PARAM_A, ecc_a, ARRAY_SIZE(ecc_a));             \
        if (status != SM_OK) {                                                                                     \
            return status;                                                                                         \
        }                                                                                                          \
                                                                                                                   \
        status = Se05x_API_SetECCurveParam(                                                                        \
            pSession, (SE05x_ECCurve_t)obj_id, kSE05x_ECCurveParam_PARAM_B, ecc_b, ARRAY_SIZE(ecc_b));             \
        if (status != SM_OK) {                                                                                     \
            return status;                                                                                         \
        }                                                                                                          \
                                                                                                                   \
        status = Se05x_API_SetECCurveParam(                                                                        \
            pSession, (SE05x_ECCurve_t)obj_id, kSE05x_ECCurveParam_PARAM_G, ecc_G, ARRAY_SIZE(ecc_G));             \
        if (status != SM_OK) {                                                                                     \
            return status;                                                                                         \
        }                                                                                                          \
                                                                                                                   \
        status = Se05x_API_SetECCurveParam(                                                                        \
            pSession, (SE05x_ECCurve_t)obj_id, kSE05x_ECCurveParam_PARAM_N, ecc_ordern, ARRAY_SIZE(ecc_ordern));   \
        if (status != SM_OK) {                                                                                     \
            return status;                                                                                         \
        }                                                                                                          \
                                                                                                                   \
        status = Se05x_API_SetECCurveParam(                                                                        \
            pSession, (SE05x_ECCurve_t)obj_id, kSE05x_ECCurveParam_PARAM_PRIME, ecc_prime, ARRAY_SIZE(ecc_prime)); \
        return status;                                                                                             \
    }

PROCESS_ECC_CURVE(secp256k1)
PROCESS_ECC_CURVE(prime256v1)
