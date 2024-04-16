
/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "sa_qi_transmitter.h"
#include "sa_qi_transmitter_helpers.h"
// #if defined(FLOW_VERBOSE)
// #define NX_LOG_ENABLE_QI_DEBUG 1
// #endif // FLOW_VERBOSE
// #include "nxLog_Qi.h"

#include "se05x_APDU_apis.h"
#include "sa_qi_nano_helper_apis.h"

/* ********************** Defines ********************** */
#define kSE05x_CLA 0x80
#define kSE05x_P2_INIT 0x0B
#define kSE05x_P2_UPDATE 0x0C
#define kSE05x_P2_FINAL 0x0D
#define kSE05x_P1_CRYPTO_OBJ 0x10
#define TLVSET_CryptoObjectID TLVSET_U16
#define TLVSET_CryptoContext TLVSET_U8
#define TLVSET_CryptoModeSubType(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    TLVSET_U8(DESCRIPTION, PBUF, PBUFLEN, TAG, ((VALUE).union_8bit))

static int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint16_t *pRsp);

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
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - ReadIdList []");

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

smStatus_t Se05x_API_ReadCryptoObjectList(pSe05xSession_t session_ctx, uint8_t *idlist, size_t *pidlistLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_LIST}};
    size_t cmdbufLen     = 0;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_ReadCryptoObjectList []");

    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet =
            tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, idlist, pidlistLen); /* If more ids are present */
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

smStatus_t Se05x_API_CreateCryptoObject(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    SE05x_CryptoContext_t cryptoContext,
    SE05x_CryptoModeSubType_t subtype)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_DEFAULT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - Se05x_API_CreateCryptoObject []");

    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoContext("cryptoContext", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoContext);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoModeSubType(
        "1-byte Crypto Object subtype, either from DigestMode, CipherMode or "
        "MACAlgo (depending on TAG_2).",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_TAG_3,
        subtype);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteCryptoObject(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_DELETE_OBJECT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - Se05x_API_DeleteCryptoObject []");

    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestInit(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_INIT}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - Se05x_API_DigestInit []");

    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestUpdate(
    pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID, const uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_UPDATE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf = &session_ctx->apdu_buffer[0];

    SMLOG_D("APDU - Se05x_API_DigestUpdate []");

    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, 0);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmacValue,
    size_t *pcmacValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_FINAL}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - Se05x_API_DigestFinal []");

    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, cmacValue, pcmacValueLen); /*  */
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

// smStatus_t Se05x_API_DigestOneShot(pSe05xSession_t session_ctx,
//     uint8_t digestMode,
//     const uint8_t *inputData,
//     size_t inputDataLen,
//     uint8_t *hashValue,
//     size_t *phashValueLen)
// {
//     smStatus_t retStatus = SM_NOT_OK;
//     tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO,
//     kSE05x_P1_DEFAULT, kSE05x_P2_ONESHOT}}; size_t cmdbufLen     = 0; uint8_t
//     *pCmdbuf     = NULL; int tlvRet           = 0; uint8_t *pRspbuf     =
//     NULL; size_t rspbufLen     = 0;

//     ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

//     pCmdbuf   = &session_ctx->apdu_buffer[0];
//     pRspbuf   = &session_ctx->apdu_buffer[0];
//     rspbufLen = sizeof(session_ctx->apdu_buffer);

//     SMLOG_D("APDU - DigestOneShot []");

//     tlvRet = TLVSET_U8("digestMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1,
//     digestMode); if (0 != tlvRet) {
//         goto cleanup;
//     }
//     tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2,
//     inputData, inputDataLen); if (0 != tlvRet) {
//         goto cleanup;
//     }
//     retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer,
//     cmdbufLen, pRspbuf, &rspbufLen, 0); if (retStatus == SM_OK) {
//         retStatus       = SM_NOT_OK;
//         size_t rspIndex = 0;
//         tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen,
//         kSE05x_TAG_1, hashValue, phashValueLen); /*  */ if (0 != tlvRet) {
//             goto cleanup;
//         }
//         if ((rspIndex + 2) == rspbufLen) {
//             retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
//         }
//     }

// cleanup:
//     return retStatus;
// }

smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_SIZE}};
    size_t cmdbufLen     = 0;
    uint8_t *pCmdbuf     = NULL;
    int tlvRet           = 0;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);

    SMLOG_D("APDU - ReadSize []");

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx(session_ctx, &hdr, session_ctx->apdu_buffer, cmdbufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U16(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, psize); /* - */
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

static int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint16_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t rspLen;

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 2) {
        goto cleanup;
    }
    *pRsp = (*pBuf++) << 8;
    *pRsp |= *pBuf++;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}