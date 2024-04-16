/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_qi_transmitter.h"
#include "sa_qi_transmitter_helpers.h"
#include "sa_qi_tx_port.h"

#if defined(FLOW_VERBOSE)
#define NX_LOG_ENABLE_QI_DEBUG 1
#endif // FLOW_VERBOSE
#include "nxLog_Qi.h"

#include <string.h>

smStatus_t getPopulatedSlots(pSe05xSession_t session_ctx, uint8_t *pSlotsPopulated)
{
    smStatus_t retStatus            = SM_NOT_OK;
    uint8_t pmore                   = kSE05x_MoreIndicator_NA;
    uint8_t list[READ_ID_LIST_SIZE] = {0};
    size_t listlen                  = sizeof(list);
    /* List all provisioned Binary objects */
    retStatus = Se05x_API_ReadIDList(session_ctx, 0 /* Offset */, kSE05x_SecObjTyp_BINARY_FILE, &pmore, list, &listlen);
    if (retStatus != SM_OK) {
        LOG_E("Failed Se05x_API_ReadIDList");
        goto exit;
    }

    /* Check which Qi slots are provisioned by iterating over the object list */
    for (size_t i = 0; i < listlen; i += 4) {
        uint32_t id = 0 | (list[i + 0] << (3 * 8)) | (list[i + 1] << (2 * 8)) | (list[i + 2] << (1 * 8)) |
                      (list[i + 3] << (0 * 8));
        LOG_D("object Id - %08X", id);
        if (id == QI_SLOT_ID_TO_CERT_ID(0)) {
            *pSlotsPopulated = *pSlotsPopulated | (1 << 0);
        }
        else if (id == QI_SLOT_ID_TO_CERT_ID(1)) {
            *pSlotsPopulated = *pSlotsPopulated | (1 << 1);
        }
        else if (id == QI_SLOT_ID_TO_CERT_ID(2)) {
            *pSlotsPopulated = *pSlotsPopulated | (1 << 2);
        }
        else if (id == QI_SLOT_ID_TO_CERT_ID(3)) {
            *pSlotsPopulated = *pSlotsPopulated | (1 << 3);
        }
    }

exit:
    return retStatus;
}

smStatus_t EcSignatureToRandS(uint8_t *signature, size_t *sigLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    ;
    uint8_t rands[128] = {0};
    int index          = 0;
    size_t i           = 0;
    size_t len         = 0;
    if (signature[index++] != 0x30) {
        goto exit;
    }
    if (signature[index++] != (*sigLen - 2)) {
        goto exit;
    }
    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    for (i = 0; i < len; i++) {
        rands[i] = signature[index++];
    }

    if (signature[index++] != 0x02) {
        goto exit;
    }

    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    len = len + i;
    for (; i < len; i++) {
        rands[i] = signature[index++];
    }

    memcpy(&signature[0], &rands[0], i);
    *sigLen = i;

    retStatus = SM_OK;

exit:
    return retStatus;
}

smStatus_t getSha256Hash(
    pSe05xSession_t session_ctx, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen)
{
    smStatus_t sm_status = SM_NOT_OK;
    size_t chunk         = 0;
    size_t offset        = 0;
    SE05x_CryptoModeSubType_t subtype;
    subtype.digest         = kSE05x_DigestMode_SHA256;
    bool create_crypto_obj = true;
    uint8_t list[1024]     = {
        0,
    };
    size_t listlen = sizeof(list);

    sm_status = Se05x_API_ReadCryptoObjectList(session_ctx, list, &listlen);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);

    for (size_t i = 0; i < listlen; i += 4) {
        uint16_t cryptoObjectId = list[i + 1] | (list[i + 0] << 8);
        if (cryptoObjectId == kSE05x_CryptoObject_DIGEST_SHA256) {
            create_crypto_obj = false;
        }
    }

    if (create_crypto_obj) {
        sm_status = Se05x_API_CreateCryptoObject(
            session_ctx, kSE05x_CryptoObject_DIGEST_SHA256, kSE05x_CryptoContext_DIGEST, subtype);
        ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    }

    sm_status = Se05x_API_DigestInit(session_ctx, kSE05x_CryptoObject_DIGEST_SHA256);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);

    do {
        chunk     = (inputLen > BINARY_WRITE_MAX_LEN) ? BINARY_WRITE_MAX_LEN : inputLen;
        sm_status = Se05x_API_DigestUpdate(session_ctx, kSE05x_CryptoObject_DIGEST_SHA256, pInput + offset, chunk);
        ENSURE_OR_GO_EXIT(SM_OK == sm_status);
        offset += chunk;
        inputLen -= chunk;
    } while (inputLen > 0);

    sm_status = Se05x_API_DigestFinal(session_ctx, kSE05x_CryptoObject_DIGEST_SHA256, NULL, 0, pOutput, pOutputLen);
    if (SM_OK != sm_status) {
        LOG_E("Se05x_API_DigestFinal failed");
    }

exit:
    if(SM_OK != Se05x_API_DeleteCryptoObject(session_ctx, kSE05x_CryptoObject_DIGEST_SHA256)){
        LOG_E("Se05x_API_DeleteCryptoObject failed");
    }

    return sm_status;
}

smStatus_t readObjectWithChunking(pSe05xSession_t session_ctx,
    uint32_t certChainId,
    uint16_t offset,
    uint16_t bytesToRead,
    uint8_t *pData,
    size_t *pdataLen)
{
    smStatus_t retStatus       = SM_NOT_OK;
    size_t outputSizeRemaining = *pdataLen;
    size_t readSize            = *pdataLen;
    uint16_t chunk             = 0;
    uint16_t chunkOffset       = 0;

    do {
        chunk = (bytesToRead > BINARY_WRITE_MAX_LEN) ? BINARY_WRITE_MAX_LEN : bytesToRead;
        retStatus =
            Se05x_API_ReadObject(session_ctx, certChainId, offset + chunkOffset, chunk, pData + chunkOffset, &readSize);
        if (retStatus != SM_OK) {
            break;
        }
        chunkOffset += chunk;
        bytesToRead -= chunk;
        outputSizeRemaining = outputSizeRemaining - readSize;
        readSize            = outputSizeRemaining;
    } while (0 != bytesToRead);

    *pdataLen = *pdataLen - outputSizeRemaining;

    return retStatus;
}

smStatus_t getManufacturerCertificateLength(pSe05xSession_t session_ctx, uint32_t certChainId, uint16_t *N_MC)
{
    smStatus_t retStatus        = SM_NOT_OK;
    uint16_t offsetMC           = DIGEST_SIZE_BYTES + 2 + DIGEST_SIZE_BYTES + 1;
    uint8_t certMCLengthBuff[3] = {0};
    size_t certMCLengthBuff_len = sizeof(certMCLengthBuff);

    retStatus = Se05x_API_ReadObject(session_ctx, certChainId, offsetMC, 0x03, certMCLengthBuff, &certMCLengthBuff_len);
    if (retStatus != SM_OK) {
        LOG_E("Se05x_API_ReadObject failed");
        return retStatus;
    }

    if ((certMCLengthBuff[0] & 0x80) == 0x80) {
        if ((certMCLengthBuff[0] & 0x7F) == 0x01) {
            *N_MC = certMCLengthBuff[1] + 3;
        }
        else if ((certMCLengthBuff[0] & 0x7F) == 0x02) {
            *N_MC = ((certMCLengthBuff[1] << 8) + certMCLengthBuff[2]) + 4;
        }
    }
    else {
        *N_MC = (certMCLengthBuff[0]) + 2;
    }

    return retStatus;
}
