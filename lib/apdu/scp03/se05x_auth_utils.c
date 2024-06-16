/** @file se05x_utils.c
 *  @brief Common util code to be used in scp03 and ECkey Auth.
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#if (defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION))

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "se05x_scp03_crypto.h"
#include "se05x_scp03.h"
#include <limits.h>

/* ********************** Functions ********************** */

smStatus_t Se05x_API_Auth_CalculateMacCmdApdu(uint8_t *sessionMacKey,
    uint8_t *mcv,
    uint8_t *inData,
    size_t inDataLen,
    uint8_t *outSignature,
    size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    cmac_ctx = hcrypto_cmac_setup(sessionMacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    memcpy(mcv, outSignature, SCP_MCV_LEN);
    return SM_OK;
}

smStatus_t Se05x_API_Auth_CalculateMacRspApdu(uint8_t *sessionRmacKey,
    uint8_t *mcv,
    uint8_t *inData,
    size_t inDataLen,
    uint8_t *outSignature,
    size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    cmac_ctx = hcrypto_cmac_setup(sessionRmacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(inDataLen >= 10, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen - 8 - 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, (inData + (inDataLen - 2)), 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    return SM_OK;
}

smStatus_t Se05x_API_Auth_PadCommandAPDU(uint8_t *cmdBuf, size_t *pCmdBufLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCmdBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= (*pCmdBufLen)), SM_NOT_OK);

    // pad the payload and adjust the length of the APDU
    cmdBuf[(*pCmdBufLen)] = SCP_DATA_PAD_BYTE;
    *pCmdBufLen += 1;
    zeroBytesToPad = (SCP_KEY_SIZE - ((*pCmdBufLen) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;
    while (zeroBytesToPad > 0) {
        cmdBuf[(*pCmdBufLen)] = 0x00;
        ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= (*pCmdBufLen)), SM_NOT_OK);
        *pCmdBufLen += 1;
        zeroBytesToPad--;
    }

    return SM_OK;
}

smStatus_t Se05x_API_Auth_CalculateCommandICV(uint8_t *sessionEncKey, uint8_t *cCounter, uint8_t *pIcv)
{
    int ret                      = 0;
    smStatus_t retStatus         = SM_NOT_OK;
    uint8_t ivZero[SCP_KEY_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    ret = hcrypto_aes_cbc_encrypt(sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, cCounter, pIcv, SCP_KEY_SIZE);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

static void Se05x_API_Auth_Dec_CmdCounter(uint8_t *pCtrblock)
{
    int i = 15;
    while (i > 0) {
        if (pCtrblock[i] == 0) {
            pCtrblock[i] = 0xFF;
            i--;
        }
        else {
            pCtrblock[i]--;
            break;
        }
    }

    return;
}

smStatus_t Se05x_API_Auth_GetResponseICV(bool hasCmd, uint8_t *cCounter, uint8_t *sessionEncKey, uint8_t *pIcv)
{
    uint8_t ivZero[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t dataLen                          = 0;
    uint8_t paddedCounterBlock[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int ret              = 0;
    smStatus_t retStatus = SM_NOT_OK;

    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    memcpy(paddedCounterBlock, cCounter, SCP_KEY_SIZE);
    if ((!hasCmd)) {
        Se05x_API_Auth_Dec_CmdCounter(paddedCounterBlock);
    }
    paddedCounterBlock[0] = SCP_DATA_PAD_BYTE; // MSB padded with 0x80 Section 6.2.7 of SCP03 spec
    dataLen               = SCP_KEY_SIZE;

    ret = hcrypto_aes_cbc_encrypt(
        sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, paddedCounterBlock, pIcv, dataLen);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

smStatus_t Se05x_API_Auth_RestoreSwRAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen, uint8_t *sw)
{
    size_t i            = plaintextRespLen;
    int removePaddingOk = 0;

    ENSURE_OR_RETURN_ON_ERROR(rspBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pRspBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(plaintextResponse != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(sw != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR((plaintextRespLen >= SCP_KEY_SIZE), SM_NOT_OK);

    while ((i > 1) && (i > (plaintextRespLen - SCP_KEY_SIZE))) {
        if (plaintextResponse[i - 1] == 0x00) {
            i--;
        }
        else if (plaintextResponse[i - 1] == SCP_DATA_PAD_BYTE) {
            // We have found padding delimitor
            memcpy(&plaintextResponse[i - 1], sw, SCP_GP_SW_LEN);

            if (*pRspBufLen < plaintextRespLen) {
                // response buffer is small
                return SM_NOT_OK;
            }
            ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= i), SM_NOT_OK);
            memcpy(rspBuf, plaintextResponse, i + 1);
            *pRspBufLen = (i + 1);

            removePaddingOk = 1;
            break;
        }
        else {
            // We've found a non-padding character while removing padding
            // Most likely the cipher text was not properly decoded.
            SMLOG_D("RAPDU Decoding failed No Padding found");
            break;
        }
    }

    if (removePaddingOk == 0) {
        return SM_NOT_OK;
    }

    return SM_OK;
}

void Se05x_API_Auth_IncCommandCounter(uint8_t *se05x_cCounter)
{
    int i = 15;

    if (se05x_cCounter == NULL) {
        return;
    }

    while (i > 0) {
        if (se05x_cCounter[i] < 255) {
            se05x_cCounter[i] += 1;
            break;
        }
        else {
            se05x_cCounter[i] = 0;
            i--;
        }
    }
    return;
}

int Se05x_API_Auth_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    const uint8_t *context,
    uint16_t contextLen)
{
    ENSURE_OR_RETURN_ON_ERROR(ddA != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pDdALen != NULL, 1);

    // SCPO3 spec p9&10
    memset(ddA, 0, DD_LABEL_LEN - 1);
    ddA[DD_LABEL_LEN - 1] = ddConstant;
    ddA[DD_LABEL_LEN]     = 0x00; // Separation Indicator
    ddA[DD_LABEL_LEN + 1] = (uint8_t)(ddL >> 8);
    ddA[DD_LABEL_LEN + 2] = (uint8_t)ddL;
    ddA[DD_LABEL_LEN + 3] = iCounter;
    if (context != NULL) {
        memcpy(&ddA[DD_LABEL_LEN + 4], context, contextLen);
    }
    *pDdALen = DD_LABEL_LEN + 4 + contextLen;

    return 0;
}

#endif //#if (defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION))
