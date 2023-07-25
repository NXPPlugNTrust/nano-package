/* Copyright 2023 DIMO
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************
 * Header Files
 *******************************************************************/
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "phNxpEse_Api.h"
#include "se05x_scp03.h"
#include "se05x_scp03_crypto.h"

#define kSE05x_CLA 0x80


extern uint8_t se05x_cCounter[SCP_KEY_SIZE];
extern uint8_t se05x_mcv[SCP_CMAC_SIZE];
extern uint8_t se05x_sessionEncKey[AES_KEY_LEN_nBYTE];
extern uint8_t se05x_sessionMacKey[AES_KEY_LEN_nBYTE];
extern uint8_t se05x_sessionRmacKey[AES_KEY_LEN_nBYTE];


void Se05x_API_SCP03_AESIncCommandCounter(pSe05xSession_t session_ctx)
{
    int i = 15;

    (void)session_ctx;

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


smStatus_t Se05x_API_SCP03_AESRestoreSwRAPDU(pSe05xSession_t session_ctx,
                                             uint8_t *rspBuf,
                                             size_t *pRspBufLen,
                                             uint8_t *plaintextResponse,
                                             size_t plaintextRespLen,
                                             uint8_t *sw)
{
    size_t i            = plaintextRespLen;
    int removePaddingOk = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rspBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pRspBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(plaintextResponse != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(sw != NULL, SM_NOT_OK);

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

static smStatus_t Se05x_API_SCP03_AESCalculateCommandICV(pSe05xSession_t session_ctx, uint8_t *pIcv)
{
    int ret                      = 0;
    smStatus_t retStatus         = SM_NOT_OK;
    uint8_t ivZero[SCP_KEY_SIZE] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    ret = hcrypto_aes_cbc_encrypt(se05x_sessionEncKey,
                                  AES_KEY_LEN_nBYTE,
                                  ivZero,
                                  SCP_KEY_SIZE,
                                  se05x_cCounter,
                                  pIcv,
                                  SCP_KEY_SIZE);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}


static smStatus_t Se05x_API_SCP03_AESGetResponseICV(pSe05xSession_t session_ctx, uint8_t *pIcv, bool hasCmd)
{
    uint8_t ivZero[SCP_IV_SIZE] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t dataLen                          = 0;
    uint8_t paddedCounterBlock[SCP_IV_SIZE] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int ret              = 0;
    smStatus_t retStatus = SM_NOT_OK;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    memcpy(paddedCounterBlock, se05x_cCounter, SCP_KEY_SIZE);
    if ((0 /*pdySCP03SessCtx->authType == kSSS_AuthType_SCP03*/) && (!hasCmd)) {
        nxpSCP03_Dec_CommandCounter(paddedCounterBlock);
    }
    paddedCounterBlock[0] = SCP_DATA_PAD_BYTE; // MSB padded with 0x80 Section 6.2.7 of SCP03 spec
    dataLen               = SCP_KEY_SIZE;

    ret = hcrypto_aes_cbc_encrypt(
            se05x_sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, paddedCounterBlock, pIcv, dataLen);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

static smStatus_t Se05x_API_SCP03_AESCalculateMacRspApdu(
        pSe05xSession_t session_ctx, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);

    cmac_ctx = hcrypto_cmac_setup(se05x_sessionRmacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen - 8 - 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, (inData + (inDataLen - 2)), 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    return SM_OK;
}


static smStatus_t Se05x_API_SCP03_AESCalculateMacCmdApdu(
        pSe05xSession_t session_ctx, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);

    cmac_ctx = hcrypto_cmac_setup(se05x_sessionMacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    memcpy(se05x_mcv, outSignature, SCP_MCV_LEN);
    return SM_OK;
}


static smStatus_t Se05x_API_SCP03_AESPadCommandAPDU(pSe05xSession_t session_ctx, uint8_t *cmdBuf, size_t *pCmdBufLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCmdBufLen != NULL, SM_NOT_OK);

    // pad the payload and adjust the length of the APDU
    cmdBuf[(*pCmdBufLen)] = SCP_DATA_PAD_BYTE;
    *pCmdBufLen += 1;
    zeroBytesToPad = (SCP_KEY_SIZE - ((*pCmdBufLen) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;
    while (zeroBytesToPad > 0) {
        cmdBuf[(*pCmdBufLen)] = 0x00;
        *pCmdBufLen += 1;
        zeroBytesToPad--;
    }

    return SM_OK;
}


static smStatus_t ex_se05x_aesauth_encrypt_data(pSe05xSession_t session_ctx,
                                         const tlvHeader_t *hdr,
                                         uint8_t *inBuf,
                                         size_t inBufLen,
                                         tlvHeader_t *outhdr,
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

    uint8_t *wsSe05x_cmd = NULL;

    ENSURE_OR_RETURN_ON_ERROR(hdr != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(inBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(outBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(poutBufLen != NULL, SM_NOT_OK);

    if (inBufLen != 0) {
        ENSURE_OR_RETURN_ON_ERROR(
                (Se05x_API_SCP03_AESPadCommandAPDU(session_ctx, inBuf, &inBufLen) == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_AESCalculateCommandICV(session_ctx, iv) == SM_OK), SM_NOT_OK);

        ret = hcrypto_aes_cbc_encrypt(
                se05x_sessionEncKey, AES_KEY_LEN_nBYTE, iv, SCP_KEY_SIZE, inBuf, inBuf, inBufLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);

        SMLOG_MAU8_D("nxSCP03_Encrypt_CommandAPDU", inBuf, inBufLen);
    }

    outhdr->hdr[0] = kSE05x_CLA;
    outhdr->hdr[1] = kSE05x_INS_PROCESS;
    outhdr->hdr[2] = kSE05x_P1_DEFAULT;
    outhdr->hdr[3] = kSE05x_P2_DEFAULT;

    se05xCmdLC  = inBufLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
    se05xCmdLCW = (se05xCmdLC == 0) ? 0 : (((se05xCmdLC < 0xFF) && !(hasle)) ? 1 : 3);

    //////////////////////////////////////////////////

    size_t wsSe05x_tag1Len = sizeof(*hdr) + se05xCmdLCW + se05xCmdLC;
    size_t wsSe05x_tag1W   = ((wsSe05x_tag1Len <= 0x7F) ? 1 : (wsSe05x_tag1Len <= 0xFF) ? 2 : 3);

    wsSe05x_cmd    = outBuf;
    uint8_t *wsCmd = wsSe05x_cmd;

    wsCmd[i++] = kSE05x_TAG_SESSION_ID;
    wsCmd[i++] = sizeof(session_ctx->session_id);
    memcpy(&wsCmd[i], session_ctx->session_id, sizeof(session_ctx->session_id));
    i += sizeof(session_ctx->session_id);

    wsCmd[i++] = kSE05x_TAG_1;

    if (wsSe05x_tag1W == 1) {
        wsCmd[i++] = (uint8_t)wsSe05x_tag1Len;
    }
    else if (wsSe05x_tag1W == 2) {
        wsCmd[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        wsCmd[i++] = (uint8_t)((wsSe05x_tag1Len >> 0 * 8) & 0xFF);
    }
    else if (wsSe05x_tag1W == 3) {
        wsCmd[i++] = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        wsCmd[i++] = (uint8_t)((wsSe05x_tag1Len >> 8) & 0xFF);
        wsCmd[i++] = (uint8_t)((wsSe05x_tag1Len)&0xFF);
    }

    uint8_t *wsSe05x_tag1Cmd  = &wsCmd[i];
    size_t wsSe05x_tag1CmdLen = sizeof(*(hdr)) + se05xCmdLCW + inBufLen;

    memcpy(&wsCmd[i], hdr, sizeof(*(hdr)));
    /* Pad CLA byte with 0x04 to indicate use of SCP03*/
    wsCmd[i] |= 0x04;
    i += sizeof(*(hdr));

    // In case there is a payload, indicate how long it is
    // in Lc in the header. Do not include an Lc in case there
    //is no payload.
    if (se05xCmdLCW > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if (se05xCmdLCW == 1) {
            wsCmd[i++] = (uint8_t)se05xCmdLC;
        }
        else {
            wsCmd[i++] = 0x00;
            wsCmd[i++] = 0xFFu & (se05xCmdLC >> 8);
            wsCmd[i++] = 0xFFu & (se05xCmdLC);
        }
    }

    memcpy(&wsCmd[i], inBuf, inBufLen);
    i += inBufLen;
    size_t wsSe05x_cmdLen = i;
    outBuf                = wsSe05x_tag1Cmd;
    i                     = wsSe05x_tag1CmdLen;

    //////////////////////////////////////////////////

    SMLOG_MAU8_D("Mac-ing", outBuf, i);

    ret = Se05x_API_SCP03_AESCalculateMacCmdApdu(session_ctx, outBuf, i, macData, &macDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

    SMLOG_MAU8_D("Mac-ed", macData, macDataLen);

    ENSURE_OR_RETURN_ON_ERROR(wsSe05x_cmdLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN <= (*poutBufLen), SM_NOT_OK);
    memcpy(&outBuf[i], macData, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    wsSe05x_cmdLen += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    *poutBufLen = wsSe05x_cmdLen;
    return SM_OK;
}

static smStatus_t ex_se05x_aesauth_decrypt_data(
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

    ENSURE_OR_RETURN_ON_ERROR(inBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(outBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pOutBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR((inBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

    apduStatus = inBuf[inBufLen - 2] << 8 | inBuf[inBufLen - 1];
    if (apduStatus == SM_OK) {
        memcpy(sw, &(inBuf[inBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);

        ret = Se05x_API_SCP03_AESCalculateMacRspApdu(session_ctx, inBuf, inBufLen, macData, &macDataLen);
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
            ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_AESGetResponseICV(session_ctx, iv, TRUE) == SM_OK), SM_NOT_OK);

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

            ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_AESRestoreSwRAPDU(
                                              session_ctx, outBuf, pOutBufLen, outBuf, actualRespLen, sw) == SM_OK),
                                      SM_NOT_OK);

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

    Se05x_API_SCP03_AESIncCommandCounter(session_ctx);

    return apduStatus;
}




smStatus_t Se05_API_AES_TransmitData(pSe05xSession_t session_ctx,
                                        const tlvHeader_t *hdr,
                                        uint8_t *cmdBuf,
                                        size_t cmdBufLen,
                                        uint8_t *rspBuf,
                                        size_t *pRspBufLen,
                                        uint8_t hasle)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t *pCmdbuf     = NULL;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = 0;
    tlvHeader_t hdr1     = {{kSE05x_CLA, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t tmpBuf[190]  = {0};


    size_t tmpBufLen = sizeof(tmpBuf);

    ENSURE_OR_GO_CLEANUP(session_ctx != NULL);

    pCmdbuf   = &session_ctx->apdu_buffer[0];
    pRspbuf   = &session_ctx->apdu_buffer[0];
    rspbufLen = sizeof(session_ctx->apdu_buffer);


    /* Wrapping in AESKey context */
    retStatus = ex_se05x_aesauth_encrypt_data(session_ctx,
                           hdr, session_ctx->apdu_buffer, cmdBufLen, &hdr1, tmpBuf, &tmpBufLen, hasle);

    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("AES WRAPPED", tmpBuf, tmpBufLen);

    retStatus = DoAPDUTxRx_Raw(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, hasle);

    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }
    tmpBufLen = sizeof(session_ctx->apdu_buffer);

    /* Unwrapping from AESKey context */
    retStatus =
            ex_se05x_aesauth_decrypt_data(session_ctx, pRspbuf, rspbufLen, &session_ctx->apdu_buffer[0], &tmpBufLen);

    if (retStatus != SM_OK) {
        return SM_NOT_OK;
    }

    // set the response length after decrypting
    *pRspBufLen = tmpBufLen;

cleanup:
    return retStatus;
}

