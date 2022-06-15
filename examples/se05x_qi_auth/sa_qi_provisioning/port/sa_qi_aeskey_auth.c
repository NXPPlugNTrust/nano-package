/** @file se05x_scp03.c
 *  @brief Se05x SCP03 implementation.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "se05x_scp03_crypto.h"
#include "se05x_scp03.h"
#include "sa_qi_port.h"

/* ********************** Global variables ********************** */
#define kSE05x_CLA 0x80

static uint8_t se05x_aesauth_sessionEncKey[AES_KEY_LEN_nBYTE] = {
    0,
};
static uint8_t se05x_aesauth_sessionMacKey[AES_KEY_LEN_nBYTE] = {
    0,
};
static uint8_t se05x_aesauth_sessionRmacKey[AES_KEY_LEN_nBYTE] = {
    0,
};
static uint8_t se05x_aesauth_cCounter[16] = {
    0,
};
static uint8_t se05x_aesauth_mcv[SCP_CMAC_SIZE] = {
    0,
};
extern uint8_t se05x_applet_session_value[8];

extern pSe05xSession_t p_aes_session_ctx;

/* ********************** Functions ********************** */

smStatus_t ex_se05x_process_session_command(const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *out,
    size_t *outLen,
    size_t hasle);

static int nxScp03_GP_InitializeUpdate(pSe05xSession_t session_ctx,
    uint8_t *hostChallenge,
    size_t hostChallengeLen,
    uint8_t *keyDivData,
    uint16_t *pKeyDivDataLen,
    uint8_t *keyInfo,
    uint16_t *pKeyInfoLen,
    uint8_t *cardChallenge,
    uint16_t *pCardChallengeLen,
    uint8_t *cardCryptoGram,
    uint16_t *pCardCryptoGramLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t keyVersion   = 0x00;
    uint8_t *pRspbuf     = NULL;
    size_t rspbufLen     = sizeof(session_ctx->apdu_buffer);
    tlvHeader_t hdr      = {{CLA_GP_7816, INS_GP_INITIALIZE_UPDATE, keyVersion, 0x00}};
    uint8_t tmpBuf[64]   = {
        0,
    };
    size_t tmpBufLen            = sizeof(tmpBuf);
    tlvHeader_t hdr1            = {0};
    uint16_t parsePos           = 0;
    uint32_t iuResponseLenSmall = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                  SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_SW_LEN;
    uint32_t iuResponseLenBig = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_IU_SEQ_COUNTER_LEN + SCP_GP_SW_LEN;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(keyDivData != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pKeyDivDataLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(keyInfo != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pKeyInfoLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pCardChallengeLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardCryptoGram != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pCardCryptoGramLen != NULL, 1);

    ENSURE_OR_RETURN_ON_ERROR(*pKeyDivDataLen == SCP_GP_IU_KEY_DIV_DATA_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pKeyInfoLen == SCP_GP_IU_KEY_INFO_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardChallengeLen == SCP_GP_CARD_CHALLENGE_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardCryptoGramLen == SCP_GP_IU_CARD_CRYPTOGRAM_LEN, 1);

    pRspbuf = &session_ctx->apdu_buffer[0];

    // memcpy(session_ctx->apdu_buffer, &hdr, 4);
    // session_ctx->apdu_buffer[4] = hostChallengeLen;

    // ENSURE_OR_RETURN_ON_ERROR((hostChallengeLen + 5) < MAX_APDU_BUFFER, 1);
    memcpy((session_ctx->apdu_buffer), hostChallenge, hostChallengeLen);

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_process_session_command(
        &hdr, session_ctx->apdu_buffer, hostChallengeLen, &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return 1;
    }

    SMLOG_D("Sending GP Initialize Update Command !!! \n");
    retStatus = DoAPDUTxRx(session_ctx, &hdr1, tmpBuf, tmpBufLen, pRspbuf, &rspbufLen, 0);
    if (retStatus != SM_OK) {
        SMLOG_D("Error in sending GP Initialize Update Command \n");
        return 1;
    }

    // Parse Response
    // The expected result length depends on random (HOST-Channel) or pseudo-random (ADMIN-Channel) challenge type.
    // The pseudo-random challenge case also includes a 3 byte sequence counter
    if ((rspbufLen != iuResponseLenSmall) && (rspbufLen != iuResponseLenBig)) {
        // Note: A response of length 2 (a proper SW) is also collapsed into return code SCP_FAIL
        SMLOG_D("GP_InitializeUpdate Unexpected amount of data returned \n");
        return 1;
    }

    memcpy(keyDivData, pRspbuf, SCP_GP_IU_KEY_DIV_DATA_LEN);
    parsePos = SCP_GP_IU_KEY_DIV_DATA_LEN;
    memcpy(keyInfo, &(pRspbuf[parsePos]), SCP_GP_IU_KEY_INFO_LEN);
    parsePos += SCP_GP_IU_KEY_INFO_LEN;
    memcpy(cardChallenge, &(pRspbuf[parsePos]), SCP_GP_CARD_CHALLENGE_LEN);
    parsePos += SCP_GP_CARD_CHALLENGE_LEN;
    memcpy(cardCryptoGram, &(pRspbuf[parsePos]), SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    parsePos += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    // Construct Return Value
    retStatus = (pRspbuf[rspbufLen - 2] << 8) + pRspbuf[rspbufLen - 1];
    if (retStatus == SM_OK) {
        SMLOG_MAU8_D(" Output: keyDivData", keyDivData, *pKeyDivDataLen);
        SMLOG_MAU8_D(" Output: keyInfo", keyInfo, *pKeyInfoLen);
        SMLOG_MAU8_D(" Output: cardChallenge", cardChallenge, *pCardChallengeLen);
        SMLOG_MAU8_D(" Output: cardCryptoGram", cardCryptoGram, *pCardCryptoGramLen);
    }
    else {
        return 1;
    }

    return 0;
}

static int nxScp03_Generate_SessionKey(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(inData != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(outSignature != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(outSignatureLen != NULL, 1);
    return hcrypto_cmac_oneshot(key, keylen, inData, inDataLen, outSignature, outSignatureLen);
}

static int nxScp03_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    const uint8_t *context,
    uint16_t contextLen)
{
    ENSURE_OR_RETURN_ON_ERROR(ddA != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pDdALen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(context != NULL, 1);

    // SCPO3 spec p9&10
    memset(ddA, 0, DD_LABEL_LEN - 1);
    ddA[DD_LABEL_LEN - 1] = ddConstant;
    ddA[DD_LABEL_LEN]     = 0x00; // Separation Indicator
    ddA[DD_LABEL_LEN + 1] = (uint8_t)(ddL >> 8);
    ddA[DD_LABEL_LEN + 2] = (uint8_t)ddL;
    ddA[DD_LABEL_LEN + 3] = iCounter;
    memcpy(&ddA[DD_LABEL_LEN + 4], context, contextLen);
    *pDdALen = DD_LABEL_LEN + 4 + contextLen;

    return 0;
}

static int nxScp03_HostLocal_CalculateSessionKeys(
    pSe05xSession_t session_ctx, uint8_t *hostChallenge, uint8_t *cardChallenge)
{
    int ret             = 0;
    uint8_t *ddA        = NULL;
    uint16_t ddALen     = DAA_BUFFER_LEN;
    uint8_t *context    = NULL;
    uint16_t contextLen = 0;
    size_t signatureLen = AES_KEY_LEN_nBYTE;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH

    // Calculate the Derviation data
    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session ENC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    // Calculate the Session-ENC key
    ret = nxScp03_Generate_SessionKey(p_aes_session_ctx->pScp03_enc_key,
        p_aes_session_ctx->scp03_enc_key_len,
        ddA,
        ddALen,
        se05x_aesauth_sessionEncKey,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:se05x_aesauth_sessionEncKey ==>", se05x_aesauth_sessionEncKey, AES_KEY_LEN_nBYTE);

    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session MAC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-MAC key
    ret = nxScp03_Generate_SessionKey(p_aes_session_ctx->pScp03_mac_key,
        p_aes_session_ctx->scp03_mac_key_len,
        ddA,
        ddALen,
        se05x_aesauth_sessionMacKey,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:se05x_aesauth_sessionMacKey ==>", se05x_aesauth_sessionMacKey, AES_KEY_LEN_nBYTE);

    /* Generation and Creation of Session RMAC SSS Key Object */
    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session RMAC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-RMAC key
    ret = nxScp03_Generate_SessionKey(p_aes_session_ctx->pScp03_mac_key,
        p_aes_session_ctx->scp03_mac_key_len,
        ddA,
        ddALen,
        se05x_aesauth_sessionRmacKey,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D("Output:se05x_aesauth_sessionRmacKey ==>", se05x_aesauth_sessionRmacKey, AES_KEY_LEN_nBYTE);

    return 0;
}

static int nxScp03_HostLocal_VerifyCardCryptogram(pSe05xSession_t session_ctx,
    uint8_t *key,
    size_t keylen,
    uint8_t *hostChallenge,
    uint8_t *cardChallenge,
    uint8_t *cardCryptogram)
{
    uint8_t *ddA                      = NULL;
    uint16_t ddALen                   = DAA_BUFFER_LEN;
    uint8_t *context                  = NULL;
    uint16_t contextLen               = 0;
    uint8_t *cardCryptogramFullLength = NULL;
    size_t signatureLen               = AES_KEY_LEN_nBYTE;
    int ret                           = 0;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH + AES_KEY_LEN_nBYTE) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardCryptogram != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH
    cardCryptogramFullLength =
        (session_ctx->apdu_buffer + DAA_BUFFER_LEN + CONTEXT_LENGTH); // Len --> AES_KEY_LEN_nBYTE

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_CARD_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    ret = nxScp03_Generate_SessionKey(key, keylen, ddA, ddALen, cardCryptogramFullLength, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:cardCryptogram ==>", cardCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Verify whether the 8 left most byte of cardCryptogramFullLength match cardCryptogram
    if (memcmp(cardCryptogramFullLength, cardCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != 0) {
        return 1;
    }

    return 0;
}

static int nxScp03_HostLocal_CalculateHostCryptogram(pSe05xSession_t session_ctx,
    uint8_t *key,
    size_t keylen,
    uint8_t *hostChallenge,
    uint8_t *cardChallenge,
    uint8_t *hostCryptogram)
{
    uint8_t *ddA                      = NULL;
    uint16_t ddALen                   = DAA_BUFFER_LEN;
    uint8_t *context                  = NULL;
    uint16_t contextLen               = 0;
    uint8_t *hostCryptogramFullLength = NULL;
    size_t signatureLen               = AES_KEY_LEN_nBYTE;
    int ret                           = 0;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH + AES_KEY_LEN_nBYTE) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostCryptogram != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH
    hostCryptogramFullLength =
        (session_ctx->apdu_buffer + DAA_BUFFER_LEN + CONTEXT_LENGTH); // Len --> AES_KEY_LEN_nBYTE

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_HOST_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    ret = nxScp03_Generate_SessionKey(key, keylen, ddA, ddALen, hostCryptogramFullLength, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }

    SMLOG_MAU8_D(" Output:hostCryptogram ==>", hostCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Chop of the tail of the hostCryptogramFullLength
    memcpy(hostCryptogram, hostCryptogramFullLength, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    return 0;
}

static int nxScp03_GP_ExternalAuthenticate(
    pSe05xSession_t session_ctx, uint8_t *key, size_t keylen, uint8_t *updateMCV, uint8_t *hostCryptogram)
{
    uint8_t *txBuf                      = NULL;
    uint8_t macToAdd[AES_KEY_LEN_nBYTE] = {0};
    smStatus_t retStatus                = SM_NOT_OK;
    int ret                             = 0;
    size_t signatureLen                 = sizeof(macToAdd);

    tlvHeader_t hdr = {
        {CLA_GP_7816 | CLA_GP_SECURITY_BIT, INS_GP_EXTERNAL_AUTHENTICATE, SECLVL_CDEC_RENC_CMAC_RMAC, 0x00}};
    uint8_t tmpBuf[64] = {
        0,
    };
    size_t tmpBufLen = sizeof(tmpBuf);
    tlvHeader_t hdr1 = {0};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(updateMCV != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostCryptogram != NULL, 1);

    txBuf = (session_ctx->apdu_buffer + (MAX_APDU_BUFFER / 2));
    // txBuf    = (session_ctx->apdu_buffer);
    txBuf[0] = CLA_GP_7816 | CLA_GP_SECURITY_BIT; //Set CLA Byte
    txBuf[1] = INS_GP_EXTERNAL_AUTHENTICATE;      //Set INS Byte
    txBuf[2] = SECLVL_CDEC_RENC_CMAC_RMAC;        //Set Security Level
    txBuf[3] = 0x00;
    txBuf[4] = 0x10; // The Lc value is set as-if the MAC has already been appended (SCP03 spec p16. Fig.61)
    memcpy(&txBuf[5], hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    /*
    * For the EXTERNAL AUTHENTICATE command MAC verification, the "MAC chaining value" is set to 16
    * bytes '00'. (SCP03 spec p16)
    */

    /* Check for txBuf */
    ENSURE_OR_RETURN_ON_ERROR((5 + (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN)) <= (MAX_APDU_BUFFER / 2), 1);
    /* Check for apdu_buffer */
    ENSURE_OR_RETURN_ON_ERROR((SCP_MCV_LEN + 5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN) <= (MAX_APDU_BUFFER / 2), 1);

    memset(updateMCV, 0, SCP_MCV_LEN);
    memcpy(session_ctx->apdu_buffer, updateMCV, SCP_MCV_LEN);
    memcpy((session_ctx->apdu_buffer + SCP_MCV_LEN), txBuf, (5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN));

    ret = hcrypto_cmac_oneshot(key,
        keylen,
        session_ctx->apdu_buffer,
        (SCP_MCV_LEN + 5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN),
        macToAdd,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in hcrypto_cmac_oneshot");
        return 1;
    }

    SMLOG_MAU8_D(" Output: Calculated MAC ==>", macToAdd, signatureLen);

    SMLOG_D("Add calculated MAC Value to cmd Data");
    memcpy(updateMCV, macToAdd, AES_KEY_LEN_nBYTE);
    memcpy(&txBuf[5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN], macToAdd, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    SMLOG_D("Sending GP External Authenticate Command !!!");

    // memcpy(session_ctx->apdu_buffer, &hdr, 4);
    // session_ctx->apdu_buffer[4] = (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    // memcpy((session_ctx->apdu_buffer + 5), &txBuf[5], (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN));
    memcpy((session_ctx->apdu_buffer), &txBuf[5], (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN));

    /* Wrapping in AESKey context */
    retStatus = ex_se05x_process_session_command(
        &hdr, session_ctx->apdu_buffer, (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN), &hdr1, tmpBuf, &tmpBufLen, 0);
    if (retStatus != SM_OK) {
        return 1;
    }

    retStatus = DoAPDUTx(session_ctx, &hdr1, tmpBuf, tmpBufLen, 0);
    if (retStatus != SM_OK) {
        SMLOG_D("GP_ExternalAuthenticate transmit failed");
        return 1;
    }

    return 0;
}

smStatus_t Se05x_API_SCP03_AESCreateSession(pSe05xSession_t session_ctx)
{
    int ret = 0;
#ifdef INITIAL_HOST_CHALLANGE
    uint8_t hostChallenge[] = INITIAL_HOST_CHALLANGE;
#else
    uint8_t hostChallenge[8] = {
        0,
    };
#endif
    size_t hostChallenge_len = sizeof(hostChallenge);
    uint8_t keyDivData[SCP_GP_IU_KEY_DIV_DATA_LEN];
    uint16_t keyDivDataLen = sizeof(keyDivData);
    uint8_t keyInfo[SCP_GP_IU_KEY_INFO_LEN];
    uint16_t keyInfoLen = sizeof(keyInfo);
    uint8_t cardChallenge[SCP_GP_CARD_CHALLENGE_LEN];
    uint16_t cardChallengeLen = sizeof(cardChallenge);
    uint8_t cardCryptoGram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    uint16_t cardCryptoGramLen = sizeof(cardCryptoGram);
    uint8_t hostCryptogram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    const uint8_t commandCounter[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    ENSURE_OR_RETURN_ON_ERROR(p_aes_session_ctx != NULL, SM_NOT_OK);
    if (p_aes_session_ctx->pScp03_enc_key == NULL || p_aes_session_ctx->pScp03_mac_key == NULL) {
        SMLOG_E("PlatformSCP03 keys (ENC and MAC) are not set. Set the keys in session context in application ! \n");
        return SM_NOT_OK;
    }
    ENSURE_OR_RETURN_ON_ERROR(p_aes_session_ctx->scp03_enc_key_len == SCP_KEY_SIZE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(p_aes_session_ctx->scp03_mac_key_len == SCP_KEY_SIZE, SM_NOT_OK);

    p_aes_session_ctx->scp03_session = 0;

#ifndef INITIAL_HOST_CHALLANGE
    ret = hcrypto_get_random(hostChallenge, hostChallenge_len);
    ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
#endif

    SMLOG_MAU8_D(" hostChallenge ==>", hostChallenge, hostChallenge_len);

    ret = nxScp03_GP_InitializeUpdate(session_ctx,
        hostChallenge,
        hostChallenge_len,
        keyDivData,
        &keyDivDataLen,
        keyInfo,
        &keyInfoLen,
        cardChallenge,
        &cardChallengeLen,
        cardCryptoGram,
        &cardCryptoGramLen);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_GP_InitializeUpdate");
        return SM_NOT_OK;
    }

    ret = nxScp03_HostLocal_CalculateSessionKeys(session_ctx, hostChallenge, cardChallenge);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_CalculateSessionKeys");
        return SM_NOT_OK;
    }

    ret = nxScp03_HostLocal_VerifyCardCryptogram(
        session_ctx, se05x_aesauth_sessionMacKey, AES_KEY_LEN_nBYTE, hostChallenge, cardChallenge, cardCryptoGram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_VerifyCardCryptogram");
        //Most likely, SCP03 keys are not correct"
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("cardCryptoGram ==>", cardCryptoGram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    SMLOG_D("CardCryptogram verified successfully...Calculate HostCryptogram \n");

    ret = nxScp03_HostLocal_CalculateHostCryptogram(
        session_ctx, se05x_aesauth_sessionMacKey, AES_KEY_LEN_nBYTE, hostChallenge, cardChallenge, hostCryptogram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_CalculateHostCryptogram");
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("hostCryptogram ==>", hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    ret = nxScp03_GP_ExternalAuthenticate(
        session_ctx, se05x_aesauth_sessionMacKey, AES_KEY_LEN_nBYTE, se05x_aesauth_mcv, hostCryptogram);
    if (ret != 0) {
        SMLOG_E("GP_ExternalAuthenticate failed \n"); // with Status %04X", status);
        return SM_NOT_OK;
    }
    else {
        // At this stage we have authenticated successfully.
        memcpy(se05x_aesauth_cCounter, commandCounter, AES_KEY_LEN_nBYTE);
        SMLOG_D("Authentication Successful!!! \n");
    }

    p_aes_session_ctx->scp03_session = 1;
    return SM_OK;
}

/**************** Data transmit functions *****************/

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

static smStatus_t Se05x_API_SCP03_AESCalculateCommandICV(pSe05xSession_t session_ctx, uint8_t *pIcv)
{
    int ret                      = 0;
    smStatus_t retStatus         = SM_NOT_OK;
    uint8_t ivZero[SCP_KEY_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    ret = hcrypto_aes_cbc_encrypt(se05x_aesauth_sessionEncKey,
        AES_KEY_LEN_nBYTE,
        ivZero,
        SCP_KEY_SIZE,
        se05x_aesauth_cCounter,
        pIcv,
        SCP_KEY_SIZE);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

void Se05x_API_SCP03_AESIncCommandCounter(pSe05xSession_t session_ctx)
{
    int i = 15;

    (void)session_ctx;

    while (i > 0) {
        if (se05x_aesauth_cCounter[i] < 255) {
            se05x_aesauth_cCounter[i] += 1;
            break;
        }
        else {
            se05x_aesauth_cCounter[i] = 0;
            i--;
        }
    }
    return;
}

static void nxpSCP03_Dec_CommandCounter(uint8_t *pCtrblock)
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

    memcpy(paddedCounterBlock, se05x_aesauth_cCounter, SCP_KEY_SIZE);
    if ((0 /*pdySCP03SessCtx->authType == kSSS_AuthType_SCP03*/) && (!hasCmd)) {
        nxpSCP03_Dec_CommandCounter(paddedCounterBlock);
    }
    paddedCounterBlock[0] = SCP_DATA_PAD_BYTE; // MSB padded with 0x80 Section 6.2.7 of SCP03 spec
    dataLen               = SCP_KEY_SIZE;

    ret = hcrypto_aes_cbc_encrypt(
        se05x_aesauth_sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, paddedCounterBlock, pIcv, dataLen);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
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

static smStatus_t Se05x_API_SCP03_AESCalculateMacRspApdu(
    pSe05xSession_t session_ctx, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);

    cmac_ctx = hcrypto_cmac_setup(se05x_aesauth_sessionRmacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_aesauth_mcv, SCP_KEY_SIZE);
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

    cmac_ctx = hcrypto_cmac_setup(se05x_aesauth_sessionMacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_aesauth_mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    memcpy(se05x_aesauth_mcv, outSignature, SCP_MCV_LEN);
    return SM_OK;
}

smStatus_t ex_se05x_aesauth_encrypt_data(pSe05xSession_t session_ctx,
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
            se05x_aesauth_sessionEncKey, AES_KEY_LEN_nBYTE, iv, SCP_KEY_SIZE, inBuf, inBuf, inBufLen);
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
    wsCmd[i++] = sizeof(se05x_applet_session_value);
    memcpy(&wsCmd[i], se05x_applet_session_value, sizeof(se05x_applet_session_value));
    i += sizeof(se05x_applet_session_value);

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

smStatus_t ex_se05x_aesauth_decrypt_data(
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
            ret = hcrypto_aes_cbc_decrypt(se05x_aesauth_sessionEncKey,
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
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_PadCommandAPDU(session_ctx, inBuf, &inBufLen) == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_CalculateCommandICV(session_ctx, iv) == SM_OK), SM_NOT_OK);

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

    ret = Se05x_API_SCP03_CalculateMacCmdApdu(session_ctx, outBuf, i, macData, &macDataLen);
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

        ret = Se05x_API_SCP03_CalculateMacRspApdu(session_ctx, inBuf, inBufLen, macData, &macDataLen);
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
            ENSURE_OR_RETURN_ON_ERROR((Se05x_API_SCP03_GetResponseICV(session_ctx, iv, TRUE) == SM_OK), SM_NOT_OK);

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
                (Se05x_API_SCP03_RestoreSwRAPDU(session_ctx, outBuf, pOutBufLen, outBuf, actualRespLen, sw) == SM_OK),
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

    Se05x_API_SCP03_IncCommandCounter(session_ctx);

    return apduStatus;
}

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
        out[i++] = (uint8_t)((STag1_Len)&0xFF);
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
