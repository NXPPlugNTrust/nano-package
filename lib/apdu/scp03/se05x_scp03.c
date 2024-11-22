/** @file se05x_scp03.c
 *  @brief Se05x SCP03 implementation.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "se05x_scp03_crypto.h"
#include "se05x_scp03.h"
#include <limits.h>

/* ********************** Functions ********************** */

extern int Se05x_API_Auth_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    const uint8_t *context,
    uint16_t contextLen);

smStatus_t Se05x_API_SCP03_GetSessionKeys(pSe05xSession_t session_ctx,
    uint8_t *encKey,
    size_t *encKey_len,
    uint8_t *macKey,
    size_t *macKey_len,
    uint8_t *rMacKey,
    size_t *rMacKey_len)
{
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey_len != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey_len != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey_len != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(*encKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*macKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*rMacKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);

    memcpy(encKey, session_ctx->scp03_session_enc_Key, AES_KEY_LEN_nBYTE);
    memcpy(macKey, session_ctx->scp03_session_mac_Key, AES_KEY_LEN_nBYTE);
    memcpy(rMacKey, session_ctx->scp03_session_rmac_Key, AES_KEY_LEN_nBYTE);

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_GetMcvCounter(
    pSe05xSession_t pSessionCtx, uint8_t *pCounter, size_t *pCounterLen, uint8_t *pMcv, size_t *pMcvLen)
{
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounter != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounterLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcv != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcvLen != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(*pCounterLen >= sizeof(pSessionCtx->scp03_counter), SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*pMcvLen >= sizeof(pSessionCtx->scp03_mcv), SM_NOT_OK);

    memcpy(pCounter, pSessionCtx->scp03_counter, sizeof(pSessionCtx->scp03_counter));
    memcpy(pMcv, pSessionCtx->scp03_mcv, sizeof(pSessionCtx->scp03_mcv));

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_SetSessionKeys(pSe05xSession_t session_ctx,
    const uint8_t *encKey,
    const size_t encKey_len,
    const uint8_t *macKey,
    const size_t macKey_len,
    const uint8_t *rMacKey,
    const size_t rMacKey_len)
{
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(encKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);

    memcpy(session_ctx->scp03_session_enc_Key, encKey, AES_KEY_LEN_nBYTE);
    memcpy(session_ctx->scp03_session_mac_Key, macKey, AES_KEY_LEN_nBYTE);
    memcpy(session_ctx->scp03_session_rmac_Key, rMacKey, AES_KEY_LEN_nBYTE);

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_SetMcvCounter(pSe05xSession_t pSessionCtx,
    const uint8_t *pCounter,
    const size_t counterLen,
    const uint8_t *pMcv,
    const size_t mcvLen)
{
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounter != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcv != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(counterLen == sizeof(pSessionCtx->scp03_counter), SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(mcvLen == sizeof(pSessionCtx->scp03_mcv), SM_NOT_OK);

    memcpy(pSessionCtx->scp03_counter, pCounter, sizeof(pSessionCtx->scp03_counter));
    memcpy(pSessionCtx->scp03_mcv, pMcv, sizeof(pSessionCtx->scp03_mcv));

    return SM_OK;
}

/* ********************** Internal Functions ********************** */

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
    smStatus_t retStatus        = SM_NOT_OK;
    uint8_t keyVersion          = 0x0b;
    uint8_t *pRspbuf            = NULL;
    size_t rspbufLen            = sizeof(session_ctx->apdu_buffer);
    tlvHeader_t hdr             = {{CLA_GP_7816, INS_GP_INITIALIZE_UPDATE, keyVersion, 0x00}};
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
    ENSURE_OR_RETURN_ON_ERROR((hostChallengeLen < UINT8_MAX), 1);

    ENSURE_OR_RETURN_ON_ERROR(*pKeyDivDataLen == SCP_GP_IU_KEY_DIV_DATA_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pKeyInfoLen == SCP_GP_IU_KEY_INFO_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardChallengeLen == SCP_GP_CARD_CHALLENGE_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardCryptoGramLen == SCP_GP_IU_CARD_CRYPTOGRAM_LEN, 1);

    pRspbuf = &session_ctx->apdu_buffer[0];

    memcpy(session_ctx->apdu_buffer, &hdr, 4);
    session_ctx->apdu_buffer[4] = hostChallengeLen;

    ENSURE_OR_RETURN_ON_ERROR(hostChallengeLen < (MAX_APDU_BUFFER - 5), 1);
    memcpy((session_ctx->apdu_buffer + 5), hostChallenge, hostChallengeLen);

    SMLOG_D("Sending GP Initialize Update Command !!! \n");
    retStatus = smComT1oI2C_TransceiveRaw(
        session_ctx->conn_context, session_ctx->apdu_buffer, (hostChallengeLen + 5), pRspbuf, &rspbufLen);
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
    ret = Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    // Calculate the Session-ENC key
    ret = nxScp03_Generate_SessionKey(session_ctx->pScp03_enc_key,
        session_ctx->scp03_enc_key_len,
        ddA,
        ddALen,
        session_ctx->scp03_session_enc_Key,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:scp03_session_enc_Key ==>", session_ctx->scp03_session_enc_Key, AES_KEY_LEN_nBYTE);

    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session MAC key \n");
    ret = Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-MAC key
    ret = nxScp03_Generate_SessionKey(session_ctx->pScp03_mac_key,
        session_ctx->scp03_mac_key_len,
        ddA,
        ddALen,
        session_ctx->scp03_session_mac_Key,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:scp03_session_mac_Key ==>", session_ctx->scp03_session_mac_Key, AES_KEY_LEN_nBYTE);

    /* Generation and Creation of Session RMAC SSS Key Object */
    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session RMAC key \n");
    ret = Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-RMAC key
    ret = nxScp03_Generate_SessionKey(session_ctx->pScp03_mac_key,
        session_ctx->scp03_mac_key_len,
        ddA,
        ddALen,
        session_ctx->scp03_session_rmac_Key,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D("Output:scp03_session_rmac_Key ==>", session_ctx->scp03_session_rmac_Key, AES_KEY_LEN_nBYTE);

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

    ret = Se05x_API_Auth_setDerivationData(
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

    ret = Se05x_API_Auth_setDerivationData(
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
    size_t rspbufLen                    = MAX_APDU_BUFFER;

    tlvHeader_t hdr = {
        {CLA_GP_7816 | CLA_GP_SECURITY_BIT, INS_GP_EXTERNAL_AUTHENTICATE, SECLVL_CDEC_RENC_CMAC_RMAC, 0x00}};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(updateMCV != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostCryptogram != NULL, 1);

    txBuf    = (session_ctx->apdu_buffer + (MAX_APDU_BUFFER / 2));
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

    /* Check for txBuf */ ENSURE_OR_RETURN_ON_ERROR(
        (5 + (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN)) <= (MAX_APDU_BUFFER / 2), 1);
    /* Check for apdu_buffer */ ENSURE_OR_RETURN_ON_ERROR(
        (SCP_MCV_LEN + 5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN) <= (MAX_APDU_BUFFER / 2), 1);

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

    memcpy(session_ctx->apdu_buffer, &hdr, 4);
    session_ctx->apdu_buffer[4] = (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    memcpy((session_ctx->apdu_buffer + 5), &txBuf[5], (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN));

    retStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context,
        session_ctx->apdu_buffer,
        ((2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN) + 5),
        session_ctx->apdu_buffer,
        &rspbufLen);
    if (retStatus != SM_OK) {
        SMLOG_D("GP_ExternalAuthenticate transmit failed");
        return 1;
    }

    return 0;
}

smStatus_t Se05x_API_SCP03_CreateSession(pSe05xSession_t session_ctx)
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

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    if (session_ctx->pScp03_enc_key == NULL || session_ctx->pScp03_mac_key == NULL) {
        SMLOG_E("PlatformSCP03 keys (ENC and MAC) are not set. Set the keys in session context in application ! \n");
        return SM_NOT_OK;
    }
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_enc_key_len == SCP_KEY_SIZE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_mac_key_len == SCP_KEY_SIZE, SM_NOT_OK);

    session_ctx->scp03_session = 0;

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

    ret = nxScp03_HostLocal_VerifyCardCryptogram(session_ctx,
        session_ctx->scp03_session_mac_Key,
        AES_KEY_LEN_nBYTE,
        hostChallenge,
        cardChallenge,
        cardCryptoGram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_VerifyCardCryptogram");
        //Most likely, SCP03 keys are not correct"
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("cardCryptoGram ==>", cardCryptoGram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    SMLOG_D("CardCryptogram verified successfully...Calculate HostCryptogram \n");

    ret = nxScp03_HostLocal_CalculateHostCryptogram(session_ctx,
        session_ctx->scp03_session_mac_Key,
        AES_KEY_LEN_nBYTE,
        hostChallenge,
        cardChallenge,
        hostCryptogram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_CalculateHostCryptogram");
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("hostCryptogram ==>", hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    ret = nxScp03_GP_ExternalAuthenticate(
        session_ctx, session_ctx->scp03_session_mac_Key, AES_KEY_LEN_nBYTE, session_ctx->scp03_mcv, hostCryptogram);
    if (ret != 0) {
        SMLOG_E("GP_ExternalAuthenticate failed \n"); // with Status %04X", status);
        return SM_NOT_OK;
    }
    else {
        // At this stage we have authenticated successfully.
        memcpy(session_ctx->scp03_counter, commandCounter, AES_KEY_LEN_nBYTE);
        SMLOG_D("Authentication Successful!!! \n");
    }

    session_ctx->scp03_session = 1;
    return SM_OK;
}

/**************** Data transmit functions *****************/

smStatus_t Se05x_API_SCP03_Encrypt(pSe05xSession_t session_ctx,
    const tlvHeader_t *inhdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t length_extended,
    uint8_t *encCmdBuf,
    size_t *encCmdBufLen)
{
    smStatus_t apduStatus = SM_NOT_OK;
    uint8_t iv[16]        = {0};
    int ret               = 0;
    size_t i              = 0;
    uint8_t macData[16]   = {
        0,
    };
    size_t macDataLen                    = 16;
    size_t se05xCmdLC                    = 0;
    size_t se05xCmdLCW                   = 0;
    uint8_t se05x_mcv_tmp[SCP_CMAC_SIZE] = {
        0,
    };

    ENSURE_OR_RETURN_ON_ERROR(inhdr != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encCmdBuf != NULL, SM_NOT_OK);

    memcpy(se05x_mcv_tmp, session_ctx->scp03_mcv, SCP_CMAC_SIZE);

    if (cmdBufLen != 0) {
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_Auth_PadCommandAPDU(cmdBuf, &cmdBufLen) == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR(
            (Se05x_API_Auth_CalculateCommandICV(
                 &(session_ctx->scp03_session_enc_Key[0]), &(session_ctx->scp03_counter[0]), iv) == SM_OK),
            SM_NOT_OK);
        ret = hcrypto_aes_cbc_encrypt(
            session_ctx->scp03_session_enc_Key, AES_KEY_LEN_nBYTE, iv, SCP_KEY_SIZE, cmdBuf, cmdBuf, cmdBufLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
    }

    se05xCmdLC  = cmdBufLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
    se05xCmdLCW = (se05xCmdLC == 0) ? 0 : (((se05xCmdLC < 0xFF) && !(length_extended)) ? 1 : 3);

    if (se05xCmdLCW > 0) {
        if (se05xCmdLCW == 1) {
            ENSURE_OR_RETURN_ON_ERROR(cmdBufLen < (MAX_APDU_BUFFER - sizeof(*inhdr) - 1), SM_NOT_OK);
            if (cmdBufLen > 0) {
                memmove(cmdBuf + sizeof(*inhdr) + 1, cmdBuf, cmdBufLen);
            }
            memcpy(cmdBuf, inhdr, sizeof(*inhdr));
            i += sizeof(*inhdr);
            cmdBuf[i++] = (uint8_t)se05xCmdLC;
        }
        else {
            ENSURE_OR_RETURN_ON_ERROR((cmdBufLen < (MAX_APDU_BUFFER - sizeof(*inhdr) - 3)), SM_NOT_OK);
            if (cmdBufLen > 0) {
                memmove(cmdBuf + sizeof(*inhdr) + 3, cmdBuf, cmdBufLen);
            }
            memcpy(cmdBuf, inhdr, sizeof(*inhdr));
            i += sizeof(*inhdr);
            cmdBuf[i++] = 0x00;
            cmdBuf[i++] = 0xFFu & (se05xCmdLC >> 8);
            cmdBuf[i++] = 0xFFu & (se05xCmdLC);
        }
    }

    cmdBuf[0] |= 0x4;

    if (cmdBufLen > 0) {
        i += cmdBufLen;
    }

    ret = Se05x_API_Auth_CalculateMacCmdApdu(
        &(session_ctx->scp03_session_mac_Key[0]), &session_ctx->scp03_mcv[0], cmdBuf, i, macData, &macDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

    if (i + SCP_GP_IU_CARD_CRYPTOGRAM_LEN > MAX_APDU_BUFFER) {
        /* Restore session_ctx->scp03_mcv*/
        memcpy(session_ctx->scp03_mcv, se05x_mcv_tmp, SCP_CMAC_SIZE);
        return SM_NOT_OK;
    }

    memcpy(&cmdBuf[i], macData, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    i += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    if (length_extended) {
        if (i + 2 > MAX_APDU_BUFFER) {
            /* Restore session_ctx->scp03_mcv*/
            memcpy(session_ctx->scp03_mcv, se05x_mcv_tmp, SCP_CMAC_SIZE);
            return SM_NOT_OK;
        }
        cmdBuf[i++] = 0x00;
        cmdBuf[i++] = 0x00;
    }

    *encCmdBufLen = i;
    memmove(encCmdBuf, cmdBuf, *encCmdBufLen);
    SMLOG_MAU8_D("SCP03: Encrypted Data ==>", encCmdBuf, *encCmdBufLen);
    apduStatus = SM_OK;
    return apduStatus;
}

smStatus_t Se05x_API_SCP03_Decrypt(pSe05xSession_t session_ctx,
    size_t cmdBufLen,
    uint8_t *encBuf,
    size_t encBufLen,
    uint8_t *decCmdBuf,
    size_t *decCmdBufLen)
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
    bool hascmd          = TRUE;

    apduStatus = encBuf[encBufLen - 2] << 8 | encBuf[encBufLen - 1];
    if (apduStatus == SM_OK) {
        memcpy(sw, &(encBuf[encBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);
        ret = Se05x_API_Auth_CalculateMacRspApdu(&(session_ctx->scp03_session_rmac_Key[0]),
            &session_ctx->scp03_mcv[0],
            encBuf,
            encBufLen,
            macData,
            &macDataLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR((encBufLen >= SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN), SM_NOT_OK);
        compareoffset = encBufLen - SCP_COMMAND_MAC_SIZE - SCP_GP_SW_LEN;
        ENSURE_OR_RETURN_ON_ERROR((compareoffset < MAX_APDU_BUFFER), SM_NOT_OK);
        if (memcmp(macData, &encBuf[compareoffset], SCP_COMMAND_MAC_SIZE) != 0) {
            SMLOG_E("SCP03: Response MAC did not verify \n");
            return SM_NOT_OK;
        }
        SMLOG_D("SCP03: RMAC verified successfully...Decrypt Response Data \n");
        // Decrypt Response Data Field in case Reponse Mac verified OK
        if (encBufLen > (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
            // Calculate ICV to decrypt the response

            if ((session_ctx->applet_version >= 0x04030000) ||
                (session_ctx->scp03_session && session_ctx->ecKey_session)) {
                hascmd = TRUE;
            }
            else {
                hascmd = (cmdBufLen == 0) ? FALSE : TRUE;
            }

            ENSURE_OR_RETURN_ON_ERROR(
                (Se05x_API_Auth_GetResponseICV(
                     hascmd, &(session_ctx->scp03_counter[0]), &(session_ctx->scp03_session_enc_Key[0]), iv) == SM_OK),
                SM_NOT_OK);

            ret = hcrypto_aes_cbc_decrypt(session_ctx->scp03_session_enc_Key,
                AES_KEY_LEN_nBYTE,
                iv,
                SCP_KEY_SIZE,
                encBuf,
                encBuf,
                ((encBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)));
            ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
            actualRespLen = (encBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN);

            ENSURE_OR_RETURN_ON_ERROR(
                (Se05x_API_Auth_RestoreSwRAPDU(encBuf, decCmdBufLen, encBuf, actualRespLen, sw) == SM_OK), SM_NOT_OK);

            memcpy(decCmdBuf, encBuf, *decCmdBufLen);
            SMLOG_MAU8_D("SCP03: Decrypted Data ==>", encBuf, *decCmdBufLen);
        }
        else if (encBufLen == (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
            // There's no data payload in response
            memcpy(encBuf, sw, SCP_GP_SW_LEN);
            *decCmdBufLen = SCP_GP_SW_LEN;
            memcpy(decCmdBuf, encBuf, *decCmdBufLen);
            SMLOG_MAU8_D("SCP03: Decrypted Data ==>", encBuf, *decCmdBufLen);
        }
    }

    if ((session_ctx->applet_version >= 0x04030000) || (session_ctx->scp03_session && session_ctx->ecKey_session)) {
        Se05x_API_Auth_IncCommandCounter(session_ctx->scp03_counter);
    }
    else {
        if ((cmdBufLen > 0)) {
            Se05x_API_Auth_IncCommandCounter(session_ctx->scp03_counter);
        }
    }

    return apduStatus;
}

#endif //#if defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)
