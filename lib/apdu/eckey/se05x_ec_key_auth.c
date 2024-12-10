/** @file se05x_scp03.c
 *  @brief Se05x EC Key Auth implementation.
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "se05x_scp03_crypto.h"
#include "se05x_APDU_apis.h"
#include "se05x_scp03.h"
#include <limits.h>

/* ********************** Defines ********************** */

/* clang-format off */
#define G_APPLET_NAME { 0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 }
/* clang-format on */

/** A device unique key pair which contains the SE05x Key Agreement key pair in ECKey session context. */
#define RESERVED_ID_ECKEY_SESSION 0x7FFF0201

/** Provisioned Authentication object ID - The user calls CreateSession with this authentication object ID */
#define ECKEY_AUTH_OBJECT_ID 0x7DA00003u

/* ********************** Global variables ********************** */

uint8_t g_rspbuf[MAX_APDU_BUFFER] = {0};
uint8_t g_cmdBuf[MAX_APDU_BUFFER] = {0};

/* ********************** Functions ********************** */

extern int Se05x_API_Auth_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    const uint8_t *context,
    uint16_t contextLen);

static smStatus_t nxECKey_InternalAuthenticate(pSe05xSession_t session_ctx,
    uint8_t *hostEckaPubKey,
    size_t hostEckaPubKeyLen,
    uint8_t *rndData,
    size_t *rndDataLen,
    uint8_t *receipt,
    size_t *receiptLen)
{
    int ret                             = 0;
    smStatus_t status                   = SM_NOT_OK;
    int tlvRet                          = 0;
    size_t cmdbufLen                    = 0;
    uint8_t *pCmdbuf                    = NULL;
    uint8_t cmdbuf_tmp[MAX_APDU_BUFFER] = {0};
    uint16_t i                          = 0;
    size_t SCmd_Lc                      = 0;
    size_t STag1_Len                    = 0;
    size_t rspIndex                     = 0;
    size_t rspbufLen                    = sizeof(g_rspbuf) / sizeof(g_rspbuf[0]);

    const tlvHeader_t hdr = {
        {CLA_GP_7816 | CLA_GP_SECURITY_BIT, INS_GP_INTERNAL_AUTHENTICATE, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    const tlvHeader_t hdr_last = {{CLA_GP_7816, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};

    uint8_t scpParms[3]     = {0xAB, SCP_CONFIG, SECURITY_LEVEL};
    uint8_t appletName[16]  = G_APPLET_NAME;
    size_t cntrlRefTemp_Len = 0 + 1 + 1 + 16 /*TLV AID */ + 1 + 1 + sizeof(scpParms) /* TLV SCP Params */ + 1 + 1 +
                              1 /* TLV Keytype */ + 1 + 1 + 1 /* TLV KeyLEN */;
    const uint8_t tagEpkSeEcka[] = {0x7F, 0x49};
    const uint8_t tagSigSeEcka[] = {0x5F, 0x37};
    uint8_t sig_host5F37[150]    = {0};
    size_t sig_host5F37Len       = sizeof(sig_host5F37);
    uint8_t md_host5F37[32];
    size_t md_host5F37Len = sizeof(md_host5F37);
    void *EcdsaKey        = NULL;

    SMLOG_D("ECKey Internal authenticate [] \n");

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->pEc_auth_key != NULL, SM_NOT_OK);

    cmdbuf_tmp[0] = 0xA6; // Tag Control reference template
    cmdbuf_tmp[1] = (uint8_t)cntrlRefTemp_Len;
    cmdbufLen     = 2;
    pCmdbuf       = &cmdbuf_tmp[2];
    tlvRet        = TLVSET_u8buf("SE05x AID", &pCmdbuf, &cmdbufLen, 0x4F, appletName, sizeof(appletName));
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = TLVSET_u8buf("SCP parameters", &pCmdbuf, &cmdbufLen, 0x90, scpParms, sizeof(scpParms));
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = TLVSET_U8("Key Type", &pCmdbuf, &cmdbufLen, 0x80, GPCS_KEY_TYPE_AES);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = TLVSET_U8("Key length", &pCmdbuf, &cmdbufLen, 0x81, GPCS_KEY_LEN_AES);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    /*Put the ephemral host ECKA pub key */
    ENSURE_OR_GO_CLEANUP(hostEckaPubKeyLen <= UINT8_MAX);
    *pCmdbuf++ = tagEpkSeEcka[0]; //Tag is 2 byte */
    cmdbufLen++;
    *pCmdbuf++ = tagEpkSeEcka[1];
    cmdbufLen++;
    *pCmdbuf++ = (uint8_t)hostEckaPubKeyLen;
    cmdbufLen++;
    memcpy(pCmdbuf, hostEckaPubKey, hostEckaPubKeyLen);
    if ((UINT_MAX - cmdbufLen) < hostEckaPubKeyLen) {
        goto cleanup;
    }
    cmdbufLen += hostEckaPubKeyLen;

    /* Generate ephemeral key */
    EcdsaKey = hcrypto_set_eckey(session_ctx->pEc_auth_key, session_ctx->ec_auth_key_len, 1);
    ENSURE_OR_GO_CLEANUP(EcdsaKey != NULL);

    ret = hcrypto_digest_one_go(cmdbuf_tmp, cmdbufLen, md_host5F37, &md_host5F37Len);
    ENSURE_OR_GO_CLEANUP(ret == 0);

    ret = hcrypto_sign_digest(EcdsaKey, md_host5F37, md_host5F37Len, sig_host5F37, &sig_host5F37Len);
    ENSURE_OR_GO_CLEANUP(ret == 0);

    /* Put the Control refernce template Value signature*/
    if (cmdbufLen > sizeof(cmdbuf_tmp) - 3 - sig_host5F37Len) {
        status = SM_NOT_OK;
        goto cleanup;
    }
    pCmdbuf    = &cmdbuf_tmp[cmdbufLen];
    *pCmdbuf++ = tagSigSeEcka[0];
    cmdbufLen++;
    *pCmdbuf++ = tagSigSeEcka[1];
    cmdbufLen++;
    *pCmdbuf++ = (uint8_t)sig_host5F37Len;
    cmdbufLen++;
    memcpy(pCmdbuf, sig_host5F37, sig_host5F37Len);
    cmdbufLen += sig_host5F37Len;

    g_cmdBuf[i++] = kSE05x_TAG_SESSION_ID;
    g_cmdBuf[i++] = sizeof(session_ctx->eckey_applet_session_value);
    memcpy(&g_cmdBuf[i], session_ctx->eckey_applet_session_value, sizeof(session_ctx->eckey_applet_session_value));
    i += sizeof(session_ctx->eckey_applet_session_value);

    SCmd_Lc   = (cmdbufLen == 0) ? 0 : (((cmdbufLen < 0xFF) && !0) ? 1 : 3);
    STag1_Len = 0 /* cla ins */ + 4 + SCmd_Lc + cmdbufLen;

    g_cmdBuf[i++] = kSE05x_TAG_1;
    if (STag1_Len <= 0x7Fu) {
        g_cmdBuf[i++] = (uint8_t)STag1_Len;
    }
    else if (STag1_Len <= 0xFFu) {
        g_cmdBuf[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        g_cmdBuf[i++] = (uint8_t)((STag1_Len >> 0 * 8) & 0xFF);
    }

    memcpy(&g_cmdBuf[i], &hdr, 4);
    i             = i + 4;
    g_cmdBuf[i++] = cmdbufLen;

    ENSURE_OR_GO_CLEANUP(cmdbufLen < (size_t)(MAX_APDU_BUFFER - i));
    memcpy(&g_cmdBuf[i], cmdbuf_tmp, cmdbufLen);

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= (size_t)(UINT16_MAX - i));
    i = i + cmdbufLen;

    status = DoAPDUTxRx(session_ctx, &hdr_last, g_cmdBuf, i, g_rspbuf, &rspbufLen, 0);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    tlvRet = tlvGet_u8buf(
        g_rspbuf, &rspIndex, rspbufLen, 0x85 /* kSE05x_GP_TAG_DR_SE*/, rndData, rndDataLen); /*Get the Random*/
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    tlvRet = tlvGet_u8buf(
        g_rspbuf, &rspIndex, rspbufLen, 0x86 /* kSE05x_GP_TAG_RECEIPT */, receipt, receiptLen); /* Get the Receipt */
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    ENSURE_OR_GO_CLEANUP((rspIndex + 2) == rspbufLen);

    status = (smStatus_t)((g_rspbuf[rspIndex] << 8) | (g_rspbuf[rspIndex + 1]));
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    status = SM_OK;
cleanup:
    if (EcdsaKey != NULL) {
        /*Erase the host key pair as it is no longer needed*/
        hcrypto_free_eckey(EcdsaKey);
    }
    return status;
}

static smStatus_t nxECKey_calculate_Shared_secret(pSe05xSession_t session_ctx,
    void *HostKeyPair,
    void *SePubkey,
    size_t SePubkeyLen,
    uint8_t *sharedSecret,
    size_t *sharedSecretLen)
{
    int ret           = 0;
    smStatus_t status = SM_NOT_OK;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_derive_dh(session_ctx, HostKeyPair, SePubkey, SePubkeyLen, sharedSecret, sharedSecretLen);
    ENSURE_OR_GO_CLEANUP(ret == 0);

    status = SM_OK;
cleanup:
    return status;
}

static smStatus_t nxECKey_calculate_master_secret(pSe05xSession_t session_ctx,
    uint8_t *rnd,
    size_t rndLen,
    uint8_t *sharedSecret,
    size_t sharedSecretLen,
    uint8_t *eckey_masterSk,
    size_t *eckey_masterSk_len)
{
    smStatus_t status            = SM_NOT_OK;
    int ret                      = 0;
    uint8_t derivationInput[100] = {0};
    const uint8_t kdf_counter[]  = {0x00, 0x00, 0x00, 0x01};
    size_t derivationInputLen    = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);

    if (session_ctx->applet_version >= 0x03050000) {
        memcpy(&derivationInput[derivationInputLen], kdf_counter, sizeof(kdf_counter));
        derivationInputLen += sizeof(kdf_counter);
    }

    memcpy(&derivationInput[derivationInputLen], sharedSecret, sharedSecretLen);

    ENSURE_OR_GO_EXIT((UINT_MAX - derivationInputLen) > sharedSecretLen)
    derivationInputLen += sharedSecretLen;

    ENSURE_OR_GO_EXIT(rndLen <= (sizeof(derivationInput) - derivationInputLen));
    memcpy(&derivationInput[derivationInputLen], rnd, rndLen);

    ENSURE_OR_GO_EXIT(((UINT_MAX - derivationInputLen) > rndLen))
    derivationInputLen += rndLen;

    ENSURE_OR_GO_EXIT(derivationInputLen <= (sizeof(derivationInput) - 4))
    derivationInput[derivationInputLen++] = SCP_CONFIG;
    derivationInput[derivationInputLen++] = SECURITY_LEVEL;
    derivationInput[derivationInputLen++] = GPCS_KEY_TYPE_AES;
    derivationInput[derivationInputLen++] = GPCS_KEY_LEN_AES;

    ret = hcrypto_digest_one_go(derivationInput, derivationInputLen, eckey_masterSk, eckey_masterSk_len);
    ENSURE_OR_GO_EXIT(ret == 0);

    /* Only the first 16 bytes are considered */
    *eckey_masterSk_len = 16;

    status = SM_OK;
exit:
    return status;
}

static smStatus_t nxECKey_HostLocal_CalculateSessionKeys(
    pSe05xSession_t session_ctx, uint8_t *eckey_masterSk, size_t eckey_masterSk_len)
{
    int ret             = 0;
    smStatus_t status   = SM_NOT_OK;
    uint8_t ddA[128]    = {0};
    uint16_t ddALen     = sizeof(ddA);
    size_t signatureLen = AES_KEY_LEN_nBYTE;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);

    /* Generation and Creation of Session ENC */
    Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);

    /* Calculate the Session-ENC key */
    ret = hcrypto_cmac_oneshot(
        eckey_masterSk, eckey_masterSk_len, ddA, ddALen, session_ctx->eckey_session_enc_Key, &signatureLen);
    ENSURE_OR_GO_EXIT((ret == 0));

    /* Generation and Creation of Session MAC*/
    Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);

    /* Calculate the Session-MAC key */
    ret = hcrypto_cmac_oneshot(
        eckey_masterSk, eckey_masterSk_len, ddA, ddALen, session_ctx->eckey_session_mac_Key, &signatureLen);
    ENSURE_OR_GO_EXIT((ret == 0));

    /* Generation and Creation of Session RMAC*/
    Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);

    /* Calculate the Session-MAC key */
    ret = hcrypto_cmac_oneshot(
        eckey_masterSk, eckey_masterSk_len, ddA, ddALen, session_ctx->eckey_session_rmac_Key, &signatureLen);
    ENSURE_OR_GO_EXIT((ret == 0));

    status = SM_OK;
exit:
    return status;
}

static smStatus_t nxECKey_Calculate_Initial_Mac_Chaining_Value(
    pSe05xSession_t session_ctx, uint8_t *eckey_masterSk, size_t eckey_masterSk_len)
{
    int ret                                   = 0;
    smStatus_t status                         = SM_NOT_OK;
    uint8_t ddA[128]                          = {0};
    uint16_t ddALen                           = sizeof(ddA);
    uint8_t iniMacChaining[AES_KEY_LEN_nBYTE] = {0};
    size_t signatureLen                       = AES_KEY_LEN_nBYTE;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);

    // Set the Derviation data
    Se05x_API_Auth_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_INITIAL_MCV, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, NULL, 0);

    ret = hcrypto_cmac_oneshot(eckey_masterSk, eckey_masterSk_len, ddA, ddALen, iniMacChaining, &signatureLen);
    ENSURE_OR_GO_EXIT((ret == 0));

    // Set the Initial MCV value
    memcpy(session_ctx->eckey_mcv, iniMacChaining, AES_KEY_LEN_nBYTE);

    status = SM_OK;
exit:
    return status;
}

smStatus_t Se05x_API_ECKey_CloseSession(pSe05xSession_t session_ctx)
{
    ENSURE_OR_RETURN_ON_ERROR((session_ctx != NULL), SM_NOT_OK);

    memset(session_ctx->eckey_session_enc_Key, 0, sizeof(session_ctx->eckey_session_enc_Key));
    memset(session_ctx->eckey_session_mac_Key, 0, sizeof(session_ctx->eckey_session_mac_Key));
    memset(session_ctx->eckey_session_rmac_Key, 0, sizeof(session_ctx->eckey_session_rmac_Key));
    memset(session_ctx->eckey_counter, 0, sizeof(session_ctx->eckey_counter));
    memset(session_ctx->eckey_mcv, 0, sizeof(session_ctx->eckey_mcv));
    memset(session_ctx->eckey_applet_session_value, 0, sizeof(session_ctx->eckey_applet_session_value));
    session_ctx->ecKey_session = 0;

    return SM_OK;
}

smStatus_t Se05x_API_ECKey_CreateSession(pSe05xSession_t session_ctx)
{
    int ret                  = 0;
    SE05x_Result_t exists    = kSE05x_Result_FAILURE;
    smStatus_t status        = SM_NOT_OK;
    size_t offset            = 0;
    uint8_t hostEckaPub[128] = {
        0,
    };
    size_t hostEckaPubLen   = sizeof(hostEckaPub);
    size_t sessionIdLen     = 0;
    uint8_t SePubkey[128]   = {0};
    size_t SePubkeyLen      = sizeof(SePubkey);
    uint8_t hostPubkey[128] = {
        0,
    };
    uint8_t shsSecret[64] = {
        0,
    };
    size_t shsSecretLen = sizeof(shsSecret);
    // Random bytes + receipt to retrive from SE in internal authenticate
    uint8_t drSE[20]           = {0};
    size_t drSELen             = sizeof(drSE);
    uint8_t receipt[16]        = {0};
    size_t receiptLen          = sizeof(receipt);
    void *EckaKey              = NULL;
    uint8_t eckey_masterSk[32] = {0};
    size_t eckey_masterSk_len  = sizeof(eckey_masterSk);
    uint16_t key_len           = 0;
    const void *header         = NULL;
    size_t header_size         = 0;

    /* clang-format off */
    const uint8_t commandCounter[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    const uint8_t nist256_header[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
                                       0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
                                       0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
                                       0x42, 0x00 };

    const uint8_t nist384_header[] = { 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
                                       0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
                                       0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };
    /* clang-format on */

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);

    sessionIdLen = sizeof(session_ctx->eckey_applet_session_value);

    status = Se05x_API_CheckObjectExists(session_ctx, ECKEY_AUTH_OBJECT_ID, &exists);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    if (exists == kSE05x_Result_FAILURE) {
        SMLOG_E("ECKEY_AUTH_OBJECT_ID is not Provisioned!!!. (Key can be provisioned using the example se05x_eckey_session_provision) \n");
        status = SM_NOT_OK;
        goto exit;
    }

    status = Se05x_API_ReadSize(session_ctx, RESERVED_ID_ECKEY_SESSION, &key_len);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    if (key_len == 32) {
        //SMLOG_I("RESERVED_ID_ECKEY_SESSION is NISTP-256 \n");
        header      = &nist256_header[0];
        header_size = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else if (key_len == 48) {
        //SMLOG_I("RESERVED_ID_ECKEY_SESSION is NISTP-384 \n");
        header      = &nist384_header[0];
        header_size = ASN_ECC_NIST_384_HEADER_LEN;
    }
    else {
        SMLOG_E("Unsupported header for key length.\n");
        status = SM_NOT_OK;
        goto exit;
    }

    memcpy(SePubkey, header, header_size);

    SePubkeyLen = SePubkeyLen - header_size;
    status = Se05x_API_ReadObject(
        session_ctx, RESERVED_ID_ECKEY_SESSION, 0, 0, SePubkey + header_size, &SePubkeyLen);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    ENSURE_OR_GO_EXIT((SIZE_MAX - (header_size)) > SePubkeyLen);
    SePubkeyLen = SePubkeyLen + header_size;

    status = Se05x_API_CreateSession(
        session_ctx, ECKEY_AUTH_OBJECT_ID, &session_ctx->eckey_applet_session_value[0], &sessionIdLen);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    /*Generate ephemeral key Using Host*/
    EckaKey = hcrypto_gen_eckey(key_len);
    if (EckaKey == NULL) {
        status = SM_NOT_OK;
        goto exit;
    }

    ret = hcrypto_get_publickey(EckaKey, hostPubkey, &hostEckaPubLen);
    if (ret != 0) {
        status = SM_NOT_OK;
        goto exit;
    }

    hostEckaPub[offset++] = GPCS_KEY_TYPE_ECC_PUB_KEY; // Tag EC public key

    ENSURE_OR_GO_EXIT(hostEckaPubLen > header_size);
    ENSURE_OR_GO_EXIT((hostEckaPubLen - header_size) < UINT8_MAX);
    hostEckaPub[offset++] = hostEckaPubLen - header_size; // public key len

    memcpy(
        hostEckaPub + offset, hostPubkey + header_size, hostEckaPubLen - header_size);
    ENSURE_OR_GO_EXIT(((UINT_MAX - offset) > (hostEckaPubLen - header_size)));
    offset += hostEckaPubLen - header_size;

    ENSURE_OR_GO_EXIT(offset + 3 <= hostEckaPubLen);
    hostEckaPub[offset++] = KEY_PARAMETER_CURVE_IDENTIFIER_TAG;
    hostEckaPub[offset++] = KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_LEN;
    hostEckaPub[offset++] =
        (key_len == 32) ? KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_NIST256 : KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_NIST384;
    hostEckaPubLen     = offset;

    status =
        nxECKey_InternalAuthenticate(session_ctx, hostEckaPub, hostEckaPubLen, drSE, &drSELen, receipt, &receiptLen);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    status = nxECKey_calculate_Shared_secret(session_ctx, EckaKey, SePubkey, SePubkeyLen, shsSecret, &shsSecretLen);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    status = nxECKey_calculate_master_secret(
        session_ctx, drSE, drSELen, shsSecret, shsSecretLen, eckey_masterSk, &eckey_masterSk_len);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    status = nxECKey_HostLocal_CalculateSessionKeys(session_ctx, eckey_masterSk, eckey_masterSk_len);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    /* Increment the command Encreption counter to 1*/
    memcpy(session_ctx->eckey_counter, commandCounter, AES_KEY_LEN_nBYTE);

    /*Compute the intial MAC changing Value*/
    status = nxECKey_Calculate_Initial_Mac_Chaining_Value(session_ctx, eckey_masterSk, eckey_masterSk_len);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    session_ctx->ecKey_session = 1;

exit:
    if (EckaKey != NULL) {
        /*Erase the host key pair as it is no longer needed*/
        hcrypto_free_eckey(EckaKey);
    }
    return status;
}

/**************** Data transmit functions *****************/
smStatus_t Se05x_API_ECKeyAuth_Encrypt(pSe05xSession_t session_ctx,
    const tlvHeader_t *inhdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t length_extended,
    tlvHeader_t *outhdr,
    uint8_t *encCmdBuf,
    size_t *encCmdBufLen)
{
    smStatus_t apduStatus                      = SM_NOT_OK;
    uint8_t iv[16]                             = {0};
    int ret                                    = 0;
    size_t i                                   = 0;
    uint8_t macData[16]                        = {0};
    size_t macDataLen                          = 16;
    uint8_t se05x_eckey_mcv_tmp[SCP_CMAC_SIZE] = {0};
    uint8_t *dataToMac                         = NULL;
    size_t dataToMac_len                       = 0;
    size_t se05xCmdLC                          = 0;
    size_t se05xCmdLCW                         = 0;
    size_t wsSe05x_tag1Len                     = 0;
    size_t wsSe05x_tag1W                       = 0;

    ENSURE_OR_RETURN_ON_ERROR(inhdr != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encCmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encCmdBufLen != NULL, SM_NOT_OK);

    memcpy(se05x_eckey_mcv_tmp, session_ctx->eckey_mcv, SCP_CMAC_SIZE);

    if (cmdBufLen != 0) {
        ENSURE_OR_RETURN_ON_ERROR((Se05x_API_Auth_PadCommandAPDU(cmdBuf, &cmdBufLen) == SM_OK), SM_NOT_OK);
        ENSURE_OR_RETURN_ON_ERROR(
            (Se05x_API_Auth_CalculateCommandICV(
                 &(session_ctx->eckey_session_enc_Key[0]), &session_ctx->eckey_counter[0], iv) == SM_OK),
            SM_NOT_OK);

        ret = hcrypto_aes_cbc_encrypt(
            session_ctx->eckey_session_enc_Key, AES_KEY_LEN_nBYTE, iv, SCP_KEY_SIZE, cmdBuf, cmdBuf, cmdBufLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
    }

    outhdr->hdr[0] = 0x80;
    outhdr->hdr[1] = 0x05;
    outhdr->hdr[2] = 0x00;
    outhdr->hdr[3] = 0x00;

    /* Add session header */
    memcpy(&g_cmdBuf[i], outhdr->hdr, sizeof(outhdr->hdr));
    i = +sizeof(outhdr->hdr);

    g_cmdBuf[i++] = 0; /* Length. To be updated later */
    g_cmdBuf[i++] = kSE05x_TAG_SESSION_ID;
    g_cmdBuf[i++] = sizeof(session_ctx->eckey_applet_session_value);
    memcpy(&g_cmdBuf[i], session_ctx->eckey_applet_session_value, sizeof(session_ctx->eckey_applet_session_value));
    i += sizeof(session_ctx->eckey_applet_session_value);

    g_cmdBuf[i++] = kSE05x_TAG_1;

    se05xCmdLC      = cmdBufLen + 8 /*MAC*/;
    se05xCmdLCW     = (se05xCmdLC == 0) ? 0 : (((se05xCmdLC < 0xFF) && !(length_extended)) ? 1 : 3);
    wsSe05x_tag1Len = 4 /*hrd*/ + se05xCmdLCW + se05xCmdLC;
    wsSe05x_tag1W   = ((wsSe05x_tag1Len <= 0x7F) ? 1 : (wsSe05x_tag1Len <= 0xFF) ? 2 : 3);

    if (wsSe05x_tag1W == 1) {
        g_cmdBuf[i++] = wsSe05x_tag1Len;
    }
    else if (wsSe05x_tag1W == 2) {
        g_cmdBuf[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        g_cmdBuf[i++] = (uint8_t)((wsSe05x_tag1Len >> 0 * 8) & 0xFF);
    }
    else {
        g_cmdBuf[i++] = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        g_cmdBuf[i++] = (uint8_t)((wsSe05x_tag1Len >> 8) & 0xFF);
        g_cmdBuf[i++] = (uint8_t)((wsSe05x_tag1Len) & 0xFF);
    }

    dataToMac = &g_cmdBuf[i];
    memcpy(&g_cmdBuf[i], inhdr, 4);
    g_cmdBuf[i] |= 0x4;
    i = i + 4;
    dataToMac_len += 4;

    if (se05xCmdLCW > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if (se05xCmdLCW == 1) {
            g_cmdBuf[i++] = (uint8_t)se05xCmdLC;
            dataToMac_len += 1;
        }
        else {
            g_cmdBuf[i++] = 0x00;
            g_cmdBuf[i++] = 0xFFu & (se05xCmdLC >> 8);
            g_cmdBuf[i++] = 0xFFu & (se05xCmdLC);
            dataToMac_len += 3;
        }
    }

    ENSURE_OR_RETURN_ON_ERROR((i < MAX_APDU_BUFFER), SM_NOT_OK);
    memcpy(&g_cmdBuf[i], cmdBuf, cmdBufLen);
    ENSURE_OR_RETURN_ON_ERROR((i <= (SIZE_MAX - cmdBufLen)), SM_NOT_OK);
    i = i + cmdBufLen;
    ENSURE_OR_RETURN_ON_ERROR(((SIZE_MAX - dataToMac_len) >= cmdBufLen), SM_NOT_OK);
    dataToMac_len += cmdBufLen;

    ret = Se05x_API_Auth_CalculateMacCmdApdu(&(session_ctx->eckey_session_mac_Key[0]),
        &(session_ctx->eckey_mcv[0]),
        dataToMac,
        dataToMac_len,
        macData,
        &macDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR((i < MAX_APDU_BUFFER), SM_NOT_OK);
    memcpy(&g_cmdBuf[i], macData, 8);
    i = i + 8;

    if (((i - 5) < 0xFF) && !length_extended) {
        g_cmdBuf[4] = (uint8_t)(i - 5);
    }
    else {
        ENSURE_OR_RETURN_ON_ERROR(((i - 5) <= MAX_APDU_BUFFER - 7), SM_NOT_OK);
        memmove(g_cmdBuf + 7, g_cmdBuf + 5, i - 5);
        g_cmdBuf[4] = 0x00;
        g_cmdBuf[5] = 0xFFu & ((i - 5) >> 8);
        g_cmdBuf[6] = 0xFFu & ((i - 5));
        i           = i + 2;
    }

    *encCmdBufLen = i;
    ENSURE_OR_RETURN_ON_ERROR((*encCmdBufLen <= MAX_APDU_BUFFER), SM_NOT_OK);
    memcpy(encCmdBuf, g_cmdBuf, *encCmdBufLen);
    SMLOG_MAU8_D("ECKey: Encrypted Data ==>", encCmdBuf, *encCmdBufLen);
    apduStatus = SM_OK;
    return apduStatus;
}

smStatus_t Se05x_API_ECKeyAuth_Decrypt(
    pSe05xSession_t session_ctx, uint8_t *encBuf, size_t encBufLen, uint8_t *decCmdBuf, size_t *decCmdBufLen)
{
    smStatus_t apduStatus = SM_NOT_OK;
    uint8_t iv[16]        = {0};
    int ret               = 0;
    uint8_t macData[16]   = {0};
    size_t macDataLen     = 16;
    uint8_t sw[SCP_GP_SW_LEN];
    size_t compareoffset = 0;
    size_t actualRespLen = 0;

    ENSURE_OR_RETURN_ON_ERROR(encBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(decCmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(decCmdBufLen != NULL, SM_NOT_OK);

    apduStatus = encBuf[encBufLen - 2] << 8 | encBuf[encBufLen - 1];
    if (apduStatus == SM_OK) {
        memcpy(sw, &(encBuf[encBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);

        ret = Se05x_API_Auth_CalculateMacRspApdu(&(session_ctx->eckey_session_rmac_Key[0]),
            &(session_ctx->eckey_mcv[0]),
            encBuf,
            encBufLen,
            macData,
            &macDataLen);
        ENSURE_OR_RETURN_ON_ERROR((ret == SM_OK), SM_NOT_OK);

        ENSURE_OR_RETURN_ON_ERROR((encBufLen >= SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN), SM_NOT_OK);
        compareoffset = encBufLen - SCP_COMMAND_MAC_SIZE - SCP_GP_SW_LEN;
        ENSURE_OR_RETURN_ON_ERROR((compareoffset < MAX_APDU_BUFFER), SM_NOT_OK);
        if (memcmp(macData, &encBuf[compareoffset], SCP_COMMAND_MAC_SIZE) != 0) {
            SMLOG_E("ECKey: Response MAC did not verify \n");
            return SM_NOT_OK;
        }

        SMLOG_D("ECKey: RMAC verified successfully...Decrypt Response Data \n");

        // Decrypt Response Data Field in case Reponse Mac verified OK
        if (encBufLen > (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) { // There is data payload in response
            // Calculate ICV to decrypt the response

            if (0) {
                ENSURE_OR_RETURN_ON_ERROR((Se05x_API_Auth_GetResponseICV(encBufLen == 0 ? FALSE : TRUE,
                                               &session_ctx->eckey_counter[0],
                                               &(session_ctx->eckey_session_enc_Key[0]),
                                               iv) == SM_OK),
                    SM_NOT_OK);
            }
            else {
                ENSURE_OR_RETURN_ON_ERROR(
                    (Se05x_API_Auth_GetResponseICV(
                         TRUE, &session_ctx->eckey_counter[0], &(session_ctx->eckey_session_enc_Key[0]), iv) == SM_OK),
                    SM_NOT_OK);
            }

            ret = hcrypto_aes_cbc_decrypt(session_ctx->eckey_session_enc_Key,
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
            SMLOG_MAU8_D("ECKey: Decrypted Data ==>", encBuf, *decCmdBufLen);
        }
        else if (encBufLen == (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
            // There's no data payload in response
            memcpy(encBuf, sw, SCP_GP_SW_LEN);
            *decCmdBufLen = SCP_GP_SW_LEN;
            memcpy(decCmdBuf, encBuf, *decCmdBufLen);
            SMLOG_MAU8_D("ECKey: Decrypted Data ==>", encBuf, *decCmdBufLen);
        }
    }

    Se05x_API_Auth_IncCommandCounter(session_ctx->eckey_counter);

    return apduStatus;
}

#endif //#if defined(WITH_ECKEY_SESSION) || defined(WITH_ECKEY_SCP03_SESSION)
