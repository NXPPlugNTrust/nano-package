/** @file ex_se05x_rotate_scp03_keys.c
 *  @brief se05x example to rotate platformSCP03 keys.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"

#if EX_SE05X_USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>
#elif EX_SE05X_USE_TC
#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#else
#error "No host crypto defined. Cannot build this example"
#endif

/* ********************** Defines ********************** */
#define AES_KEY_LEN_nBYTE 0x10
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88
#define CRYPTO_KEY_CHECK_LEN 0x03
#define GP_CLA_BYTE 0x80
#define GP_INS_PUTKEY 0xD8
#define GP_P2_MULTIPLEKEYS 0x81

/** Platform SCP03 key version */
#define KEY_VERSION 0x0B

/* ********************** Global variables ********************** */

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[AES_KEY_LEN_nBYTE] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[AES_KEY_LEN_nBYTE] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};
uint8_t scp03_dek_key[AES_KEY_LEN_nBYTE] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x03};

/**** NEW SCP03 KEYS ****/
uint8_t NEW_scp03_enc_key[AES_KEY_LEN_nBYTE] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
uint8_t NEW_scp03_mac_key[AES_KEY_LEN_nBYTE] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
uint8_t NEW_scp03_dek_key[AES_KEY_LEN_nBYTE] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

/* ********************** Function Prototypes ********************** */
static int ex_se05x_change_keys(
    pSe05xSession_t session_ctx, uint8_t *scp03EncKey, uint8_t *scp03MacKey, uint8_t *scp03DecKey);

/* ********************** Functions ********************** */

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = &scp03_dek_key[0];
    session_ctx->scp03_enc_key_len = AES_KEY_LEN_nBYTE;
    session_ctx->scp03_mac_key_len = AES_KEY_LEN_nBYTE;
    session_ctx->scp03_dek_key_len = AES_KEY_LEN_nBYTE;
    return;
}

int ex_se05x_rotate_scp03_keys()
{
    smStatus_t status;
    Se05xSession_t se05x_session = {
        0,
    };
    uint8_t ret = 0;

    se05x_session.skip_applet_select = 1;
    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    SMLOG_I("Changing SCP03 keys(version - %02x) to NEW KEYS \n", KEY_VERSION);
    ret = ex_se05x_change_keys(&se05x_session, &NEW_scp03_enc_key[0], &NEW_scp03_mac_key[0], &NEW_scp03_dek_key[0]);
    if (ret != 0) {
        SMLOG_E("Error in ex_se05x_change_keys \n");
        return 1;
    }

    SMLOG_I("Reverting SCP03 keys(version - %02x) to OLD KEYS \n", KEY_VERSION);
    ret = ex_se05x_change_keys(&se05x_session, &scp03_enc_key[0], &scp03_mac_key[0], &scp03_dek_key[0]);
    if (ret != 0) {
        SMLOG_E("Error in ex_se05x_change_keys \n");
        return 1;
    }

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}

static int ex_aes_ecb_encrypt(uint8_t *key, size_t keylen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
#if EX_SE05X_USE_OPENSSL
    AES_KEY AESKey;
#elif EX_SE05X_USE_TC
    struct tc_aes_key_sched_struct aes_ecb_sched;
#else
#error "No host crypto defined. Cannot build this example"
#endif

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((srcData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((destData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((dataLen == 16), 1);

#if EX_SE05X_USE_OPENSSL
    if (AES_set_encrypt_key((uint8_t *)key, keylen * 8, &AESKey) < 0) {
        return 1;
    }
    AES_ecb_encrypt(srcData, destData, &AESKey, AES_ENCRYPT);
#elif EX_SE05X_USE_TC
    if (TC_CRYPTO_SUCCESS != tc_aes128_set_encrypt_key(&aes_ecb_sched, key)) {
        return 1;
    }
    if (TC_CRYPTO_SUCCESS != tc_aes_encrypt(destData, srcData, &aes_ecb_sched)) {
        return 1;
    }
#else
    return 1;
#endif

    return 0;
}

static uint8_t genKCVandEncryptKey(
    pSe05xSession_t session_ctx, uint8_t *encryptedkey, uint8_t *keyCheckVal, uint8_t *plainKey)
{
    uint8_t refOneArray[AES_KEY_LEN_nBYTE] = {0};
    uint8_t ret                            = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);

    memset(refOneArray, 1, sizeof(refOneArray));

    //Encrypt refOneArray using plainKey and store enc data in keyCheckVal
    ret = ex_aes_ecb_encrypt(plainKey, AES_KEY_LEN_nBYTE, refOneArray, keyCheckVal, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    /* Encyrpt the key using DEK key and store enc data in encryptedkey*/
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->pScp03_dek_key != NULL, 1);
    ret = ex_aes_ecb_encrypt(session_ctx->pScp03_dek_key, AES_KEY_LEN_nBYTE, plainKey, encryptedkey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    return 0;
}

static uint8_t createKeyData(pSe05xSession_t session_ctx, uint8_t *key, uint8_t *command)
{
    uint8_t keyCheckValues[AES_KEY_LEN_nBYTE] = {0};
    uint8_t ret                               = 1;

    /* For Each Key add Key Type Length of Key data and key length*/
    command[0]                     = PUT_KEYS_KEY_TYPE_CODING_AES; //Key Type
    command[1]                     = AES_KEY_LEN_nBYTE + 1;        // Length of the 'AES key data'
    command[2]                     = AES_KEY_LEN_nBYTE;            // Length of 'AES key'
    command[3 + AES_KEY_LEN_nBYTE] = CRYPTO_KEY_CHECK_LEN;         //Lenth of KCV

    /* Encrypt Key and generate key check values */
    ret = genKCVandEncryptKey(session_ctx, &command[3], keyCheckValues, key);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    /* Copy the Key Check values */
    memcpy(&command[3 + AES_KEY_LEN_nBYTE + 1], &keyCheckValues[0], CRYPTO_KEY_CHECK_LEN);

    return 0;
}

static int ex_se05x_change_keys(
    pSe05xSession_t session_ctx, uint8_t *scp03EncKey, uint8_t *scp03MacKey, uint8_t *scp03DecKey)
{
    smStatus_t status;
    tlvHeader_t hdr = {{GP_CLA_BYTE, GP_INS_PUTKEY, KEY_VERSION, GP_P2_MULTIPLEKEYS}};
    uint8_t *pCmd   = NULL;
    uint8_t cmdLen  = 0;
    uint8_t response[64];
    size_t responseLen = sizeof(response);
    uint8_t keyVersion = KEY_VERSION;
    uint8_t keyChkValues[16];
    uint8_t keyChkValLen = 0;
    uint8_t ret          = 0;

    pCmd = &session_ctx->apdu_buffer[0];
    memset(pCmd, 0, sizeof(session_ctx->apdu_buffer));

    pCmd[cmdLen++]               = keyVersion; //keyVersion to replace
    keyChkValues[keyChkValLen++] = keyVersion;

    /* Prepare the packet for ENC Key */
    ret = createKeyData(session_ctx, scp03EncKey, &pCmd[cmdLen]);
    if (ret != 0) {
        SMLOG_E("Error in createKeyData \n");
        return 1;
    }
    memcpy(&keyChkValues[keyChkValLen], &pCmd[cmdLen + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    cmdLen += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for MAC Key */
    ret = createKeyData(session_ctx, scp03MacKey, &pCmd[cmdLen]);
    if (ret != 0) {
        SMLOG_E("Error in createKeyData \n");
        return 1;
    }
    memcpy(&keyChkValues[keyChkValLen], &pCmd[cmdLen + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    cmdLen += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for DEK Key */
    ret = createKeyData(session_ctx, scp03DecKey, &pCmd[cmdLen]);
    if (ret != 0) {
        SMLOG_E("Error in createKeyData \n");
        return 1;
    }
    memcpy(&keyChkValues[keyChkValLen], &pCmd[cmdLen + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    cmdLen += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    status = DoAPDUTxRx(session_ctx, &hdr, &session_ctx->apdu_buffer[0], cmdLen, response, &responseLen, 0);
    if (status != SM_OK) {
        SMLOG_E("Error in DoAPDUTxRx \n");
        return 1;
    }

    status = (response[responseLen - 2] << 8) + response[responseLen - 1];
    if (status == SM_OK) {
        if ((memcmp(response, keyChkValues, keyChkValLen) == 0)) {
            SMLOG_I("Congratulations !!! Key Rotation Example Success \n");
            return 0;
        }
    }

    SMLOG_E("Rotate platformSCP keys example failed ! \n");
    return 1;
}
