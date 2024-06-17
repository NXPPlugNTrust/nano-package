/** @file ex_se05x_crypto.c
 *  @brief se05x crypto example
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"

/* ********************** Defines ********************** */

#define EX_FAIL                                 \
    {                                           \
        SMLOG_I("%s, FAILED \n", __FUNCTION__); \
        return 1;                               \
    }

#define EX_PASS                                 \
    {                                           \
        SMLOG_I("%s, PASSED \n", __FUNCTION__); \
        return 0;                               \
    }

#define TEST_ID_BASE 0x7B000100
#define CERT_SIZE 1024
#define SET_CERT_BLK_SIZE 128

/* ********************** Global variables ********************** */

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973

uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

/**** EC Auth Key ****/
/* clang-format off */
uint8_t ec_auth_key[] = {                                                 \
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,                   \
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,                   \
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,                   \
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,                   \
        0x01, 0x01, 0x04, 0x20,                                           \
        0x6D, 0x2F, 0x43, 0x2F, 0x8A, 0x2F, 0x45, 0xEC,                   \
        0xD5, 0x82, 0x84, 0x7E, 0xC0, 0x83, 0xBB, 0xEB,                   \
        0xC2, 0x3F, 0x1D, 0xF4, 0xF0, 0xDD, 0x2A, 0x6F,                   \
        0xB8, 0x1A, 0x24, 0xE7, 0xB6, 0xD5, 0x4C, 0x7F,                   \
        0xA1, 0x44, 0x03, 0x42, 0x00,                                     \
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,                   \
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,                   \
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,                   \
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,                   \
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,                   \
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,                   \
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,                   \
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,                   \
        0xC4                                                              \
    };
/* clang-format on */

/**** nist256 key pair ****/
/* clang-format off */
const uint8_t nist256PrivKey[] = {
    0xE4, 0xEE, 0x5F, 0x99, 0xD9, 0xD8, 0x37, 0x8F, 0x39, 0xC2, 0xC9, 0xFD, 0xA9, 0x12, 0x5E, 0xA7,
    0x3F, 0xB8, 0xFD, 0x00, 0xB5, 0x19, 0xE6, 0x94, 0x1E, 0xF1, 0x34, 0x75, 0x8D, 0x33, 0x59, 0x8A,
};
const uint8_t nist256PubKey[] = {
    0x04, 0xF2, 0x24, 0xBC, 0x5E, 0xEA, 0x74, 0x28, 0xA1, 0x20, 0xD3, 0xD2, 0x69, 0xFE, 0x22, 0xF3,
    0x59, 0x9C, 0x20, 0x33, 0xA2, 0xE0, 0xCB, 0x81, 0xC2, 0xCE, 0xA9, 0xD6, 0xD4, 0x66, 0xC3, 0x68,
    0xF8, 0xB6, 0xA8, 0x9C, 0xDE, 0x08, 0x88, 0xB5, 0x49, 0xCD, 0xED, 0x85, 0xD3, 0xB5, 0x88, 0x72,
    0x0A, 0xDC, 0x26, 0x32, 0xB0, 0x30, 0xBF, 0xB1, 0x67, 0xD0, 0xFD, 0xBC, 0x89, 0xE7, 0x2B, 0x9C,
    0xC1,
};
/* clang-format on */

/* ********************** Functions ********************** */

void print_key(uint8_t *key_buf, size_t key_buflen)
{
    size_t i = 0;
    for (i = 0; i < key_buflen; i++) {
        SMLOG_I("%02x ", key_buf[i]);
        if ((i + 1) % 8 == 0 && i != 0) {
            SMLOG_I("\n");
        }
    }
    SMLOG_I("\n");
}

int ex_get_version(pSe05xSession_t session_ctx)
{
    uint8_t version[64] = {
        0,
    };
    size_t version_len = sizeof(version);
    smStatus_t status;

    SMLOG_I("Get Version ==> \n");
    status = Se05x_API_GetVersion(session_ctx, version, &version_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_GetVersion \n");
        goto exit;
    }
    SMLOG_I("Applet Version %d.%d.%d \n", version[0], version[1], version[2]);
    EX_PASS;
exit:
    EX_FAIL;
}

int ex_generate_nist256_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID = TEST_ID_BASE + __LINE__;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, set curveID = NA  */
        curveID = kSE05x_ECCurve_NA;
    }

    /* Generate key */
    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

int ex_set_get_nist256_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint8_t key_buf[128] = {
        0,
    };
    size_t key_buflen = sizeof(key_buf);
    uint32_t keyID    = TEST_ID_BASE + __LINE__;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, set curveID = NA  */
        curveID = kSE05x_ECCurve_NA;
    }

    /* Set nist256 key pair */
    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        nist256PrivKey,
        sizeof(nist256PrivKey),
        nist256PubKey,
        sizeof(nist256PubKey),
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Read public key */
    status = Se05x_API_ReadObject(session_ctx, keyID, 0, 0, key_buf, &key_buflen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        goto exit;
    }

    if ((key_buflen != sizeof(nist256PubKey)) || (memcmp(key_buf, nist256PubKey, key_buflen) != 0)) {
        SMLOG_E("Public key not same \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

int ex_nist256_sign_verify(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID     = TEST_ID_BASE + __LINE__;
    uint32_t pub_keyID = TEST_ID_BASE + __LINE__;
    uint8_t input[32];
    size_t input_len = sizeof(input);
    for (int i = 0; i < input_len; i++) {
        input[i] = i;
    }
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    uint8_t pub_key[128] = {
        0,
    };
    size_t pub_key_len = sizeof(pub_key);
    SE05x_Result_t sign_result;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, set curveID = NA */
        curveID = kSE05x_ECCurve_NA;
    }

    /* Generate nist256 key */
    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Sign input data using key at 'keyId' */
    status = Se05x_API_ECDSASign(
        session_ctx, keyID, kSE05x_ECSignatureAlgo_SHA_256, input, input_len, signature, &signature_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        goto exit;
    }

    /* Read public key at 'keyId' */
    status = Se05x_API_ReadObject(session_ctx, keyID, 0, 0, pub_key, &pub_key_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        goto exit;
    }

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, pub_keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        curveID = kSE05x_ECCurve_NA;
    }
    else {
        curveID = kSE05x_ECCurve_NIST_P256;
    }

    /* Set public key */
    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, pub_keyID, curveID, NULL, 0, pub_key, pub_key_len, kSE05x_INS_NA, kSE05x_KeyPart_Public);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Verify signature using public key at location 'pub_keyID' */
    status = Se05x_API_ECDSAVerify(session_ctx,
        pub_keyID,
        kSE05x_ECSignatureAlgo_SHA_256,
        input,
        input_len,
        signature,
        signature_len,
        &sign_result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        goto exit;
    }

    if (sign_result != kSE05x_Result_SUCCESS) {
        SMLOG_E("verification failed \n");
        goto exit;
    }

    /* Corrupt signature and expect verification failure */
    signature[0] = 0;
    signature[1] = 0;
    status       = Se05x_API_ECDSAVerify(session_ctx,
        pub_keyID,
        kSE05x_ECSignatureAlgo_SHA_256,
        input,
        input_len,
        signature,
        signature_len,
        &sign_result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        goto exit;
    }

    if (sign_result != kSE05x_Result_FAILURE) {
        SMLOG_E("verification should have failed \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, pub_keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

int ex_set_certificate(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint8_t certificate[CERT_SIZE] = {
        0,
    };
    size_t certificate_len             = sizeof(certificate);
    uint8_t certificate_ret[CERT_SIZE] = {
        0,
    };
    size_t certificate_ret_len = sizeof(certificate_ret);
    uint32_t keyID             = TEST_ID_BASE + __LINE__;
    size_t file_size           = sizeof(certificate);
    size_t offset              = 0;
    size_t blk_size            = SET_CERT_BLK_SIZE;
    size_t i                   = 0;
    SE05x_Result_t result;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If binary file already exsists, Set file size = 0 */
        file_size = 0;
    }

    for (i = 0; i < certificate_len; i++) {
        certificate[i] = i;
    }

    /* Set certificate with chunks of blk_size(128) */
    for (offset = 0; offset < certificate_len; offset = offset + blk_size) {
        status = Se05x_API_WriteBinary(session_ctx, NULL, keyID, offset, file_size, certificate + offset, blk_size);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_WriteBinary \n");
            goto exit;
        }
        file_size = 0;
    }

    /* Retrive certificate from offset 200 */
    status = Se05x_API_ReadObject(session_ctx, keyID, 200 /*offset*/, blk_size, certificate_ret, &certificate_ret_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        goto exit;
    }

    if ((certificate_ret_len != blk_size) || (memcmp(certificate + 200, certificate_ret, certificate_ret_len) != 0)) {
        SMLOG_E("certificate not same \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

int ex_ecdh(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID = TEST_ID_BASE + __LINE__;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID  = kSE05x_ECCurve_NIST_P256;
    uint8_t sharedSecret[32] = {
        0,
    };
    size_t sharedSecret_len = sizeof(sharedSecret);

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, set curveID = NA */
        curveID = kSE05x_ECCurve_NA;
    }

    /* Generate nist256 key */
    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Calulate ECDH key using key pair at location 'keyID' and public key in buffer 'nist256PubKey' */
    status = Se05x_API_ECDHGenerateSharedSecret(
        session_ctx, keyID, nist256PubKey, sizeof(nist256PubKey), sharedSecret, &sharedSecret_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDHGenerateSharedSecret \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

int ex_aes(pSe05xSession_t session_ctx, SE05x_CipherMode_t cipherMode)
{
    smStatus_t status;
    uint32_t keyID = TEST_ID_BASE + __LINE__;
    /* clang-format off */
    uint8_t key[16];
    uint8_t data[16] = {
        1, 1, 1, 1, 1, 1, 1, 1,
    };
    /* clang-format on */
    size_t key_len = sizeof(key);
    for (int i = 0; i < key_len; i++) {
        key[i] = i;
    }
    size_t data_len = sizeof(data);
    uint8_t enc[16] = {
        0,
    };
    size_t enc_len  = sizeof(enc);
    uint8_t dec[16] = {
        0,
    };
    size_t dec_len = sizeof(dec);

    /* Write symm key */
    status = Se05x_API_WriteSymmKey(
        session_ctx, NULL, 0, keyID, SE05x_KeyID_KEK_NONE, key, key_len, kSE05x_INS_NA, kSE05x_SymmKeyType_AES);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteSymmKey \n");
        goto exit;
    }

    /* Encrypt data */
    status = Se05x_API_CipherOneShot(
        session_ctx, keyID, cipherMode, data, data_len, NULL, 0, enc, &enc_len, kSE05x_Cipher_Oper_OneShot_Encrypt);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CipherOneShot \n");
        goto exit;
    }

    /* Decrypt data */
    status = Se05x_API_CipherOneShot(
        session_ctx, keyID, cipherMode, enc, enc_len, NULL, 0, dec, &dec_len, kSE05x_Cipher_Oper_OneShot_Decrypt);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CipherOneShot \n");
        goto exit;
    }

    if (memcmp(dec, data, data_len) != 0) {
        SMLOG_E("Decrypt data not same \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    return 0;
exit:
    return -1;
}

#define EX_AES_FUNC(MODE)                                             \
    int ex_aes_##MODE(pSe05xSession_t session_ctx)                    \
    {                                                                 \
        if (ex_aes(session_ctx, kSE05x_CipherMode_AES_##MODE) != 0) { \
            goto exit;                                                \
        }                                                             \
        EX_PASS;                                                      \
    exit:                                                             \
        EX_FAIL;                                                      \
    }

EX_AES_FUNC(ECB_NOPAD)
EX_AES_FUNC(CBC_NOPAD)
EX_AES_FUNC(CTR)

int ex_nist256_sign_policy(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID = TEST_ID_BASE + __LINE__;
    uint8_t input[32];
    size_t input_len = sizeof(input);
    for (int i = 0; i < input_len; i++) {
        input[i] = i;
    }
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;

    uint8_t policyBuf[64] = {
        0,
    };
    size_t policyBuflen   = 0;
    uint32_t policyHeader = 0;
    uint32_t AuthObjId    = 0;
    Se05xPolicy_t eccKeyPolicy;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, delete the key */
        SMLOG_I("Deleting key with id %02x \n", keyID);
        status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
            goto exit;
        }
    }

    /* Set Read, Write, Generate, Read, Delete policy. No sign / verify policy is set. */
    policyHeader = POLICY_OBJ_ALLOW_WRITE;
    policyHeader |= POLICY_OBJ_ALLOW_GEN;
    policyHeader |= POLICY_OBJ_ALLOW_READ;
    policyHeader |= POLICY_OBJ_ALLOW_DELETE;
    //policyHeader |= POLICY_OBJ_ALLOW_SIGN; //No sign policy added.

    policyBuf[policyBuflen++] = 0; //Update At end.

    policyBuf[policyBuflen++] = (uint8_t)((AuthObjId >> 3 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((AuthObjId >> 2 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((AuthObjId >> 1 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((AuthObjId >> 0 * 8) & 0xFF);

    policyBuf[policyBuflen++] = (uint8_t)((policyHeader >> 3 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((policyHeader >> 2 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((policyHeader >> 1 * 8) & 0xFF);
    policyBuf[policyBuflen++] = (uint8_t)((policyHeader >> 0 * 8) & 0xFF);

    policyBuf[0] = policyBuflen - 1;

    eccKeyPolicy.value     = &policyBuf[0];
    eccKeyPolicy.value_len = policyBuflen;

    /* Generate nist256 key */
    status = Se05x_API_WriteECKey(
        session_ctx, &eccKeyPolicy, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Sign input data using key at 'keyId' */
    status = Se05x_API_ECDSASign(
        session_ctx, keyID, kSE05x_ECSignatureAlgo_SHA_256, input, input_len, signature, &signature_len);
    if (status != SM_ERR_ACCESS_DENIED_BASED_ON_POLICY) {
        SMLOG_E("Se05x_API_ECDSASign should have failed with 'SM_ERR_ACCESS_DENIED_BASED_ON_POLICY' \n");
        goto exit;
    }

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
}

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL; // DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

void ex_set_ec_auth_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pEc_auth_key    = &ec_auth_key[0];
    session_ctx->ec_auth_key_len = sizeof(ec_auth_key);
    return;
}

int ex_se05x_crypto()
{
    smStatus_t status;
    Se05xSession_t se05x_session = {
        0,
    };

    /* Based on the cmake option, set either of the one keys in your application */
    ex_set_scp03_keys(&se05x_session);
    ex_set_ec_auth_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    ex_get_version(&se05x_session);
    ex_generate_nist256_key(&se05x_session);
    ex_set_get_nist256_key(&se05x_session);
    ex_nist256_sign_verify(&se05x_session);
    ex_set_certificate(&se05x_session);
    ex_ecdh(&se05x_session);
    ex_aes_ECB_NOPAD(&se05x_session);
    ex_aes_CBC_NOPAD(&se05x_session);
    ex_aes_CTR(&se05x_session);
    ex_nist256_sign_policy(&se05x_session);

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}
