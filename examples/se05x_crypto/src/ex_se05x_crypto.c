/** @file ex_se05x_crypto.c
 *  @brief se05x crypto example
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "se05x_scp03_crypto.h"
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
#define ATTESTATION_KEY_ID 0xF0000012

/* ********************** Global variables ********************** */

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973

uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

// Certificate buffers
uint8_t certificate_ret[CERT_SIZE] = {0};
uint8_t certificate[CERT_SIZE]     = {0};
size_t certificate_len;
size_t certificate_ret_len;

/**** EC Auth Key ****/
/* Key pair corresponding to - ECKEY_AUTH_OBJECT_ID */
/* clang-format off */
/* Key pair corresponding to - ECKEY_AUTH_OBJECT_ID */
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

/**** nist384 key pair ****/
/* clang-format off */
const uint8_t nist384PrivKey[] = {
    0x7d, 0x79, 0xa9, 0xa9, 0xbd, 0x20, 0x28, 0x31, 0xbd, 0x00, 0xd7, 0x51, 0x35, 0x3c, 0xd4, 0xe0,
    0x2c, 0xd3, 0x93, 0x53, 0xc1, 0x4d, 0x0c, 0x36, 0xde, 0x29, 0xb1, 0x3e, 0x56, 0xc9, 0x48, 0xff,
    0x37, 0xe5, 0x73, 0x22, 0xf8, 0xe5, 0xe5, 0x2e, 0xb9, 0x34, 0xbc, 0x85, 0xbf, 0xa4, 0xaa, 0xc5
};
const uint8_t nist384PubKey[] = {
    0x04, 0x74, 0x19, 0x1f, 0x4f, 0x1e, 0x4a, 0x03, 0xff, 0x6d, 0x4c, 0x59, 0x2c, 0x55, 0x7d, 0x1d,
    0x2c, 0x9e, 0xb9, 0x91, 0x65, 0xa9, 0xbe, 0xe6, 0x67, 0x38, 0xa6, 0x67, 0x6e, 0x74, 0xff, 0x8e,
    0x1e, 0x90, 0x6e, 0x90, 0x01, 0xd1, 0xc8, 0x79, 0xff, 0x48, 0xd1, 0x3e, 0x6b, 0xe2, 0x0a, 0x1f,
    0x51, 0x76, 0xb5, 0x1a, 0x23, 0xc4, 0xb5, 0xf5, 0xef, 0x0a, 0x6a, 0x08, 0x6a, 0xc3, 0x3e, 0x76,
    0x75, 0xa5, 0xc8, 0xf1, 0xdb, 0x38, 0x27, 0xc6, 0x7b, 0xaf, 0x6b, 0x14, 0xfc, 0xca, 0xa2, 0xf3,
    0xd6, 0xfb, 0xa0, 0x56, 0x55, 0xdb, 0x72, 0x64, 0x89, 0x66, 0x92, 0x4a, 0x4c, 0xe5, 0xea, 0x17,
    0xa0
};
/* clang-format on */

/* clang-format off */
#define EC_PARAM_prime  \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
#define EC_PARAM_a      \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
#define EC_PARAM_b      \
    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, \
    0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19, \
    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, \
    0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A, \
    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, \
    0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
#define EC_PARAM_x      \
    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, \
    0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74, \
    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, \
    0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, \
    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, \
    0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
#define EC_PARAM_y      \
    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, \
    0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29, \
    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, \
    0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0, \
    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, \
    0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F
#define EC_PARAM_order  \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
    0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, \
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, \
    0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73

/* clang-format on */

/* ********************** Functions ********************** */

smStatus_t ex_se05x_create_curve(pSe05xSession_t session_ctx, uint32_t curve_id)
{
    smStatus_t status;
    const uint8_t ecc_prime[]  = {EC_PARAM_prime};
    const uint8_t ecc_a[]      = {EC_PARAM_a};
    const uint8_t ecc_b[]      = {EC_PARAM_b};
    const uint8_t ecc_G[]      = {0x04, EC_PARAM_x, EC_PARAM_y};
    const uint8_t ecc_ordern[] = {EC_PARAM_order};

    status = Se05x_API_CreateECCurve(session_ctx, (SE05x_ECCurve_t)curve_id);
    if (status != SM_OK) {
        return status;
    }
    status = Se05x_API_SetECCurveParam(
        session_ctx, (SE05x_ECCurve_t)curve_id, kSE05x_ECCurveParam_PARAM_A, ecc_a, sizeof(ecc_a) / sizeof(ecc_a[0]));
    if (status != SM_OK) {
        return status;
    }
    status = Se05x_API_SetECCurveParam(
        session_ctx, (SE05x_ECCurve_t)curve_id, kSE05x_ECCurveParam_PARAM_B, ecc_b, sizeof(ecc_b) / sizeof(ecc_b[0]));
    if (status != SM_OK) {
        return status;
    }
    status = Se05x_API_SetECCurveParam(
        session_ctx, (SE05x_ECCurve_t)curve_id, kSE05x_ECCurveParam_PARAM_G, ecc_G, sizeof(ecc_G) / sizeof(ecc_G[0]));
    if (status != SM_OK) {
        return status;
    }
    status = Se05x_API_SetECCurveParam(session_ctx,
        (SE05x_ECCurve_t)curve_id,
        kSE05x_ECCurveParam_PARAM_N,
        ecc_ordern,
        sizeof(ecc_ordern) / sizeof(ecc_ordern[0]));
    if (status != SM_OK) {
        return status;
    }
    status = Se05x_API_SetECCurveParam(session_ctx,
        (SE05x_ECCurve_t)curve_id,
        kSE05x_ECCurveParam_PARAM_PRIME,
        ecc_prime,
        sizeof(ecc_prime) / sizeof(ecc_prime[0]));
    return status;
}

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
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_TRANSIENT, kSE05x_KeyPart_Pair);
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
    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        pub_keyID,
        curveID,
        NULL,
        0,
        pub_key,
        pub_key_len,
        kSE05x_INS_TRANSIENT,
        kSE05x_KeyPart_Public);
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

int ex_generate_nist384_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID = TEST_ID_BASE + __LINE__;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P384;
    uint8_t curveList[32]   = {
        0,
    };
    size_t curveListLen = 32;

    status = Se05x_API_ReadECCurveList(session_ctx, curveList, &curveListLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadECCurveList \n");
        goto exit;
    }
    else {
        if (curveList[curveID - 1] == kSE05x_SetIndicator_SET) {
            SMLOG_I("curveID = %0x already exists \n", curveID);
        }
        else {
            status = ex_se05x_create_curve(session_ctx, curveID);
            if (status != SM_OK) {
                SMLOG_I("Error in ex_se05x_create_curve \n");
                goto exit;
            }
        }
    }

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

int ex_set_get_nist384_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint8_t key_buf[256] = {
        0,
    };
    size_t key_buflen = sizeof(key_buf);
    uint32_t keyID    = TEST_ID_BASE + __LINE__;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P384;

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

    /* Set nist384 key pair */
    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        nist384PrivKey,
        sizeof(nist384PrivKey),
        nist384PubKey,
        sizeof(nist384PubKey),
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

    if ((key_buflen != sizeof(nist384PubKey)) || (memcmp(key_buf, nist384PubKey, key_buflen) != 0)) {
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

int ex_nist384_sign_verify(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID     = TEST_ID_BASE + __LINE__;
    uint32_t pub_keyID = TEST_ID_BASE + __LINE__;
    uint8_t input[32];
    size_t input_len = sizeof(input);
    for (int i = 0; i < input_len; i++) {
        input[i] = i;
    }
    uint8_t signature[150] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    uint8_t pub_key[128] = {
        0,
    };
    size_t pub_key_len = sizeof(pub_key);
    SE05x_Result_t sign_result;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P384;

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

    /* Generate nist384 key */
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
        curveID = kSE05x_ECCurve_NIST_P384;
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
    uint32_t keyID   = TEST_ID_BASE + __LINE__;
    size_t file_size = sizeof(certificate);
    size_t offset    = 0;
    size_t blk_size  = SET_CERT_BLK_SIZE;
    size_t i         = 0;
    SE05x_Result_t result;

    certificate_len     = sizeof(certificate);
    certificate_ret_len = sizeof(certificate_ret);

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

int ex_read_attst_object(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_Result_t result;
    uint32_t keyID          = TEST_ID_BASE + __LINE__;
    uint32_t pub_keyID      = TEST_ID_BASE + __LINE__;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint8_t random[16]      = {
        0,
    };
    size_t randomLen    = sizeof(random);
    uint8_t cmd[256]    = {0};
    size_t cmdLen       = sizeof(cmd);
    uint8_t rspBuf[256] = {0};
    size_t rspbufLen    = sizeof(rspBuf);

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

    /* Read the key at location 'keyID' and using the attestation from key id 'ATTESTATION_KEY_ID' */
    status = Se05x_API_ReadObject_W_Attst(session_ctx,
        keyID,
        0,
        0,
        ATTESTATION_KEY_ID,
        kSE05x_AttestationAlgo_EC_SHA_256,
        random,
        randomLen,
        cmd,
        &cmdLen,
        rspBuf,
        &rspbufLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject_W_Attst \n");
        goto exit;
    }

    /* Attestation Verification part */
    /* Below part of the code require host crypto support */
#if 0
    {
        int tlvRet               = 0;
        uint8_t chipId[18]       = {0};
        size_t chipIdLen         = sizeof(chipId);
        uint8_t attribute[128]   = {0};
        size_t attributeLen      = sizeof(attribute);
        uint8_t data[256]        = {0};
        size_t dataLen           = sizeof(data);
        uint8_t objectSize[2]    = {0};
        size_t objectSizeLen     = sizeof(objectSize);
        uint8_t ts[32]           = {0};
        size_t tsLen             = sizeof(ts);
        uint8_t signature[128]   = {0};
        size_t signatureLen      = sizeof(signature);
        int ret                  = 0;
        uint8_t cmd_digest[32]   ={0};
        size_t cmd_digestLen     = sizeof(cmd_digest);
        uint8_t digest[32]       ={0};
        size_t digestLen         = sizeof(digest);
        uint8_t inputData[256]   = {0};
        size_t inputDataLen      = 0;
        uint8_t pub_key[128]     = {0};
        size_t pub_keylen        = sizeof(pub_key);
        SE05x_Result_t sign_result = kSE05x_Result_FAILURE;
        size_t rspIndex          = 0;
        uint8_t outRandom[32]    = {0};
        size_t outRandomLen      = sizeof(outRandom);

        tlvRet  = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, &dataLen); /*  */
        if (0 != tlvRet) {
            /* Keys with no read policy will not return TAG1 */
            //goto cleanup;
        }
        tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_2, chipId, &chipIdLen); /*  */
        if (0 != tlvRet) {
            goto exit;
        }
        tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_3, attribute, &attributeLen); /*  */
        if (0 != tlvRet) {
            goto exit;
        }

        if(session_ctx->applet_version >= 0x7020000){
            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_4, objectSize, &objectSizeLen); /*  */
            if (0 != tlvRet) {
                goto exit;
            }

            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_TIMESTAMP, ts, &tsLen);
            if(0 != tlvRet){
                goto exit;
            }

            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_SIGNATURE, signature, &signatureLen); /*  */
            if (0 != tlvRet) {
                goto exit;
            }
        }
        else {
            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_4, outRandom, &outRandomLen); /*  */
            if (0 != tlvRet) {
                goto exit;
            }

            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_5, ts, &tsLen);
            if(0 != tlvRet){
                goto exit;
            }

            tlvRet = tlvGet_u8buf(rspBuf, &rspIndex, rspbufLen, kSE05x_TAG_6, signature, &signatureLen); /*  */
            if (0 != tlvRet) {
                goto exit;
            }
        }

        if(session_ctx->applet_version >= 0x7020000){
            /* Calculate the digest of command data */
            ret = hcrypto_digest_one_go(cmd, cmdLen, cmd_digest, &cmd_digestLen);
            if(ret != 0) {
                goto exit;
            }

            /* Append digest(cmd) + Response data excuding the signature TLV */
            memcpy(inputData, cmd_digest, cmd_digestLen);
            inputDataLen += cmd_digestLen;
            memcpy(inputData + inputDataLen, rspBuf, rspbufLen - signatureLen - 6); /* 6 ==> TLV of Signature and Response (0x9000)*/
            inputDataLen += rspbufLen - signatureLen - 6;
        }
        else {

            memcpy(inputData, data, dataLen);
            inputDataLen += dataLen;

            memcpy(inputData+inputDataLen, chipId, chipIdLen);
            inputDataLen += chipIdLen;

            memcpy(inputData+inputDataLen, attribute, attributeLen);
            inputDataLen += attributeLen;

            memcpy(inputData+inputDataLen, outRandom, outRandomLen);
            inputDataLen += outRandomLen;

            memcpy(inputData+inputDataLen, ts, tsLen);
            inputDataLen += tsLen;
        }

        /* Caluclate digest of (digest(cmd) + Response data excuding the signature TLV) */
        ret = hcrypto_digest_one_go(inputData, inputDataLen, digest, &digestLen);
        if(ret != 0) {
            goto exit;
        }

        /* Read Attestation Public Key */
        status = Se05x_API_ReadObject(session_ctx, ATTESTATION_KEY_ID, 0, 0, pub_key, &pub_keylen);
        if(status != SM_OK)
        {
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
            /* If key already exists, set curveID = NA */
            curveID = kSE05x_ECCurve_NA;
        }

        /* Set Attestation Public Key */
        status = Se05x_API_WriteECKey(
            session_ctx, NULL, 0, pub_keyID, curveID, NULL, 0, pub_key, pub_keylen, kSE05x_INS_NA, kSE05x_KeyPart_Public);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_WriteECKey \n");
            goto exit;
        }

        /* Verify the signature received from SE */
        status = Se05x_API_ECDSAVerify(session_ctx,
            pub_keyID,
            kSE05x_ECSignatureAlgo_SHA_256,
            digest,
            digestLen,
            signature,
            signatureLen,
            &sign_result);
        if(status != SM_OK) {
            goto exit;
        }

        if (sign_result != kSE05x_Result_SUCCESS){
            SMLOG_E("Verification of Attestation Signature failed \n");
            goto exit;
        }
        SMLOG_I("Attestation Signature verification success \n");

        status = Se05x_API_DeleteSecureObject(session_ctx, pub_keyID);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
            // Ignore the error
            // goto exit;
        }
    }
#endif

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        // Ignore the error
        // goto exit;
    }

    EX_PASS;
exit:
    EX_FAIL;
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
    ex_generate_nist384_key(&se05x_session);
    ex_set_get_nist384_key(&se05x_session);
    ex_nist384_sign_verify(&se05x_session);
    ex_set_certificate(&se05x_session);
    ex_ecdh(&se05x_session);
    ex_aes_ECB_NOPAD(&se05x_session);
    ex_aes_CBC_NOPAD(&se05x_session);
    ex_aes_CTR(&se05x_session);
    ex_nist256_sign_policy(&se05x_session);
    ex_read_attst_object(&se05x_session);

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}
