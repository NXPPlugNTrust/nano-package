/** @file test_se05x_nist256.c
 *  @brief NIST256 key Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x_utils.h"

/* ********************** Global variables ********************** */
/* clang-format off */
const uint8_t test_se05x_nist256PrivKey[] = {
    0xE4, 0xEE, 0x5F, 0x99, 0xD9, 0xD8, 0x37, 0x8F, 0x39, 0xC2, 0xC9, 0xFD, 0xA9, 0x12, 0x5E, 0xA7,
    0x3F, 0xB8, 0xFD, 0x00, 0xB5, 0x19, 0xE6, 0x94, 0x1E, 0xF1, 0x34, 0x75, 0x8D, 0x33, 0x59, 0x8A,
};

const uint8_t test_se05x_nist256PubKey[] = {
    0x04, 0xF2, 0x24, 0xBC, 0x5E, 0xEA, 0x74, 0x28, 0xA1, 0x20, 0xD3, 0xD2, 0x69, 0xFE, 0x22, 0xF3,
    0x59, 0x9C, 0x20, 0x33, 0xA2, 0xE0, 0xCB, 0x81, 0xC2, 0xCE, 0xA9, 0xD6, 0xD4, 0x66, 0xC3, 0x68,
    0xF8, 0xB6, 0xA8, 0x9C, 0xDE, 0x08, 0x88, 0xB5, 0x49, 0xCD, 0xED, 0x85, 0xD3, 0xB5, 0x88, 0x72,
    0x0A, 0xDC, 0x26, 0x32, 0xB0, 0x30, 0xBF, 0xB1, 0x67, 0xD0, 0xFD, 0xBC, 0x89, 0xE7, 0x2B, 0x9C,
    0xC1,
};
/* clang-format on */

/* ********************** Defines ********************** */
#define TEST_SE05X_NIST256_ID_BASE 0x7B000400

/* ********************** Functions ********************** */

uint8_t test_se05x_nist256_generate_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_se05x_nist256_get_public_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;
    uint8_t key_buf[128]    = {
        0,
    };
    size_t key_buflen = sizeof(key_buf);

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    status = Se05x_API_ReadObject(session_ctx, keyID, 0, 0, key_buf, &key_buflen);
    Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_se05x_nist256_set_key_pair(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        test_se05x_nist256PrivKey,
        sizeof(test_se05x_nist256PrivKey),
        test_se05x_nist256PubKey,
        sizeof(test_se05x_nist256PubKey),
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_se05x_nist256_set_private_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        test_se05x_nist256PrivKey,
        sizeof(test_se05x_nist256PrivKey),
        NULL,
        0,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Private);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_se05x_nist256_set_public_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        NULL,
        0,
        test_se05x_nist256PubKey,
        sizeof(test_se05x_nist256PubKey),
        kSE05x_INS_NA,
        kSE05x_KeyPart_Public);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_se05x_nist256_invalid_args(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_ID_BASE + __LINE__;

    /* clang-format off */
    // NULL session
    status = Se05x_API_WriteECKey(NULL, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_NOT_OK, SE05X_TEST_FAIL);

    // Key id = 0
    status = Se05x_API_WriteECKey(session_ctx, NULL, 0, 0, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED, SE05X_TEST_FAIL);

    // Invalid key pair
    status = Se05x_API_WriteECKey(session_ctx, NULL, 0, 0, curveID, test_se05x_nist256PrivKey, sizeof(test_se05x_nist256PrivKey), NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED, SE05X_TEST_FAIL);

    // Invalid public key length
    status = Se05x_API_WriteECKey(session_ctx, NULL, 0, 0, curveID, NULL, 0, test_se05x_nist256PubKey, sizeof(test_se05x_nist256PubKey)+1, kSE05x_INS_NA, kSE05x_KeyPart_Public);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED, SE05X_TEST_FAIL);

    // Invalid private key length
    status = Se05x_API_WriteECKey(session_ctx, NULL, 0, 0, curveID, test_se05x_nist256PrivKey, sizeof(test_se05x_nist256PrivKey)+1, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Private);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED, SE05X_TEST_FAIL);
    /* clang-format on */

    PASS_SE05X_TEST();
}

void test_se05x_nist256(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    UPDATE_RESULT(test_se05x_nist256_generate_key(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_get_public_key(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_set_key_pair(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_set_private_key(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_set_public_key(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_invalid_args(session_ctx), pass, fail, ignore);
    return;
}
