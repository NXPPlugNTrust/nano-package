/** @file test_se05x_nist256_ecdsa.c
 *  @brief Nist256 ECDSA Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x.h"
#include "test_se05x_utils.h"

/* ********************** Defines ********************** */
#define TEST_SE05X_NIST256_SIGN_VER_ID_BASE (0x7B000600)

/* ********************** Functions ********************** */

static uint8_t test_se05x_get_input_len(SE05x_ECSignatureAlgo_t ecSignAlgo)
{
    uint8_t input_len = 0;
    switch (ecSignAlgo) {
    case kSE05x_ECSignatureAlgo_SHA:
        input_len = 20;
        break;
    case kSE05x_ECSignatureAlgo_SHA_224:
        input_len = 28;
        break;
    case kSE05x_ECSignatureAlgo_SHA_256:
        input_len = 32;
        break;
    case kSE05x_ECSignatureAlgo_SHA_384:
        input_len = 48;
        break;
    default:
        input_len = 0;
    }
    return input_len;
}

uint8_t test_se05x_nist256_ecdsa_sign_verify(
    pSe05xSession_t session_ctx, SE05x_ECSignatureAlgo_t ecSignAlgo, const char *test_name)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_SIGN_VER_ID_BASE + __LINE__;
    uint8_t input[64];
    size_t input_len       = 0;
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    SE05x_Result_t sign_result;
    for (int i = 0; i < sizeof(input); i++) {
        input[i] = i;
    }

    input_len = test_se05x_get_input_len(ecSignAlgo);
    TEST_ENSURE_OR_RETURN_ON_ERROR(input_len != 0, SE05X_TEST_FAIL);

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status =
        Se05x_API_ECDSAVerify(session_ctx, keyID, ecSignAlgo, input, input_len, signature, signature_len, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
    status = SM_NOT_OK;
    TEST_ENSURE_OR_GOTO_EXIT(sign_result == kSE05x_Result_SUCCESS);

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(session_ctx, keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", test_name);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", test_name);
        return SE05X_TEST_FAIL;
    }
}

#define TEST_NIST256_ECDSA_SIGN_VERIFY(DIGEST)                                                                       \
    uint8_t test_se05x_nist256_ecdsa_sign_verify_sha##DIGEST(pSe05xSession_t session_ctx)                            \
    {                                                                                                                \
        return test_se05x_nist256_ecdsa_sign_verify(session_ctx, kSE05x_ECSignatureAlgo_SHA_##DIGEST, __FUNCTION__); \
    }

// TEST_NIST256_ECDSA_SIGN_VERIFY(1)
uint8_t test_se05x_nist256_ecdsa_sign_verify_sha1(pSe05xSession_t session_ctx)
{
    return test_se05x_nist256_ecdsa_sign_verify(session_ctx, kSE05x_ECSignatureAlgo_SHA, __FUNCTION__);
}
TEST_NIST256_ECDSA_SIGN_VERIFY(224)
TEST_NIST256_ECDSA_SIGN_VERIFY(256)
TEST_NIST256_ECDSA_SIGN_VERIFY(384)

uint8_t test_se05x_nist256_ecdsa_sign_pub_key_verify(
    pSe05xSession_t session_ctx, SE05x_ECSignatureAlgo_t ecSignAlgo, const char *test_name)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_SIGN_VER_ID_BASE + __LINE__;
    uint32_t pub_keyID      = TEST_SE05X_NIST256_SIGN_VER_ID_BASE + __LINE__;
    uint8_t input[64];
    size_t input_len       = 0;
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    SE05x_Result_t sign_result;
    uint8_t pub_key[128] = {
        0,
    };
    size_t pub_key_len = sizeof(pub_key);
    for (int i = 0; i < sizeof(input); i++) {
        input[i] = i;
    }

    input_len = test_se05x_get_input_len(ecSignAlgo);
    TEST_ENSURE_OR_RETURN_ON_ERROR(input_len != 0, SE05X_TEST_FAIL);

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ReadObject(session_ctx, keyID, 0, 0, pub_key, &pub_key_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    curveID = kSE05x_ECCurve_NIST_P256;
    if (se05x_object_exists(session_ctx, pub_keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, pub_keyID, curveID, NULL, 0, pub_key, pub_key_len, kSE05x_INS_NA, kSE05x_KeyPart_Public);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ECDSAVerify(
        session_ctx, pub_keyID, ecSignAlgo, input, input_len, signature, signature_len, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
    status = SM_NOT_OK;
    TEST_ENSURE_OR_GOTO_EXIT(sign_result == kSE05x_Result_SUCCESS);

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(session_ctx, keyID);
    Se05x_API_DeleteSecureObject(session_ctx, pub_keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", test_name);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", test_name);
        return SE05X_TEST_FAIL;
    }
}

#define TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(DIGEST)                                            \
    uint8_t test_se05x_nist256_ecdsa_sign_pub_key_verify_sha##DIGEST(pSe05xSession_t session_ctx) \
    {                                                                                             \
        return test_se05x_nist256_ecdsa_sign_pub_key_verify(                                      \
            session_ctx, kSE05x_ECSignatureAlgo_SHA_##DIGEST, __FUNCTION__);                      \
    }

// TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(1)
uint8_t test_se05x_nist256_ecdsa_sign_pub_key_verify_sha1(pSe05xSession_t session_ctx)
{
    return test_se05x_nist256_ecdsa_sign_pub_key_verify(session_ctx, kSE05x_ECSignatureAlgo_SHA, __FUNCTION__);
}
TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(224)
TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(256)
TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(384)

uint8_t test_se05x_nist256_ecdsa_sign_verify_corr_sig(
    pSe05xSession_t session_ctx, SE05x_ECSignatureAlgo_t ecSignAlgo, const char *test_name)
{
    smStatus_t status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_SIGN_VER_ID_BASE + __LINE__;
    uint8_t input[64];
    size_t input_len       = 0;
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    SE05x_Result_t sign_result;

    for (int i = 0; i < sizeof(input); i++) {
        input[i] = i;
    }

    input_len = test_se05x_get_input_len(ecSignAlgo);
    TEST_ENSURE_OR_RETURN_ON_ERROR(input_len != 0, SE05X_TEST_FAIL);

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    // corrupt data
    signature[0] ^= 0xFF;
    signature[1] ^= 0xFF;
    status =
        Se05x_API_ECDSAVerify(session_ctx, keyID, ecSignAlgo, input, input_len, signature, signature_len, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
    status = SM_NOT_OK;
    TEST_ENSURE_OR_GOTO_EXIT(sign_result == kSE05x_Result_FAILURE);

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(session_ctx, keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", test_name);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", test_name);
        return SE05X_TEST_FAIL;
    }
}

#define TEST_NIST256_ECDSA_SIGN_VERIFY_CORR_SIG(DIGEST)                                               \
    uint8_t test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha##DIGEST(pSe05xSession_t session_ctx) \
    {                                                                                                 \
        return test_se05x_nist256_ecdsa_sign_verify_corr_sig(                                         \
            session_ctx, kSE05x_ECSignatureAlgo_SHA_##DIGEST, __FUNCTION__);                          \
    }

// TEST_NIST256_ECDSA_SIGN_PUB_KEY_VERIFY(1)
uint8_t test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha1(pSe05xSession_t session_ctx)
{
    return test_se05x_nist256_ecdsa_sign_verify_corr_sig(session_ctx, kSE05x_ECSignatureAlgo_SHA, __FUNCTION__);
}
TEST_NIST256_ECDSA_SIGN_VERIFY_CORR_SIG(224)
TEST_NIST256_ECDSA_SIGN_VERIFY_CORR_SIG(256)
TEST_NIST256_ECDSA_SIGN_VERIFY_CORR_SIG(384)

uint8_t test_se05x_nist256_ecdsa_sign_verify_invalid_data(pSe05xSession_t session_ctx)
{
    smStatus_t status       = SM_NOT_OK;
    smStatus_t test_status  = SM_NOT_OK;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint32_t keyID          = TEST_SE05X_NIST256_SIGN_VER_ID_BASE + __LINE__;
    uint8_t input[64];
    size_t input_len       = 0;
    uint8_t signature[128] = {
        0,
    };
    size_t signature_len = sizeof(signature);
    SE05x_Result_t sign_result;
    SE05x_ECSignatureAlgo_t ecSignAlgo = kSE05x_ECSignatureAlgo_SHA_256;

    for (int i = 0; i < sizeof(input); i++) {
        input[i] = i;
    }

    input_len = test_se05x_get_input_len(ecSignAlgo);
    TEST_ENSURE_OR_RETURN_ON_ERROR(input_len != 0, SE05X_TEST_FAIL);

    if (se05x_object_exists(session_ctx, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    status = Se05x_API_WriteECKey(
        session_ctx, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /* Invalid key */
    status = Se05x_API_ECDSASign(session_ctx, keyID + 0x100, ecSignAlgo, input, input_len, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);

    /* Invalid input length */
    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len + 1, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);

    /* Invalid signature buffer length */
    signature_len = 65;
    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len + 1, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);
    signature_len = sizeof(signature);

    status = Se05x_API_ECDSASign(session_ctx, keyID, ecSignAlgo, input, input_len, signature, &signature_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /* Invalid key */
    status = Se05x_API_ECDSAVerify(
        session_ctx, keyID + 0x100, ecSignAlgo, input, input_len, signature, signature_len, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);

    /* Invalid input length */
    status = Se05x_API_ECDSAVerify(
        session_ctx, keyID + 0x100, ecSignAlgo, input, input_len + 1, signature, signature_len, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);

    /* Invalid input length */
    status = Se05x_API_ECDSAVerify(
        session_ctx, keyID + 0x100, ecSignAlgo, input, input_len + 1, signature, signature_len - 10, &sign_result);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED);

    test_status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(session_ctx, keyID);

    if (test_status == SM_OK) {
        SMLOG_I("%s, PASSED \n", __FUNCTION__);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", __FUNCTION__);
        return SE05X_TEST_FAIL;
    }
}

void test_se05x_nist256_ecdsa(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_sha1(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_sha224(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_sha256(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_sha384(session_ctx), pass, fail, ignore);

    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_pub_key_verify_sha1(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_pub_key_verify_sha224(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_pub_key_verify_sha256(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_pub_key_verify_sha384(session_ctx), pass, fail, ignore);

    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha1(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha224(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha256(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_corrupt_sig_sha384(session_ctx), pass, fail, ignore);

    UPDATE_RESULT(test_se05x_nist256_ecdsa_sign_verify_invalid_data(session_ctx), pass, fail, ignore);

    return;
}
