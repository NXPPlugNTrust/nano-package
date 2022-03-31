/** @file test_se05x_nist256_ecdh.c
 *  @brief NIST256 ECDH Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x_utils.h"

/* ********************** Defines ********************** */
#define TEST_SE05X_NIST256_ECDH_OBJ_ID_BASE 0x7B000500

/* clang-format off */
const uint8_t nist256PubKey[] = {
    0x04, 0xF2, 0x24, 0xBC, 0x5E, 0xEA, 0x74, 0x28, 0xA1, 0x20, 0xD3, 0xD2, 0x69, 0xFE, 0x22, 0xF3,
    0x59, 0x9C, 0x20, 0x33, 0xA2, 0xE0, 0xCB, 0x81, 0xC2, 0xCE, 0xA9, 0xD6, 0xD4, 0x66, 0xC3, 0x68,
    0xF8, 0xB6, 0xA8, 0x9C, 0xDE, 0x08, 0x88, 0xB5, 0x49, 0xCD, 0xED, 0x85, 0xD3, 0xB5, 0x88, 0x72,
    0x0A, 0xDC, 0x26, 0x32, 0xB0, 0x30, 0xBF, 0xB1, 0x67, 0xD0, 0xFD, 0xBC, 0x89, 0xE7, 0x2B, 0x9C,
    0xC1,
};
/* clang-format on */

uint8_t test_nist256_ecdh_generate(Se05xSession_t *pSession)
{
    smStatus_t status;
    uint32_t keyID          = TEST_SE05X_NIST256_ECDH_OBJ_ID_BASE + __LINE__;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint8_t sharedSecret[32];
    size_t sharedSecret_len = sizeof(sharedSecret);

    if (se05x_object_exists(pSession, keyID)) {
        curveID = kSE05x_ECCurve_NA;
    }

    /*Generates EC Key Object*/
    status =
        Se05x_API_WriteECKey(pSession, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    /* Calulate ECDH key using key pair at location keyID and public key in buffer nist256*/
    status = Se05x_API_ECDHGenerateSharedSecret(
        pSession, keyID, nist256PubKey, sizeof(nist256PubKey), sharedSecret, &sharedSecret_len);
    Se05x_API_DeleteSecureObject(pSession, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status == SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

uint8_t test_nist256_ecdh_gen_twokeypairs(Se05xSession_t *pSession)
{
    smStatus_t status;
    uint32_t keyid1 = TEST_SE05X_NIST256_ECDH_OBJ_ID_BASE + __LINE__;
    uint32_t keyid2 = TEST_SE05X_NIST256_ECDH_OBJ_ID_BASE + __LINE__;
    uint8_t pub_key[128];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t pub_key2[128];
    size_t pub_key_len2     = sizeof(pub_key2);
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    uint8_t sharedSecret1[32];
    size_t sharedSecret1_len = sizeof(sharedSecret1);
    uint8_t sharedSecret2[32];
    size_t sharedSecret2_len = sizeof(sharedSecret2);

    if (se05x_object_exists(pSession, keyid1)) {
        curveID = kSE05x_ECCurve_NA;
    }

    /*creates EC key pair and get pubic key*/
    status =
        Se05x_API_WriteECKey(pSession, NULL, 0, keyid1, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ReadObject(pSession, keyid1, 0, 0, pub_key, &pub_key_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    curveID = kSE05x_ECCurve_NIST_P256;
    if (se05x_object_exists(pSession, keyid2)) {
        curveID = kSE05x_ECCurve_NA;
    }

    /*creates second EC key and get public key*/
    status =
        Se05x_API_WriteECKey(pSession, NULL, 0, keyid2, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = Se05x_API_ReadObject(pSession, keyid2, 0, 0, pub_key2, &pub_key_len2);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /*Calculate ecdh key using key pair at location key id and pub_key2*/
    status =
        Se05x_API_ECDHGenerateSharedSecret(pSession, keyid1, pub_key2, pub_key_len2, sharedSecret1, &sharedSecret1_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /*Calculate ecdh key using key pair2 at location key id and pub_key*/
    status =
        Se05x_API_ECDHGenerateSharedSecret(pSession, keyid2, pub_key, pub_key_len, sharedSecret2, &sharedSecret2_len);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = SM_NOT_OK;
    if (memcmp(sharedSecret1, sharedSecret2, sharedSecret1_len) != 0) {
        SMLOG_E("Both shared secret keys are not equal \n");
        goto exit;
    }

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(pSession, keyid1);
    Se05x_API_DeleteSecureObject(pSession, keyid2);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", __FUNCTION__);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", __FUNCTION__);
        return SE05X_TEST_FAIL;
    }
}

/* ********************** Functions ********************** */

void test_se05x_nist256_ecdh(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    UPDATE_RESULT(test_nist256_ecdh_generate(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_nist256_ecdh_gen_twokeypairs(session_ctx), pass, fail, ignore);
    return;
}
