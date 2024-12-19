/** @file test_se05x_bin_objects.c
 *  @brief Binary Objects Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x.h"
#include "test_se05x_utils.h"

/* ********************** Defines ********************** */
#define TEST_SE05X_BIN_OBJ_ID_BASE (0x7B000200)
#define TEST_SE05X_SET_CERT_BLK_SIZE (128)

/* ********************** Functions ********************** */

uint8_t test_se05x_set_get_cert(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint8_t certificate[512] = {
        0,
    };
    size_t certificate_len       = sizeof(certificate);
    uint8_t get_certificate[512] = {
        0,
    };
    size_t get_certificate_len = sizeof(get_certificate);
    uint32_t keyID             = TEST_SE05X_BIN_OBJ_ID_BASE + __LINE__;
    size_t file_size           = sizeof(certificate);
    size_t offset              = 0;
    size_t blk_size            = TEST_SE05X_SET_CERT_BLK_SIZE;
    size_t i                   = 0;

    if (se05x_object_exists(session_ctx, keyID)) {
        /* Binary file already exsists. So set file size = 0 */
        file_size = 0;
    }

    for (i = 0; i < certificate_len; i++) {
        certificate[i] = i;
    }

    /* Set certificate */
    for (offset = 0; offset < certificate_len; offset = offset + blk_size) {
        status = Se05x_API_WriteBinary(session_ctx, NULL, keyID, offset, file_size, certificate + offset, blk_size);
        TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
        file_size = 0;
    }

    /* Read certificate */
    for (offset = 0; offset < certificate_len; offset = offset + blk_size) {
        status =
            Se05x_API_ReadObject(session_ctx, keyID, offset, blk_size, get_certificate + offset, &get_certificate_len);
        TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
        get_certificate_len = sizeof(get_certificate) - (offset + blk_size);
    }

    status = SM_NOT_OK;
    TEST_ENSURE_OR_GOTO_EXIT((memcmp(certificate, get_certificate, certificate_len) == 0));

    status = Se05x_API_DeleteSecureObject(session_ctx, keyID);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(session_ctx, keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", __FUNCTION__);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", __FUNCTION__);
        return SE05X_TEST_FAIL;
    }
}

uint8_t test_se05x_set_cert_invalid_len(pSe05xSession_t session_ctx)
{
    smStatus_t status        = SM_NOT_OK;
    smStatus_t test_status   = SM_NOT_OK;
    uint8_t certificate[150] = {
        0,
    };
    size_t certificate_len = sizeof(certificate);
    uint32_t keyID         = TEST_SE05X_BIN_OBJ_ID_BASE + __LINE__;
    size_t file_size       = sizeof(certificate);
    size_t offset          = 0;
    size_t blk_size        = 2 * TEST_SE05X_SET_CERT_BLK_SIZE;
    size_t i               = 0;

    if (se05x_object_exists(session_ctx, keyID)) {
        /* Binary file already exsists. So set file size = 0 */
        file_size = 0;
    }

    for (i = 0; i < certificate_len; i++) {
        certificate[i] = i;
    }

    /* Set certificate */
    status = Se05x_API_WriteBinary(session_ctx, NULL, keyID, offset, file_size, certificate + offset, blk_size);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_ERR_WRONG_DATA);

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

void test_se05x_bin_objects(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    UPDATE_RESULT(test_se05x_set_get_cert(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_se05x_set_cert_invalid_len(session_ctx), pass, fail, ignore);
    return;
}
