/** @file test_se05x_aes.c
 *  @brief AES Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "test_se05x.h"
#include "test_se05x_utils.h"

#define TEST_SE05X_AES_OBJ_ID_BASE 0x7B000100
#define MAX_DATA_LEN 112

uint8_t test_write_encrypt_decrypt_aes_key(
    Se05xSession_t *pSession, SE05x_CipherMode_t cipherMode, size_t keyLenBits, size_t data_len, const char *test_name)
{
    smStatus_t status;
    uint32_t keyID  = TEST_SE05X_AES_OBJ_ID_BASE + __LINE__ + keyLenBits;
    uint8_t key[32] = {
        0,
    };
    /* clang-format off */
    uint8_t data[256] = { 1, 1, 1, 1, 1, 1, 1, 1, };
    /* clang-format on */
    size_t key_len = keyLenBits / 8;
    uint8_t enc[256];
    size_t enc_len = data_len;
    uint8_t dec[256];
    size_t dec_len = data_len;
    /* clang-format off */
    uint8_t iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    /* clang-format on */
    size_t ivlen   = sizeof(iv);
    uint8_t *ivBuf = &iv[0];

    if (cipherMode == kSE05x_CipherMode_AES_ECB_NOPAD) {
        ivBuf = NULL;
        ivlen = 0;
    }

    for (int i = 0; i < sizeof(key); i++) {
        key[i] = i;
    }

    /*create AES KEY*/
    status = Se05x_API_WriteSymmKey(
        pSession, NULL, 0, keyID, SE05x_KeyID_KEK_NONE, key, key_len, kSE05x_INS_NA, kSE05x_SymmKeyType_AES);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /* Encrypts data*/
    status = Se05x_API_CipherOneShot(
        pSession, keyID, cipherMode, data, data_len, ivBuf, ivlen, enc, &enc_len, kSE05x_Cipher_Oper_OneShot_Encrypt);
    if (pSession->scp03_session == 0) {
        TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
    }
    else {
        if (data_len > MAX_DATA_LEN && cipherMode != kSE05x_CipherMode_AES_ECB_NOPAD) {
            TEST_ENSURE_OR_GOTO_EXIT(status == SM_NOT_OK);
        }
        else {
            TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
        }
    }

    /*decrypts data*/
    status = Se05x_API_CipherOneShot(
        pSession, keyID, cipherMode, enc, enc_len, ivBuf, ivlen, dec, &dec_len, kSE05x_Cipher_Oper_OneShot_Decrypt);
    if (pSession->scp03_session == 0) {
        TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
    }
    else {
        if (data_len > MAX_DATA_LEN && cipherMode != kSE05x_CipherMode_AES_ECB_NOPAD) {
            TEST_ENSURE_OR_GOTO_EXIT(status == SM_NOT_OK);
            status = SM_OK;
            goto exit;
        }
        else {
            TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);
        }
    }

    status = SM_NOT_OK;
    /*compares data with dec data*/
    if (memcmp(dec, data, data_len) != 0) {
        SMLOG_E("Decrypt data not same \n");
        goto exit;
    }

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(pSession, keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", test_name);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", test_name);
        return SE05X_TEST_FAIL;
    }
}

#define TEST_AES_ENCRYPT_DECRYPT(MODE, KEY_LEN_BITS, DATA_LEN)                                     \
    uint8_t test_aes_##MODE##_keylen_##KEY_LEN_BITS##_DataLen_##DATA_LEN(Se05xSession_t *pSession) \
    {                                                                                              \
        return test_write_encrypt_decrypt_aes_key(                                                 \
            pSession, kSE05x_CipherMode_AES_##MODE, KEY_LEN_BITS, DATA_LEN, __FUNCTION__);         \
    }

/* key length = 128 bits, datalen = 32 bytes, cipher mode=ECB_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(ECB_NOPAD, 128, 32)
/* key length = 128 bits, datalen = 32 bytes, cipher mode=CBC_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(CBC_NOPAD, 128, 32)
/* key length = 128 bits, datalen = 32 bytes, cipher mode=CTR */
TEST_AES_ENCRYPT_DECRYPT(CTR, 128, 32)

/* key length = 192 bits, datalen = 32 bytes, cipher mode=ECB_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(ECB_NOPAD, 192, 32)
/* key length = 192 bits, datalen = 32 bytes, cipher mode=CBC_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(CBC_NOPAD, 192, 32)
/* key length = 192 bits, datalen = 32 bytes, cipher mode=CTR */
TEST_AES_ENCRYPT_DECRYPT(CTR, 192, 32)

/* key length = 256 bits, datalen = 32 bytes, cipher mode=ECB_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(ECB_NOPAD, 256, 32)
/* key length = 256 bits, datalen = 32 bytes, cipher mode=CBC_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(CBC_NOPAD, 256, 32)
/* key length = 256 bits, datalen = 32 bytes, cipher mode=CTR */
TEST_AES_ENCRYPT_DECRYPT(CTR, 256, 32)

/* key length = 256 bits, datalen = MAX_DATA_LEN bytes, cipher mode=ECB_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(ECB_NOPAD, 256, 112)
/* key length = 256 bits, datalen = MAX_DATA_LEN bytes, cipher mode=CBC_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(CBC_NOPAD, 256, 112)
/* key length = 256 bits, datalen = MAX_DATA_LEN bytes, cipher mode=CTR */
TEST_AES_ENCRYPT_DECRYPT(CTR, 256, 112)

/* key length = 256 bits, datalen = 128 bytes, cipher mode=ECB_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(ECB_NOPAD, 256, 128)
/* key length = 256 bits, datalen = 128 bytes, cipher mode=CBC_NOPAD */
TEST_AES_ENCRYPT_DECRYPT(CBC_NOPAD, 256, 128)
/* key length = 256 bits, datalen = 128 bytes, cipher mode=CTR */
TEST_AES_ENCRYPT_DECRYPT(CTR, 256, 128)

/*invalid key*/
uint8_t test_write_aes_invalid_key(Se05xSession_t *pSession)
{
    smStatus_t status;
    uint32_t keyID = TEST_SE05X_AES_OBJ_ID_BASE + __LINE__;
    /* clang-format off */
    uint8_t key[8] = {1, 2, 3, 4, 5, 6, 7, 8, };
    /* clang-format on */
    size_t key_len = sizeof(key);
    /* Write AES key with length = 8 bytes*/
    status = Se05x_API_WriteSymmKey(
        pSession, NULL, 0, keyID, SE05x_KeyID_KEK_NONE, key, key_len, kSE05x_INS_NA, kSE05x_SymmKeyType_AES);
    Se05x_API_DeleteSecureObject(pSession, keyID);
    TEST_ENSURE_OR_RETURN_ON_ERROR(status != SM_OK, SE05X_TEST_FAIL);

    PASS_SE05X_TEST();
}

/* create AES key, encrypt and decrypt for key of size 256 bits */
uint8_t test_write_encrypt_decrypt_aes_corrupt_enc_data(
    Se05xSession_t *pSession, SE05x_CipherMode_t cipherMode, const char *test_name)
{
    smStatus_t status;
    uint32_t keyID  = TEST_SE05X_AES_OBJ_ID_BASE + __LINE__;
    uint8_t key[32] = {
        0,
    };
    /* clang-format off */
    uint8_t data[16] = {1, 1, 1, 1, 1, 1, 1, 1, };
    /* clang-format on */
    size_t key_len  = sizeof(key);
    size_t data_len = sizeof(data);
    uint8_t enc[32];
    size_t enc_len = sizeof(enc);
    uint8_t dec[32];
    size_t dec_len = sizeof(dec);
    for (int i = 0; i < sizeof(key); i++) {
        key[i] = i;
    }
    /*create AES KEY*/
    status = Se05x_API_WriteSymmKey(
        pSession, NULL, 0, keyID, SE05x_KeyID_KEK_NONE, key, key_len, kSE05x_INS_NA, kSE05x_SymmKeyType_AES);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /* Encrypts data*/
    status = Se05x_API_CipherOneShot(
        pSession, keyID, cipherMode, data, data_len, NULL, 0, enc, &enc_len, kSE05x_Cipher_Oper_OneShot_Encrypt);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /*corrupts encryption data*/
    enc[0] ^= 0xFF;

    /*decrypts data*/
    status = Se05x_API_CipherOneShot(
        pSession, keyID, cipherMode, enc, enc_len, NULL, 0, dec, &dec_len, kSE05x_Cipher_Oper_OneShot_Decrypt);
    TEST_ENSURE_OR_GOTO_EXIT(status == SM_OK);

    /*compares data with dec data*/
    status = SM_NOT_OK;
    if (memcmp(dec, data, data_len) == 0) {
        goto exit;
    }

    status = SM_OK;
exit:
    /* Erase key */
    Se05x_API_DeleteSecureObject(pSession, keyID);

    if (status == SM_OK) {
        SMLOG_I("%s, PASSED \n", test_name);
        return SE05X_TEST_PASS;
    }
    else {
        SMLOG_I("%s, FAILED \n", test_name);
        return SE05X_TEST_FAIL;
    }
}

/* ciphermode = AES_EBC_NOPAD, key_size = 256 bits */
uint8_t test_aescorrupt_ECB_NOPAD(Se05xSession_t *pSession)
{
    return test_write_encrypt_decrypt_aes_corrupt_enc_data(pSession, kSE05x_CipherMode_AES_ECB_NOPAD, __FUNCTION__);
}
/* ciphermode = AES_CBC_NOPAD, key_size = 256 bits*/
uint8_t test_aescorrupt_CBC_NOPAD(Se05xSession_t *pSession)
{
    return test_write_encrypt_decrypt_aes_corrupt_enc_data(pSession, kSE05x_CipherMode_AES_CBC_NOPAD, __FUNCTION__);
}
/* ciphermode = AES_CTR, key_size = 256 bits */
uint8_t test_aescorrupt_CTR(Se05xSession_t *pSession)
{
    return test_write_encrypt_decrypt_aes_corrupt_enc_data(pSession, kSE05x_CipherMode_AES_CTR, __FUNCTION__);
}

void test_se05x_aes(pSe05xSession_t session_ctx, uint8_t *pass, uint8_t *fail, uint8_t *ignore)
{
    /* key size = 128 bits, Data len = 32 */
    UPDATE_RESULT(test_aes_ECB_NOPAD_keylen_128_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CBC_NOPAD_keylen_128_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CTR_keylen_128_DataLen_32(session_ctx), pass, fail, ignore);

    /* key size = 192 bits, Data len = 32 */
    UPDATE_RESULT(test_aes_ECB_NOPAD_keylen_192_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CBC_NOPAD_keylen_192_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CTR_keylen_192_DataLen_32(session_ctx), pass, fail, ignore);

    /* key size = 256 bits, Data len = 32 */
    UPDATE_RESULT(test_aes_ECB_NOPAD_keylen_256_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CBC_NOPAD_keylen_256_DataLen_32(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CTR_keylen_256_DataLen_32(session_ctx), pass, fail, ignore);

    /* key size = 256 bits, Data len = MAX_DATA_LEN (112 Bytes) */
    UPDATE_RESULT(test_aes_ECB_NOPAD_keylen_256_DataLen_112(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CBC_NOPAD_keylen_256_DataLen_112(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CTR_keylen_256_DataLen_112(session_ctx), pass, fail, ignore);

    /* Negative tests */

    /* key size = 256 bits, Data len = 128  ==> Should Fail when platformSCP03 is enabled */
    UPDATE_RESULT(test_aes_ECB_NOPAD_keylen_256_DataLen_128(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CBC_NOPAD_keylen_256_DataLen_128(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aes_CTR_keylen_256_DataLen_128(session_ctx), pass, fail, ignore);

    UPDATE_RESULT(test_write_aes_invalid_key(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aescorrupt_ECB_NOPAD(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aescorrupt_CBC_NOPAD(session_ctx), pass, fail, ignore);
    UPDATE_RESULT(test_aescorrupt_CTR(session_ctx), pass, fail, ignore);
    return;
}
