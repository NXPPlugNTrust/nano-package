/** @file se05x_scp03_crypto_openssl.c
 *  @brief Host crypto imlementation using openssl.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sm_port.h"
#include "se05x_types.h"
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>

/* ********************** Functions ********************** */

int hcrypto_get_random(uint8_t *buffer, size_t bufferLen)
{
    ENSURE_OR_RETURN_ON_ERROR((buffer != NULL), 1);

    if (0 == RAND_bytes((unsigned char *)buffer, bufferLen)) {
        return 1;
    }
    return 0;
}

int hcrypto_cmac_oneshot(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret                       = 0;
    CMAC_CTX *cmac_ctx            = CMAC_CTX_new();
    const EVP_CIPHER *cipher_info = NULL;
    cipher_info                   = EVP_aes_128_cbc();

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    ret = CMAC_Init(cmac_ctx, key, keylen, cipher_info, NULL);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = CMAC_Update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == 1), 1);

    ret = CMAC_Final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == 1), 1);

    ret = 0;
exit:
    CMAC_CTX_free((CMAC_CTX *)cmac_ctx);
    return ret;
}

void *hcrypto_cmac_setup(uint8_t *key, size_t keylen)
{
    int ret;
    CMAC_CTX *cmac_ctx            = CMAC_CTX_new();
    const EVP_CIPHER *cipher_info = NULL;

    if (key == NULL) {
        return NULL;
    }

    cipher_info = EVP_aes_128_cbc();

    ret = CMAC_Init(cmac_ctx, key, keylen, cipher_info, NULL);
    if (ret != 1) {
        CMAC_CTX_free((CMAC_CTX *)cmac_ctx);
        return NULL;
    }
    return (void *)cmac_ctx;
}

int hcrypto_cmac_init(void *cmac_ctx)
{
    (void)cmac_ctx;
    return 0;
}

int hcrypto_cmac_update(void *cmac_ctx, uint8_t *inData, size_t inDataLen)
{
    int ret = 1;

    ENSURE_OR_RETURN_ON_ERROR((cmac_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);

    ret = CMAC_Update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == 1), 1);

    return 0;
}

int hcrypto_cmac_final(void *cmac_ctx, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((cmac_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    ret = CMAC_Final(cmac_ctx, outSignature, outSignatureLen);
    CMAC_CTX_free((CMAC_CTX *)cmac_ctx);

    ENSURE_OR_RETURN_ON_ERROR((ret == 1), 1);

    return 0;
}

int hcrypto_aes_cbc_encrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    AES_KEY AESKey;
    (void)ivLen;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((iv != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((srcData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((destData != NULL), 1);

    if (AES_set_encrypt_key((uint8_t *)key, keylen * 8, &AESKey) < 0) {
        return 1;
    }
    AES_cbc_encrypt(srcData, destData, dataLen, &AESKey, iv, AES_ENCRYPT);
    return 0;
}

int hcrypto_aes_cbc_decrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    AES_KEY AESKey;
    (void)ivLen;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((iv != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((srcData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((destData != NULL), 1);

    if (AES_set_decrypt_key((uint8_t *)key, keylen * 8, &AESKey) < 0) {
        return 1;
    }
    AES_cbc_encrypt(srcData, destData, dataLen, &AESKey, iv, AES_DECRYPT);
    return 0;
}