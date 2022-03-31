/** @file se05x_scp03_crypto_tc.c
 *  @brief Host crypto imlementation using tiny crypt.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Warning :
 * The scp03 host crypto implementation using tinycrypt is non re-entrant
 */

/* ********************** Include files ********************** */
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sm_port.h"
#include "se05x_types.h"
#include <tinycrypt/ctr_prng.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cmac_mode.h>
#include <tinycrypt/cbc_mode.h>

/* ********************** Global variables ********************** */
static struct tc_aes_key_sched_struct cmac_key_sched;
static struct tc_cmac_struct g_cmac_ctx = {
    0,
};

/* ********************** Functions ********************** */

int hcrypto_get_random(uint8_t *buffer, size_t bufferLen)
{
    TCCtrPrng_t rng_ctx = {0};
    int ret             = 0;

    ENSURE_OR_RETURN_ON_ERROR((buffer != NULL), 1);

    ret = tc_ctr_prng_generate(&rng_ctx, NULL, 0, buffer, bufferLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);
    return 0;
}

int hcrypto_cmac_oneshot(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    struct tc_cmac_struct cmac_ctx;
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    ENSURE_OR_RETURN_ON_ERROR((keylen == 16), 1);
    ENSURE_OR_RETURN_ON_ERROR((*outSignatureLen == 16), 1);

    ret = tc_cmac_setup(&cmac_ctx, key, &cmac_key_sched);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    ret = tc_cmac_init(&cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    ret = tc_cmac_update(&cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    ret = tc_cmac_final(outSignature, &cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    return 0;
}

void *hcrypto_cmac_setup(uint8_t *key, size_t keylen)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), NULL);
    ENSURE_OR_RETURN_ON_ERROR((keylen == 16), NULL);

    ret = tc_cmac_setup(&g_cmac_ctx, key, &cmac_key_sched);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), NULL);

    return (void *)&g_cmac_ctx;
}

int hcrypto_cmac_init(void *cmac_ctx)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((cmac_ctx != NULL), 1);

    ret = tc_cmac_init((struct tc_cmac_struct *)cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    return 0;
}

int hcrypto_cmac_update(void *cmac_ctx, uint8_t *inData, size_t inDataLen)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((cmac_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);

    ret = tc_cmac_update((struct tc_cmac_struct *)cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    return 0;
}

int hcrypto_cmac_final(void *cmac_ctx, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((cmac_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    ENSURE_OR_RETURN_ON_ERROR((*outSignatureLen == 16), 1);

    ret = tc_cmac_final(outSignature, (struct tc_cmac_struct *)cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    return 0;
}

int hcrypto_aes_cbc_encrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    struct tc_aes_key_sched_struct aes_cbc_sched;
    int ret                             = 1;
    int i                               = 0;
    uint8_t temp[2 * TC_AES_BLOCK_SIZE] = {
        0,
    };

    ENSURE_OR_GO_EXIT(key != NULL);
    ENSURE_OR_GO_EXIT(iv != NULL);
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(destData != NULL);

    ENSURE_OR_GO_EXIT(keylen == TC_AES_BLOCK_SIZE);
    ENSURE_OR_GO_EXIT(ivLen == TC_AES_BLOCK_SIZE);

    ret = tc_aes128_set_encrypt_key(&aes_cbc_sched, key);
    ENSURE_OR_GO_EXIT(ret == TC_CRYPTO_SUCCESS);

    while (i < dataLen) {
        ret = tc_cbc_mode_encrypt(temp, sizeof(temp), srcData + i, TC_AES_BLOCK_SIZE, iv, &aes_cbc_sched);
        ENSURE_OR_GO_EXIT(ret == TC_CRYPTO_SUCCESS);

        ENSURE_OR_GO_EXIT((i + TC_AES_BLOCK_SIZE) <= dataLen);
        memcpy(destData + i, temp + TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);

        memcpy(iv, temp + TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);

        i = i + TC_AES_BLOCK_SIZE;
    }

    ret = 0;
exit:
    return ret;
}

int hcrypto_aes_cbc_decrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    int i = 0;
    struct tc_aes_key_sched_struct aes_cbc_sched;
    int ret                            = 1;
    uint8_t temp_iv[TC_AES_BLOCK_SIZE] = {
        0,
    };

    ENSURE_OR_GO_EXIT(key != NULL);
    ENSURE_OR_GO_EXIT(iv != NULL);
    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(destData != NULL);

    ENSURE_OR_GO_EXIT(keylen == TC_AES_BLOCK_SIZE);
    ENSURE_OR_GO_EXIT(ivLen == TC_AES_BLOCK_SIZE);

    ret = tc_aes128_set_decrypt_key(&aes_cbc_sched, key);
    ENSURE_OR_GO_EXIT((ret == TC_CRYPTO_SUCCESS));

    while (i < dataLen) {
        memcpy(temp_iv, srcData + i, TC_AES_BLOCK_SIZE);
        ret = tc_cbc_mode_decrypt(destData + i, TC_AES_BLOCK_SIZE, srcData + i, TC_AES_BLOCK_SIZE, iv, &aes_cbc_sched);
        ENSURE_OR_GO_EXIT(ret == TC_CRYPTO_SUCCESS);
        memcpy(iv, temp_iv, TC_AES_BLOCK_SIZE);
        i = i + TC_AES_BLOCK_SIZE;
    }

    ret = 0;
exit:
    return ret;
}
