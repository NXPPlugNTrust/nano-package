/** @file se05x_scp03_crypto_tc.c
 *  @brief Host crypto imlementation using tiny crypt.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Warning :
 * The scp03 host crypto implementation using tinycrypt is non re-entrant
 */

#if defined(WITH_ECKEY_SESSION) || defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)

/* ********************** Include files ********************** */
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sm_port.h"
#include "se05x_types.h"
#include <tinycrypt/ctr_prng.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cmac_mode.h>
#include <tinycrypt/cbc_mode.h>

/* ********************** Global variables ********************** */
static struct tc_aes_key_sched_struct cmac_key_sched;
static struct tc_cmac_struct g_cmac_ctx = {
    0,
};

/*
Note: The implemntation is used only for ec key auth.
It is assumed that the ecc key gen and ecc key set operations
are called only once.
ecc_key[0] is used for ephermeral key and
ecc_key[1] is used to set public key,
*/
typedef struct
{
    uint8_t privkey[NUM_ECC_BYTES];
    uint8_t pubkey[2 * NUM_ECC_BYTES];
} tc_nist256_key_t;

tc_nist256_key_t ecc_key[2] = {0};

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

void *hcrypto_gen_eckey()
{
    int ret = 0;

    ret = uECC_make_key(ecc_key[0].pubkey, ecc_key[0].privkey, uECC_secp256r1());
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), NULL);

    return (void *)&ecc_key[0];
}

void hcrypto_free_eckey(void *eckey)
{
    tc_nist256_key_t *pkey = (tc_nist256_key_t *)eckey;
    memset(pkey, 0, sizeof(tc_nist256_key_t));
    return;
}

void *hcrypto_set_eckey(uint8_t *Buf, size_t Len, int isPrivate)
{
    ENSURE_OR_RETURN_ON_ERROR(Buf != NULL, NULL);

    if (isPrivate) {
        memcpy(ecc_key[1].privkey, &Buf[36], 32);
        return (void *)&ecc_key[1];
    }
    else {
        //TBU
        return NULL;
    }
}

int hcrypto_get_publickey(void *privkey, uint8_t *data, size_t *dataLen)
{
    int ret                       = 0;
    tc_nist256_key_t *private_key = (tc_nist256_key_t *)privkey;
    size_t offset                 = 0;
    uint8_t publicKey[100];
    const uint8_t nist256_header[] = {0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00};

    ENSURE_OR_RETURN_ON_ERROR(privkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(data != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(dataLen != NULL, 1);

    ret = uECC_compute_public_key(private_key->privkey, publicKey, uECC_secp256r1());
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    // Copy DER header to the data buffer
    memcpy(data + offset, nist256_header, sizeof(nist256_header));
    offset += sizeof(nist256_header);

    // Append 0x04 byte to indicate uncompressed key format
    data[offset++] = 0x04;

    // Copy the public key from the buffer to the data buffer
    memcpy(data + offset, publicKey, 64);
    offset += 64;
    *dataLen = offset;

    return 0;
}

int hcrypto_sign_digest(void *key, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    int ret       = 0;
    size_t offset = 0;
    uint8_t rawSig[64];
    size_t rawSigLen       = sizeof(rawSig);
    tc_nist256_key_t *pkey = (tc_nist256_key_t *)key;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signatureLen != NULL), 1);

    ret = uECC_sign(pkey->privkey, digest, digestLen, rawSig, uECC_secp256r1());
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    signature[0] = 0x30;
    signature[1] = (uint8_t)(rawSigLen + 2 /* Tag + len */ + 2 /* Tag + len */);

    signature[2] = 0x02;
    signature[3] = (uint8_t)32;
    if ((rawSig[0] & 0x80) == 0x80) /* Check for first byte of R */
    {
        signature[1]++;
        signature[3]++;
        signature[4] = 0x00;
        memcpy(&signature[5], &rawSig[0], 32);
        offset = 5 + 32;
    }
    else {
        memcpy(&signature[4], &rawSig[0], 32);
        offset = 4 + 32;
    }
    *signatureLen = offset;

    /* Update S value*/
    signature[offset + 0] = 0x02;
    signature[offset + 1] = (uint8_t)32;
    if ((rawSig[32] & 0x80) == 0x80) /* Check for first byte of S */
    {
        signature[1]++;
        signature[offset + 1]++;
        signature[offset + 2] = 0x00;
        memcpy(&signature[offset + 3], &rawSig[32], 32);
        *signatureLen += 3 + 32;
    }
    else {
        memcpy(&signature[offset + 2], &rawSig[32], 32);
        *signatureLen += 2 + 32;
    }

    return 0;
}

int hcrypto_derive_dh(pSe05xSession_t session_ctx,
    void *HostKeyPair,
    void *pubkey,
    size_t pubkeyLen,
    uint8_t *shSecret,
    size_t *shSecretLen)
{
    int ret = 0;
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(HostKeyPair != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pubkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecret != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecretLen != NULL, 1);

    ret = uECC_shared_secret(
        (uint8_t *)pubkey + 27, ((tc_nist256_key_t *)HostKeyPair)->privkey, shSecret, uECC_secp256r1());
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    *shSecretLen = 32;

    return 0;
}

int hcrypto_digest_one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    struct tc_sha256_state_struct md_ctx;
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((message != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digestLen != NULL), 1);

    ret = tc_sha256_init(&md_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    ret = tc_sha256_update(&md_ctx, message, messageLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    ret = tc_sha256_final(digest, &md_ctx);
    ENSURE_OR_RETURN_ON_ERROR((ret == TC_CRYPTO_SUCCESS), 1);

    *digestLen = TC_SHA256_DIGEST_SIZE;

    return 0;
}

int default_CSPRNG(uint8_t *dest, unsigned int size)
{
    for (size_t i = 0; i < size; i++) {
        dest[i] = i;
    }
    return 1;
}

#endif //#if defined(WITH_ECKEY_SESSION) || defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION)
