/** @file se05x_scp03_crypto_openssl.c
 *  @brief Host crypto imlementation using openssl.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sm_port.h"
#include <stdlib.h>
#include "se05x_types.h"
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

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

void *hcrypto_gen_eckey()
{
    int ret             = 1;
    EC_KEY *pEcKey      = NULL;
    EC_GROUP *pEC_Group = NULL;
    EVP_PKEY *pEvpKey   = NULL;

    pEvpKey = EVP_PKEY_new();
    ENSURE_OR_GO_EXIT(pEvpKey != NULL);

    pEcKey = EC_KEY_new();
    ENSURE_OR_GO_EXIT(pEcKey != NULL);

    pEC_Group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ENSURE_OR_GO_EXIT(pEC_Group != NULL);

    EC_GROUP_set_asn1_flag(pEC_Group, 0x001);

    ENSURE_OR_GO_EXIT(EC_KEY_set_group(pEcKey, pEC_Group) == 1);

    /* Generate the EC keys. */
    ret = EC_KEY_generate_key(pEcKey);
    ENSURE_OR_GO_EXIT(ret == 1);

    ENSURE_OR_GO_EXIT(EVP_PKEY_set1_EC_KEY(pEvpKey, pEcKey) == 1);

    ret = 0; /* success */
exit:
    if (ret != 0) {
        if (pEvpKey != NULL) {
            //EC_KEY_free(pEcKey); TBU
            pEvpKey = NULL;
        }
    }
    if (pEC_Group != NULL) {
        EC_GROUP_free(pEC_Group);
    }
    if (pEcKey != NULL) {
        EC_KEY_free(pEcKey);
    }
    return (void *)pEvpKey;
}

void hcrypto_free_eckey(void *eckey)
{
    EVP_PKEY *pEvpKey = (EVP_PKEY *)eckey;
    if (pEvpKey != NULL) {
        EVP_PKEY_free(pEvpKey);
    }
}

void *hcrypto_set_eckey(uint8_t *Buf, size_t Len, int isPrivate)
{
    EVP_PKEY *pKey = NULL;

    ENSURE_OR_GO_EXIT(Buf != NULL);

    if (isPrivate == 1) {
        pKey = d2i_PrivateKey(EVP_PKEY_EC, NULL, (const unsigned char **)&Buf, Len);
    }
    else {
        pKey = d2i_PUBKEY(NULL, (const unsigned char **)&Buf, Len);
    }

exit:
    return (void *)pKey;
}

int hcrypto_get_publickey(void *privkey, uint8_t *data, size_t *dataLen)
{
    int ret = 0;
    int len;

    ENSURE_OR_RETURN_ON_ERROR(privkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(data != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(dataLen != NULL, 1);

    EVP_PKEY *pkey = (EVP_PKEY *)privkey;
    ENSURE_OR_RETURN_ON_ERROR(pkey != NULL, 1);

    len = i2d_PUBKEY(pkey, &data);
    if ((*dataLen) > INT_MAX) {
        return 1;
    }
    if (len < 0 || (int)(*dataLen) < len) {
        return 1;
    }
    *dataLen = len;
    return ret;
}

int hcrypto_sign_digest(void *key, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    int ret;
    EVP_PKEY_CTX *pKey_Ctx = NULL;
    void *hashfPtr         = NULL;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signatureLen != NULL), 1);

    EVP_PKEY *pKey = (EVP_PKEY *)key;
    ENSURE_OR_RETURN_ON_ERROR((pKey != NULL), 1);

    /* Get the context from EVP_PKEY */
    pKey_Ctx = EVP_PKEY_CTX_new(pKey, NULL);
    ENSURE_OR_RETURN_ON_ERROR((pKey_Ctx != NULL), 1);

    /* Init the Signing context. */
    ret = EVP_PKEY_sign_init(pKey_Ctx);
    ENSURE_OR_GO_EXIT((ret == 1));

    hashfPtr = (void *)EVP_sha256();
    ENSURE_OR_RETURN_ON_ERROR((hashfPtr != NULL), 1);

    ret = EVP_PKEY_CTX_set_signature_md(pKey_Ctx, hashfPtr);
    ENSURE_OR_GO_EXIT((ret == 1));

    /* Perfom Signing of the message. */
    ret = EVP_PKEY_sign(pKey_Ctx, signature, signatureLen, digest, digestLen);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = 0;
exit:
    if (pKey_Ctx != NULL) {
        EVP_PKEY_CTX_free(pKey_Ctx);
    }
    return ret;
}

int hcrypto_derive_dh(pSe05xSession_t session_ctx,
    void *HostKeyPair,
    void *pubkey,
    size_t pubkeyLen,
    uint8_t *shSecret,
    size_t *shSecretLen)
{
    int ret;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(HostKeyPair != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pubkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecret != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecretLen != NULL, 1);

    EVP_PKEY *pKeyPrv = (EVP_PKEY *)HostKeyPair;
    ENSURE_OR_RETURN_ON_ERROR(pKeyPrv != NULL, 1);

    /*Set public key*/
    void *seHostPubKey = hcrypto_set_eckey(pubkey, pubkeyLen, 0);
    ENSURE_OR_RETURN_ON_ERROR(seHostPubKey != NULL, 1);

    EVP_PKEY *pKeyExt = (EVP_PKEY *)seHostPubKey;
    ENSURE_OR_RETURN_ON_ERROR(pKeyExt != NULL, 1);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pKeyPrv, NULL);
    ENSURE_OR_RETURN_ON_ERROR(ctx != NULL, 1);

    ret = EVP_PKEY_derive_init(ctx);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = EVP_PKEY_derive_set_peer(ctx, pKeyExt);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = EVP_PKEY_derive(ctx, shSecret, shSecretLen);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = 0;

exit:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (seHostPubKey != NULL) {
        EVP_PKEY_free(seHostPubKey);
    }
    return ret;
}

int hcrypto_digest_one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    int ret          = 1;
    const EVP_MD *md = NULL;

    ENSURE_OR_RETURN_ON_ERROR((message != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digestLen != NULL), 1);

    md = EVP_get_digestbyname("sha256");
    ENSURE_OR_RETURN_ON_ERROR(md != NULL, 1);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    ENSURE_OR_RETURN_ON_ERROR(mdctx != NULL, 1);

    ret = EVP_DigestInit_ex(mdctx, md, NULL);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = EVP_DigestUpdate(mdctx, message, messageLen);
    ENSURE_OR_GO_EXIT((ret == 1));

    ret = EVP_DigestFinal_ex(mdctx, digest, (unsigned int *)digestLen);
    ENSURE_OR_GO_EXIT((ret == 1));
    /*As we are only using sha256 the digestlen should be 32*/
    ENSURE_OR_GO_EXIT(*digestLen <= 32);

    ret = 0;
exit:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}
