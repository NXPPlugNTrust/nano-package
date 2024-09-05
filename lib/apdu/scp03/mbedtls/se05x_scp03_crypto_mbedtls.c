/** @file se05x_scp03_crypto_mbdetls.c
 *  @brief Host crypto imlementation using mbedtls.
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/cmac.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"

/* ********************** Functions ********************** */

int hcrypto_get_random(uint8_t *buffer, size_t bufferLen)
{
    int ret = 1;
    mbedtls_ctr_drbg_context mbedtls_ctx;
    size_t chunk  = 0;
    size_t offset = 0;

    ENSURE_OR_RETURN_ON_ERROR((ret == 1), 1);

    while (bufferLen > 0) {
        if (bufferLen > MBEDTLS_CTR_DRBG_MAX_REQUEST) {
            chunk = MBEDTLS_CTR_DRBG_MAX_REQUEST;
        }
        else {
            chunk = bufferLen;
        }

        ret = mbedtls_ctr_drbg_random(&mbedtls_ctx, (buffer + offset), chunk);
        ENSURE_OR_RETURN_ON_ERROR((ret == 0), 1);
        ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - offset) >= chunk), 1);

        offset += chunk;
        bufferLen -= chunk;
    }

    return 0;
}

int hcrypto_cmac_oneshot(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret = 1;
    mbedtls_cipher_context_t *cmac_cipher_ctx;
    const mbedtls_cipher_info_t *cipher_info;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    cmac_cipher_ctx = mbedtls_calloc(1, sizeof(mbedtls_cipher_context_t));
    if (cmac_cipher_ctx == NULL) {
        return 1;
    }

    mbedtls_cipher_type_t cipher_type = MBEDTLS_CIPHER_NONE;
    switch (keylen * 8) {
    case 128:
        cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
        break;
    default:
        goto exit;
    }

    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info != NULL) {
        mbedtls_cipher_init(cmac_cipher_ctx);
        ret = mbedtls_cipher_setup(cmac_cipher_ctx, cipher_info);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_cipher_cmac_starts(cmac_cipher_ctx, key, (keylen * 8));
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_cipher_cmac_update(cmac_cipher_ctx, inData, inDataLen);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_cipher_cmac_finish(cmac_cipher_ctx, outSignature);
        if (ret == 0) {
            *outSignatureLen = cmac_cipher_ctx->cipher_info->block_size;
        }
    }

exit:
    mbedtls_cipher_free(cmac_cipher_ctx);
    return ret;
}

void *hcrypto_cmac_setup(uint8_t *key, size_t keylen)
{
    int ret = 1;

    mbedtls_cipher_context_t *cmac_cipher_ctx;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    mbedtls_cipher_type_t cipher_type        = MBEDTLS_CIPHER_NONE;

    switch (keylen * 8) {
    case 128:
        cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
        break;
    default:
        return NULL;
    }

    if (cipher_type != MBEDTLS_CIPHER_NONE) {
        cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    }

    if (cipher_info != NULL) {
        cmac_cipher_ctx = mbedtls_calloc(1, sizeof(mbedtls_cipher_context_t));
        if (cmac_cipher_ctx == NULL) {
            return NULL;
        }

        mbedtls_cipher_init(cmac_cipher_ctx);

        ret = mbedtls_cipher_setup(cmac_cipher_ctx, cipher_info);
        if (ret != 0) {
            mbedtls_cipher_free((mbedtls_cipher_context_t *)cmac_cipher_ctx);
            return NULL;
        }

        ret = mbedtls_cipher_cmac_starts(cmac_cipher_ctx, key, keylen * 8);
        if (ret != 0) {
            mbedtls_cipher_free(cmac_cipher_ctx);
            return NULL;
        }
    }

    return (void *)cmac_cipher_ctx;
}

int hcrypto_cmac_init(void *cmac_cipher_ctx)
{
    return 0;
}

int hcrypto_cmac_update(void *cmac_cipher_ctx, uint8_t *inData, size_t inDataLen)
{
    int ret = 1;

    ENSURE_OR_RETURN_ON_ERROR((cmac_cipher_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((inData != NULL), 1);

    ret = mbedtls_cipher_cmac_update((mbedtls_cipher_context_t *)cmac_cipher_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR((ret == 0), 1);

    return 0;
}

int hcrypto_cmac_final(void *cmac_cipher_ctx, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret = 0;

    ENSURE_OR_RETURN_ON_ERROR((cmac_cipher_ctx != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((outSignatureLen != NULL), 1);

    mbedtls_cipher_context_t *cmac_ctx = (mbedtls_cipher_context_t *)cmac_cipher_ctx;

    ret = mbedtls_cipher_cmac_finish(cmac_ctx, outSignature);

    *outSignatureLen = cmac_ctx->cipher_info->block_size;

    mbedtls_cipher_free(cmac_ctx);

    ENSURE_OR_RETURN_ON_ERROR((ret == 0), 1);

    return 0;
}

int hcrypto_aes_cbc_encrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    int ret = 0;
    mbedtls_aes_context aes_ctx;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((iv != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((srcData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((destData != NULL), 1);

    mbedtls_aes_init(&aes_ctx);

    ret = mbedtls_aes_setkey_enc(&aes_ctx, key, (unsigned int)(keylen * 8));
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, dataLen, iv, srcData, destData);
    ENSURE_OR_GO_EXIT(ret == 0);

exit:
    mbedtls_aes_free(&aes_ctx);
    return ret;
}

int hcrypto_aes_cbc_decrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    int ret = 0;
    mbedtls_aes_context aes_ctx;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((iv != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((srcData != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((destData != NULL), 1);

    mbedtls_aes_init(&aes_ctx);

    mbedtls_aes_setkey_dec(&aes_ctx, key, (unsigned int)(keylen * 8));
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, dataLen, iv, srcData, destData);
    ENSURE_OR_GO_EXIT(ret == 0);

exit:
    mbedtls_aes_free(&aes_ctx);
    return ret;
}

void *hcrypto_gen_eckey(uint16_t keylen)
{
    int ret                            = 1;
    const char pers[]                  = "gen_key";
    mbedtls_pk_context *pKey           = NULL;
    mbedtls_entropy_context *entropy   = NULL;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    int curve_id                       = 0;

    pKey = mbedtls_calloc(1, sizeof(mbedtls_pk_context));
    ENSURE_OR_GO_EXIT(pKey != NULL);

    entropy = mbedtls_calloc(1, sizeof(mbedtls_entropy_context));
    ENSURE_OR_GO_EXIT(entropy != NULL);

    ctr_drbg = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context));
    ENSURE_OR_GO_EXIT(ctr_drbg != NULL);

    mbedtls_pk_init(pKey);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    ret = mbedtls_pk_setup(pKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)pers, sizeof(pers) - 1);
    ENSURE_OR_GO_EXIT(ret == 0);

    curve_id = (keylen == 32) ? MBEDTLS_ECP_DP_SECP256R1 :
               (keylen == 48) ? MBEDTLS_ECP_DP_SECP384R1 :
                                0; // Handle unsupported key length

    if (curve_id == 0) {
        SMLOG_E("Key length not supported.");
        ret = 1;
        goto exit;
    }

    ret = mbedtls_ecp_gen_key(curve_id, mbedtls_pk_ec(*pKey), mbedtls_ctr_drbg_random, ctr_drbg);
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = 0;
exit:
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
        mbedtls_free(entropy);
    }
    if (ctr_drbg != NULL) {
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_free(ctr_drbg);
    }
    return (void *)pKey;
}

void hcrypto_free_eckey(void *eckey)
{
    mbedtls_pk_context *pkey = (mbedtls_pk_context *)eckey;
    if (pkey != NULL) {
        mbedtls_pk_free(pkey);
    }
}

void *hcrypto_set_eckey(uint8_t *Buf, size_t Len, int isPrivate)
{
    int ret                              = 1;
    mbedtls_pk_context *pK               = NULL;

    ENSURE_OR_RETURN_ON_ERROR(Buf != NULL, NULL);

    pK = mbedtls_calloc(1, sizeof(mbedtls_pk_context));
    ENSURE_OR_GO_EXIT(pK != NULL);

    if (isPrivate) {
        ret = mbedtls_pk_parse_key(pK, Buf, Len, NULL, 0);
        ENSURE_OR_GO_EXIT(ret == 0);
    }
    else {
        ret = mbedtls_pk_parse_public_key(pK, Buf, Len);
        ENSURE_OR_GO_EXIT(ret == 0);
    }

    ret = 0;
exit:
    return (void *)pK;
}

int hcrypto_get_publickey(void *privkey, uint8_t *data, size_t *dataLen)
{
    int ret                  = 1;
    uint8_t output[100]      = {0};
    unsigned char *c         = output;
    mbedtls_pk_context *pkey = NULL;

    ENSURE_OR_RETURN_ON_ERROR(privkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(data != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(dataLen != NULL, 1);

    pkey = (mbedtls_pk_context *)privkey;

    ret = mbedtls_pk_write_pubkey_der(pkey, output, sizeof(output));
    if (ret > 0) {
        *dataLen = ret;
        /* Data is put at end, so copy it to front of output buffer */
        c = output + sizeof(output) - ret;
        memcpy(data, c, ret);
        ret = 0;
    }

    return ret;
}

int hcrypto_sign_digest(void *key, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    int ret                            = 1;
    const char pers[]                  = "sign_digest";
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    mbedtls_entropy_context *entropy   = NULL;
    mbedtls_pk_context *pKey           = NULL;

    ENSURE_OR_RETURN_ON_ERROR((key != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signature != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((signatureLen != NULL), 1);

    pKey = (mbedtls_pk_context *)key;
    ENSURE_OR_GO_EXIT(pKey != NULL);

    entropy = mbedtls_calloc(1, sizeof(mbedtls_entropy_context));
    ENSURE_OR_GO_EXIT(entropy != NULL);

    ctr_drbg = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context));
    ENSURE_OR_GO_EXIT(ctr_drbg != NULL);

    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)pers, strlen(pers));
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = mbedtls_pk_sign(
        pKey, MBEDTLS_MD_SHA256, digest, digestLen, signature, signatureLen, mbedtls_ctr_drbg_random, ctr_drbg);
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = 0; /* succcess */
exit:
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
        mbedtls_free(entropy);
    }
    if (ctr_drbg != NULL) {
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_free(ctr_drbg);
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
    int ret                                    = 1;
    size_t keyLen                              = 0;
    const char pers[]                          = "Derive_dh";
    const mbedtls_ecp_curve_info *p_curve_info = NULL;
    /*Key pair*/
    mbedtls_pk_context *pKeyPrv  = NULL;
    mbedtls_ecp_keypair *pEcpPrv = NULL;
    /*External peer-key*/
    mbedtls_pk_context *pKeyExt        = NULL;
    mbedtls_ecp_keypair *pEcpExt       = NULL;
    mbedtls_entropy_context *entropy   = NULL;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    mbedtls_mpi rawSharedData;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(HostKeyPair != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pubkey != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecret != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(shSecretLen != NULL, 1);

    entropy = mbedtls_calloc(1, sizeof(mbedtls_entropy_context));
    ENSURE_OR_GO_EXIT(entropy != NULL);

    ctr_drbg = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context));
    ENSURE_OR_GO_EXIT(ctr_drbg != NULL);

    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)pers, sizeof(pers) - 1);
    ENSURE_OR_GO_EXIT(ret == 0);

    /*Set Public key*/
    void *sePubkey = hcrypto_set_eckey(pubkey, pubkeyLen, 0);
    ENSURE_OR_GO_EXIT(sePubkey != NULL);

    pKeyExt = (mbedtls_pk_context *)sePubkey;
    pEcpExt = mbedtls_pk_ec(*pKeyExt);
    ENSURE_OR_GO_EXIT(pEcpExt);

    pKeyPrv = (mbedtls_pk_context *)HostKeyPair;
    pEcpPrv = mbedtls_pk_ec(*pKeyPrv);
    ENSURE_OR_GO_EXIT(pEcpPrv);

    mbedtls_mpi_init(&rawSharedData);

    p_curve_info = mbedtls_ecp_curve_info_from_grp_id(pEcpPrv->grp.id);
    ENSURE_OR_GO_EXIT(p_curve_info != NULL);

    keyLen = (size_t)(((p_curve_info->bit_size + 7)) / 8);

    *shSecretLen = keyLen;

    ret = mbedtls_ecdh_compute_shared(
        &pEcpPrv->grp, &rawSharedData, &(pEcpExt->Q), &(pEcpPrv->d), mbedtls_ctr_drbg_random, ctr_drbg);
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = mbedtls_mpi_write_binary(&rawSharedData, shSecret, *shSecretLen);
    ENSURE_OR_GO_EXIT(ret == 0);

    ret = 0;

exit:
    if (pEcpExt != NULL) {
        mbedtls_ecp_keypair_free(pEcpExt);
    }
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
        mbedtls_free(entropy);
    }
    if (ctr_drbg != NULL) {
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_free(ctr_drbg);
    }
    return ret;
}

int hcrypto_digest_one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    int ret                         = 1;
    const mbedtls_md_info_t *mdinfo = NULL;

    ENSURE_OR_RETURN_ON_ERROR((message != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digest != NULL), 1);
    ENSURE_OR_RETURN_ON_ERROR((digestLen != NULL), 1);

    mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    ret = mbedtls_md(mdinfo, message, messageLen, digest);
    ENSURE_OR_RETURN_ON_ERROR((ret == 0), 1);

    *digestLen = 32;
    return 0;
}
