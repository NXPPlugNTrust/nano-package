/** @file se05x_scp03_crypto.h
 *  @brief Host crypto APIs.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_SCP03_CRYPTO_H_INC
#define SE05X_SCP03_CRYPTO_H_INC

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"

/* ********************** Function Pototypes ********************** */

int hcrypto_get_random(uint8_t *buffer, size_t bufferLen);

/**** cmac operations ****/
int hcrypto_cmac_oneshot(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen);
void *hcrypto_cmac_setup(uint8_t *key, size_t keylen);
int hcrypto_cmac_init(void *cmac_ctx);
int hcrypto_cmac_update(void *cmac_ctx, uint8_t *inData, size_t inDataLen);
int hcrypto_cmac_final(void *cmac_ctx, uint8_t *outSignature, size_t *outSignatureLen);

/**** aes cbc operations ****/
int hcrypto_aes_cbc_encrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);
int hcrypto_aes_cbc_decrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

/**** ecc key operations ****/
void *hcrypto_gen_eckey(uint16_t keylen);
void hcrypto_free_eckey(void *eckey);
void *hcrypto_set_eckey(uint8_t *pubBuf, size_t Len, int isPrivate);
int hcrypto_get_publickey(void *privkey, uint8_t *data, size_t *dataLen);
int hcrypto_sign_digest(void *key, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);
int hcrypto_derive_dh(pSe05xSession_t session_ctx,
    void *HostKeyPair,
    void *pubkey,
    size_t pubkeyLen,
    uint8_t *shSecret,
    size_t *shSecretLen);

/**** message digest (sha256) ****/
int hcrypto_digest_one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

#endif //#ifndef SE05X_SCP03_CRYPTO_H_INC
