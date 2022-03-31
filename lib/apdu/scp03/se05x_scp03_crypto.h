/** @file se05x_scp03_crypto.h
 *  @brief Host crypto APIs.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_SCP03_CRYPTO_H_INC
#define SE05X_SCP03_CRYPTO_H_INC

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"

/* ********************** Function Pototypes ********************** */
int hcrypto_get_random(uint8_t *buffer, size_t bufferLen);
int hcrypto_cmac_oneshot(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen);
void *hcrypto_cmac_setup(uint8_t *key, size_t keylen);
int hcrypto_cmac_init(void *cmac_ctx);
int hcrypto_cmac_update(void *cmac_ctx, uint8_t *inData, size_t inDataLen);
int hcrypto_cmac_final(void *cmac_ctx, uint8_t *outSignature, size_t *outSignatureLen);
int hcrypto_aes_cbc_encrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);
int hcrypto_aes_cbc_decrypt(
    uint8_t *key, size_t keylen, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

#endif //#ifndef SE05X_SCP03_CRYPTO_H_INC
