/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_qi_auth.h"

void getDigestSHA256(uint8_t *pInput, size_t inputLen, uint8_t *pOutput)
{
    pSe05xSession_t session_ctx = pgSe05xSessionctx;
    size_t outputLen            = DIGEST_SIZE_BYTES;
    getSha256Hash(session_ctx, pInput, inputLen, pOutput, &outputLen);
}

void getPublicKeyFromSlot(uint8_t slot_id, uint8_t *pPublicKey, size_t *pPublicKeyLen)
{
    pSe05xSession_t session_ctx = pgSe05xSessionctx;
    uint32_t keyId              = QI_SLOT_ID_TO_KEY_ID(slot_id);
    readObjectWithChunking(session_ctx, keyId, 0, 0, pPublicKey, pPublicKeyLen);
}
