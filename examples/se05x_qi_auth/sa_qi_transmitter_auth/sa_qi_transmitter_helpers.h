/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_TX_HELPERS_H__
#define __SA_QI_TX_HELPERS_H__

#include <se05x_tlv.h>

smStatus_t getSha256Hash(
    pSe05xSession_t session_ctx, const uint8_t *pInput, size_t inputLen, uint8_t *pOutput, size_t *pOutputLen);
smStatus_t EcSignatureToRandS(uint8_t *signature, size_t *sigLen);
smStatus_t getPopulatedSlots(pSe05xSession_t session_ctx, uint8_t *pSlotsPopulated);
smStatus_t readObjectWithChunking(pSe05xSession_t session_ctx,
    uint32_t certChainId,
    uint16_t offset,
    uint16_t bytesToRead,
    uint8_t *pData,
    size_t *pdataLen);
smStatus_t getManufacturerCertificateLength(pSe05xSession_t session_ctx, uint32_t certChainId, uint16_t *N_MC);

#define readCertificateChain readObjectWithChunking

#endif // __SA_QI_TX_HELPERS_H__
