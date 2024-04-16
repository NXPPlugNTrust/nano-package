/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_NANO_HELPER_APIS_H__
#define __SA_QI_NANO_HELPER_APIS_H__

#include "se05x_tlv.h"

#define kSE05x_SecObjTyp_BINARY_FILE 0x0B

/** Crypto object identifiers */
typedef enum
{
    /** Invalid */
    kSE05x_CryptoObject_NA            = 0,
    kSE05x_CryptoObject_DIGEST_SHA256 = 3,
} SE05x_CryptoObject_t;

#define SE05x_CryptoObjectID_t SE05x_CryptoObject_t

/** Cryptographic context for operation */
typedef enum
{
    /** Invalid */
    kSE05x_CryptoContext_NA = 0,
    /** For DigestInit/DigestUpdate/DigestFinal */
    kSE05x_CryptoContext_DIGEST = 0x01,
} SE05x_CryptoContext_t;

/** Hashing/Digest algorithms */
typedef enum
{
    /** Invalid */
    kSE05x_DigestMode_NA     = 0,
    kSE05x_DigestMode_SHA256 = 0x04,
} SE05x_DigestMode_t;

/** Cyrpto module subtype */
typedef union {
    /** In case it's digest */
    SE05x_DigestMode_t digest;
    /** Accessing 8 bit value for APDUs */
    uint8_t union_8bit;
} SE05x_CryptoModeSubType_t;

typedef enum
{
    /** Invalid */
    kSE05x_MoreIndicator_NA = 0,
    /** No more data available */
    kSE05x_MoreIndicator_NO_MORE = 0x01,
    /** More data available */
    kSE05x_MoreIndicator_MORE = 0x02,
} SE05x_MoreIndicator_t;

smStatus_t Se05x_API_DigestInit(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID);
smStatus_t Se05x_API_DigestUpdate(
    pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID, const uint8_t *inputData, size_t inputDataLen);
smStatus_t Se05x_API_DigestFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmacValue,
    size_t *pcmacValueLen);
smStatus_t Se05x_API_DeleteCryptoObject(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID);
smStatus_t Se05x_API_CreateCryptoObject(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    SE05x_CryptoContext_t cryptoContext,
    SE05x_CryptoModeSubType_t subtype);
smStatus_t Se05x_API_ReadCryptoObjectList(pSe05xSession_t session_ctx, uint8_t *idlist, size_t *pidlistLen);

smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
    uint16_t outputOffset,
    uint8_t filter,
    uint8_t *pmore,
    uint8_t *idlist,
    size_t *pidlistLen);

smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize);

#endif // __SA_QI_NANO_HELPER_APIS_H__
