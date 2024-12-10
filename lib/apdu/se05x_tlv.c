/** @file se05x_tlv.c
 *  @brief TLV utils functions.
 *
 * Copyright 2021,2022, 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_tlv.h"
#include "smCom.h"
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_scp03.h"
#include <limits.h>

/* ********************** Global vaiables ********************** */

#ifdef ENABLE_SM_APDU_MUTEX
/*
    Mutex used at the se05x_tlv.c (DoAPDUTxRx/DoAPDUTx functions) layer
    Use this feature, in case multiple tasks call Se05x_API_* APIs.
    Set `PLUGANDTRUST_ENABLE_SM_APDU_MUTEX` cmake option to ON to enable this feature.
*/
SM_MUTEX_EXTERN_DEFINE(g_sm_apdu_mutex);
#endif

/* ********************** Function ********************** */

int tlvSet_U8(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint8_t value)
{
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = 1 + 1 + 1;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    if (UINTPTR_MAX - 3 < (uintptr_t)pBuf) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 1;
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U16(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    const size_t size_of_tlv = 1 + 1 + 2;
    uint8_t *pBuf            = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 2;
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U32(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t value)
{
    const size_t size_of_tlv = 1 + 1 + 4;
    uint8_t *pBuf            = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    if (UINTPTR_MAX - 6 < (uintptr_t)pBuf) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 4;
    *pBuf++ = (uint8_t)((value >> 3 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFf ? 2 : 3));
    const size_t size_of_tlv    = 1 + size_of_length + cmdLen;

    if ((UINT_MAX - size_of_tlv) < (*bufLen)) {
        return 1;
    }

    if (((*bufLen) + size_of_tlv) > MAX_APDU_BUFFER) {
        SMLOG_E("Not enough buffer \n");
        return 1;
    }

    if (UINTPTR_MAX - 1 < (uintptr_t)pBuf) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;

    if (cmdLen <= 0x7Fu) {
        if (UINTPTR_MAX - 1 < (uintptr_t)pBuf) {
            return 1;
        }
        *pBuf++ = (uint8_t)cmdLen;
    }
    else if (cmdLen <= 0xFFu) {
        if (UINTPTR_MAX - 2 < (uintptr_t)pBuf) {
            return 1;
        }
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else if (cmdLen <= 0xFFFFu) {
        if (UINTPTR_MAX - 3 < (uintptr_t)pBuf) {
            return 1;
        }
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            if (UINTPTR_MAX - 1 < (uintptr_t)pBuf) {
                return 1;
            }
            *pBuf++ = *cmd++;
        }
    }

    *bufLen += size_of_tlv;
    *buf = pBuf;

    return 0;
}

int tlvSet_u8bufOptional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    if (cmdLen == 0) {
        return 0;
    }
    else {
        return tlvSet_u8buf(buf, bufLen, tag, cmd, cmdLen);
    }
}

int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    if (value == 0) {
        return 0;
    }
    else {
        return tlvSet_U16(buf, bufLen, tag, value);
    }
}

int tlvSet_Se05xPolicy(const char *description, uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, Se05xPolicy_t *policy)
{
    int tlvRet = 0;
    (void)description;
    if ((policy != NULL) && (policy->value != NULL)) {
        tlvRet = tlvSet_u8buf(buf, bufLen, tag, policy->value, policy->value_len);
        return tlvRet;
    }
    return tlvRet;
}

int tlvSet_MaxAttemps(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t maxAttemps)
{
    int retVal = 0;
    if (maxAttemps != 0) {
        retVal = tlvSet_U16(buf, bufLen, tag, maxAttemps);
    }
    return retVal;
}

int tlvSet_ECCurve(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, SE05x_ECCurve_t value)
{
    int retVal = 0;
    if (value != kSE05x_ECCurve_NA) {
        retVal = tlvSet_U8(buf, bufLen, tag, (uint8_t)value);
    }
    return retVal;
}

int tlvSet_KeyID(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t keyID)
{
    int retVal = 0;
    if (keyID != 0) {
        retVal = tlvSet_U32(buf, bufLen, tag, keyID);
    }
    return retVal;
}

int tlvSet_header(uint8_t **buf, size_t *bufLen, tlvHeader_t *hdr)
{
    uint8_t *pBuf = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hdr != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 5) >= *bufLen), 1);

    pBuf = *buf;

    memcpy(pBuf, hdr, 4);
    *buf = pBuf + (4 + 1);
    *bufLen += (4 + 1);
    return 0;
}

int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = 0;
    size_t rspLen;

    if (UINTPTR_MAX - 2 < (uintptr_t)pBuf) {
        goto cleanup;
    }
    got_tag = *pBuf++;

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 1) {
        goto cleanup;
    }
    *pRsp = *pBuf;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint16_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t rspLen;

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 2) {
        goto cleanup;
    }
    *pRsp = (*pBuf++) << 8;
    *pRsp |= *pBuf++;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;

    if (rsp == NULL) {
        goto cleanup;
    }

    if (pRspLen == NULL) {
        goto cleanup;
    }

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > *pRspLen) {
        goto cleanup;
    }
    if (extendedLen > bufLen) {
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    if (retVal != 0) {
        if (pRspLen != NULL) {
            *pRspLen = 0;
        }
    }
    return retVal;
}

int tlvGet_Result(uint8_t *buf, size_t *pBufIndex, size_t bufLen, SE05x_TAG_t tag, SE05x_Result_t *presult)
{
    uint8_t uType   = 0;
    size_t uTypeLen = 1;
    int retVal      = tlvGet_u8buf(buf, pBufIndex, bufLen, tag, &uType, &uTypeLen);
    *presult        = (SE05x_Result_t)uType;
    return retVal;
}

smStatus_t DoAPDUTx(
    pSe05xSession_t session_ctx, const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t length_extended)
{
    smStatus_t apduStatus = SM_NOT_OK;
#if (defined(WITH_ECKEY_SCP03_SESSION) || defined(WITH_ECKEY_SESSION))
    tlvHeader_t outHdr = {
        0,
    };
#endif
    size_t rxBufLen = MAX_APDU_BUFFER;
    uint8_t *rspBuf = &session_ctx->apdu_buffer[0];
#if (defined(WITH_ECKEY_SCP03_SESSION) || defined(WITH_PLATFORM_SCP03))
    size_t org_cmd_len = cmdBufLen;
#endif
    ENSURE_OR_GO_EXIT(hdr != NULL);
    if (cmdBufLen > 0) {
        ENSURE_OR_GO_EXIT(cmdBuf != NULL);
    }

#ifdef ENABLE_SM_APDU_MUTEX
    SM_MUTEX_LOCK(g_sm_apdu_mutex);
#endif

#if defined(WITH_PLATFORM_SCP03)
    if (session_ctx->scp03_session) {
        apduStatus = Se05x_API_SCP03_Encrypt(session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

        apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
    }
    else
#endif //#if defined(WITH_PLATFORM_SCP03)

#if defined(WITH_ECKEY_SCP03_SESSION)
        if (session_ctx->ecKey_session == 0 && session_ctx->scp03_session == 1) {
        apduStatus = Se05x_API_SCP03_Encrypt(session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

        apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
    }
    else if (session_ctx->ecKey_session == 1 && session_ctx->scp03_session == 1) {
        size_t cmd_index = 0;

        apduStatus = Se05x_API_ECKeyAuth_Encrypt(
            session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, &outHdr, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        cmd_index = (cmdBuf[4] == 0) ? (7) : (5);

        apduStatus = Se05x_API_SCP03_Encrypt(
            session_ctx, &outHdr, &cmdBuf[cmd_index], cmdBufLen - cmd_index, length_extended, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

        apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, &rxBufLen);
        if (apduStatus != SM_OK) {
            Se05x_API_Auth_IncCommandCounter(&session_ctx->eckey_counter[0]);
            goto exit;
        }
        else {
            apduStatus = Se05x_API_ECKeyAuth_Decrypt(session_ctx, rspBuf, rxBufLen, rspBuf, &rxBufLen);
        }
    }
    else
#endif //#if defined(WITH_ECKEY_SCP03_SESSION)

#if defined(WITH_ECKEY_SESSION)
        if (session_ctx->ecKey_session == 1) {
        apduStatus = Se05x_API_ECKeyAuth_Encrypt(
            session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, &outHdr, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

        apduStatus = Se05x_API_ECKeyAuth_Decrypt(session_ctx, cmdBuf, rxBufLen, rspBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
    }
    else
#endif //#if defined(WITH_ECKEY_SESSION)
    {
        (void)length_extended;
        if (cmdBufLen > 0) {
            if ((cmdBufLen < 0xFF) && !length_extended) {
                ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 5) >= cmdBufLen);
                memmove((cmdBuf + 5), cmdBuf, cmdBufLen);
                memcpy(cmdBuf, hdr, 4);
                cmdBuf[4] = cmdBufLen;
                ENSURE_OR_GO_EXIT((UINT_MAX - 5) >= cmdBufLen);
                cmdBufLen += 5;
            }
            else {
                ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 7) >= cmdBufLen);
                memmove((cmdBuf + 7), cmdBuf, cmdBufLen);
                memcpy(cmdBuf, hdr, 4);

                cmdBuf[4] = 0x00;
                cmdBuf[5] = 0xFFu & (cmdBufLen >> 8);
                cmdBuf[6] = 0xFFu & (cmdBufLen);

                ENSURE_OR_GO_EXIT((UINT_MAX - 7) >= cmdBufLen);
                cmdBufLen += 7;
            }
        }
        else {
            memcpy(cmdBuf, hdr, 4);
            cmdBufLen = 4;
        }
        if (length_extended) {
            ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 2) >= cmdBufLen);
            ENSURE_OR_GO_EXIT((UINT_MAX - 2) >= cmdBufLen);
            cmdBuf[cmdBufLen++] = 0x00;
            cmdBuf[cmdBufLen++] = 0x00;
        }
        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, rspBuf, &rxBufLen);
        if (rxBufLen >= 2) {
            apduStatus = rspBuf[(rxBufLen)-2] << 8 | rspBuf[(rxBufLen)-1];
        }
    }

exit:
#ifdef ENABLE_SM_APDU_MUTEX
    SM_MUTEX_UNLOCK(g_sm_apdu_mutex);
#endif
    return apduStatus;
}

smStatus_t DoAPDUTxRx(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    uint8_t length_extended)
{
    smStatus_t apduStatus = SM_NOT_OK;
#if (defined(WITH_ECKEY_SCP03_SESSION) || defined(WITH_ECKEY_SESSION))
    tlvHeader_t outHdr = {
        0,
    };
#endif
#if (defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION) || defined(WITH_ECKEY_SESSION))
    size_t rxBufLen = MAX_APDU_BUFFER;
#endif

#if (defined(WITH_PLATFORM_SCP03) || defined(WITH_ECKEY_SCP03_SESSION))
    size_t org_cmd_len = cmdBufLen;
#endif

    ENSURE_OR_GO_EXIT(hdr != NULL);
    if (cmdBufLen > 0) {
        ENSURE_OR_GO_EXIT(cmdBuf != NULL);
    }
    ENSURE_OR_GO_EXIT(pRspBufLen != NULL);
    ENSURE_OR_GO_EXIT(rspBuf != NULL);

#ifdef ENABLE_SM_APDU_MUTEX
    SM_MUTEX_LOCK(g_sm_apdu_mutex);
#endif

#if defined(WITH_PLATFORM_SCP03)
    if (session_ctx->scp03_session) {
        apduStatus = Se05x_API_SCP03_Encrypt(session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, cmdBuf, &cmdBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

        apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

        apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, pRspBufLen);
        ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
    }
    else
#endif //#if defined(WITH_PLATFORM_SCP03)

#if defined(WITH_ECKEY_SCP03_SESSION)
        /*Only PlatformSCP session is opened*/
        if (session_ctx->ecKey_session == 0 && session_ctx->scp03_session == 1) {
            apduStatus =
                Se05x_API_SCP03_Encrypt(session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, cmdBuf, &cmdBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

            apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
            ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

            apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, pRspBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        }
        /*Both PlatformSCP and ECKey sessions are opened*/
        else if (session_ctx->ecKey_session == 1 && session_ctx->scp03_session == 1) {
            size_t cmd_index = 0;

            apduStatus = Se05x_API_ECKeyAuth_Encrypt(
                session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, &outHdr, cmdBuf, &cmdBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

            cmd_index = (cmdBuf[4] == 0) ? (7) : (5);

            apduStatus = Se05x_API_SCP03_Encrypt(
                session_ctx, &outHdr, &cmdBuf[cmd_index], cmdBufLen - cmd_index, length_extended, cmdBuf, &cmdBufLen);

            apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
            ENSURE_OR_RETURN_ON_ERROR((apduStatus == SM_OK), apduStatus);
            ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

            apduStatus = Se05x_API_SCP03_Decrypt(session_ctx, org_cmd_len, cmdBuf, rxBufLen, rspBuf, pRspBufLen);
            if (apduStatus != SM_OK) {
                Se05x_API_Auth_IncCommandCounter(&session_ctx->eckey_counter[0]);
                goto exit;
            }
            else {
                apduStatus = Se05x_API_ECKeyAuth_Decrypt(session_ctx, rspBuf, *pRspBufLen, rspBuf, pRspBufLen);
            }
        }
        else
#endif //#if defined(WITH_ECKEY_SCP03_SESSION)

#if defined(WITH_ECKEY_SESSION)
            if (session_ctx->ecKey_session == 1) {
            apduStatus = Se05x_API_ECKeyAuth_Encrypt(
                session_ctx, hdr, cmdBuf, cmdBufLen, length_extended, &outHdr, cmdBuf, &cmdBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);

            apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, cmdBuf, &rxBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
            ENSURE_OR_RETURN_ON_ERROR((rxBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

            apduStatus = Se05x_API_ECKeyAuth_Decrypt(session_ctx, cmdBuf, rxBufLen, rspBuf, pRspBufLen);
            ENSURE_OR_GO_EXIT(apduStatus == SM_OK);
        }
        else
#endif //#if defined(WITH_ECKEY_SESSION)

        {
            if (cmdBufLen > 0) {
                if ((cmdBufLen < 0xFF) && !length_extended) {
                    ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 5) >= cmdBufLen);
                    memmove((cmdBuf + 5), cmdBuf, cmdBufLen);
                    memcpy(cmdBuf, hdr, 4);
                    cmdBuf[4] = cmdBufLen;
                    ENSURE_OR_GO_EXIT((UINT_MAX - 5) >= cmdBufLen);
                    cmdBufLen += 5;
                }
                else {
                    ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 7) >= cmdBufLen);
                    memmove((cmdBuf + 7), cmdBuf, cmdBufLen);
                    memcpy(cmdBuf, hdr, 4);

                    cmdBuf[4] = 0x00;
                    cmdBuf[5] = 0xFFu & (cmdBufLen >> 8);
                    cmdBuf[6] = 0xFFu & (cmdBufLen);

                    ENSURE_OR_GO_EXIT((UINT_MAX - 7) >= cmdBufLen);
                    cmdBufLen += 7;
                }
            }
            else {
                memcpy(cmdBuf, hdr, 4);
                cmdBufLen = 4;
            }
            if (length_extended) {
                ENSURE_OR_GO_EXIT((MAX_APDU_BUFFER - 2) >= cmdBufLen);
                ENSURE_OR_GO_EXIT((UINT_MAX - 2) >= cmdBufLen);
                cmdBuf[cmdBufLen++] = 0x00;
                cmdBuf[cmdBufLen++] = 0x00;
            }
            apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, rspBuf, pRspBufLen);
            if (*pRspBufLen >= 2) {
                apduStatus = rspBuf[(*pRspBufLen) - 2] << 8 | rspBuf[(*pRspBufLen) - 1];
            }
        }

exit:
#ifdef ENABLE_SM_APDU_MUTEX
    SM_MUTEX_UNLOCK(g_sm_apdu_mutex);
#endif
    return apduStatus;
}
