/* License text */

#ifndef __SA_QI_PORT_H__
#define __SA_QI_PORT_H__

smStatus_t Se05x_API_CreateSession(
    pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen);

smStatus_t ex_se05x_aesauth_encrypt_data(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *inBuf,
    size_t inBufLen,
    tlvHeader_t *outhdr,
    uint8_t *outBuf,
    size_t *poutBufLen,
    uint8_t hasle);

smStatus_t Se05x_API_SCP03_AESCreateSession(pSe05xSession_t session_ctx);

smStatus_t ex_se05x_aesauth_decrypt_data(
    pSe05xSession_t session_ctx, uint8_t *inBuf, size_t inBufLen, uint8_t *outBuf, size_t *pOutBufLen);

smStatus_t Se05x_API_CheckObjectExists_AESAuth(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_Result_t *presult);
smStatus_t Se05x_API_WriteECKey_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part);
smStatus_t Se05x_API_UpdateECKey_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part);
smStatus_t Se05x_API_WriteBinary_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen);
smStatus_t Se05x_API_UpdateBinary_AESAuth(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen);

#endif // __SA_QI_PORT_H__
