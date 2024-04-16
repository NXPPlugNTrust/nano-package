/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************
 * Header Files
 *******************************************************************/
#include "sa_qi_provisioning.h"
#include "sa_qi_port.h"

#define EX_FAIL                                 \
    {                                           \
        SMLOG_I("%s, FAILED \n", __FUNCTION__); \
        return 1;                               \
    }

#define EX_PASS                                 \
    {                                           \
        SMLOG_I("%s, PASSED \n", __FUNCTION__); \
        return 0;                               \
    }

#define SET_CHUNK_SIZE 70
Se05xSession_t aes_se05x_session = {
    0,
};
pSe05xSession_t p_aes_session_ctx = &aes_se05x_session;

Se05xSession_t se05x_session = {
    0,
};
pSe05xSession_t p_base_session_ctx = &se05x_session;

uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

/* doc:start:aes-key-auth */
#define EX_MANAGEMENT_CREDENTIAL_ID 0x7DA00002
uint8_t aes_scp03_enc_key[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
uint8_t aes_scp03_mac_key[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
uint8_t aes_scp03_dek_key[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
/* doc:end:aes-key-auth */

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL; // DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

void ex_set_aes_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &aes_scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &aes_scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = &aes_scp03_mac_key[0]; // DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 16;
    return;
}

/*******************************************************************
* Static Functions
*******************************************************************/

size_t insertPolicyForAuthObject(uint32_t auth_obj_id, uint8_t *pBuf, uint32_t policyHeader)
{
    size_t policyBuflen  = 0;
    pBuf[policyBuflen++] = (uint8_t)((auth_obj_id >> 3 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((auth_obj_id >> 2 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((auth_obj_id >> 1 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((auth_obj_id >> 0 * 8) & 0xFF);

    pBuf[policyBuflen++] = (uint8_t)((policyHeader >> 3 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((policyHeader >> 2 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((policyHeader >> 1 * 8) & 0xFF);
    pBuf[policyBuflen++] = (uint8_t)((policyHeader >> 0 * 8) & 0xFF);

    return policyBuflen;
}

void getEcKeyPolicy(uint8_t *pPolicyBuf, Se05xPolicy_t *policy_for_ec_key)
{
    uint32_t policyHeader = 0;
    uint8_t *pPolicy      = pPolicyBuf;
    /* EC Key policies for Qi credentials */
    policyHeader = POLICY_OBJ_ALLOW_READ;
    policyHeader |= POLICY_OBJ_ALLOW_WRITE;
    policyHeader |= POLICY_OBJ_ALLOW_DELETE;
    policyHeader |= POLICY_OBJ_ALLOW_GEN;

    /* Size of each policy would be 8 (4-byte KeyID + 4-byte policy buffer) */
    *pPolicyBuf = 8;
    insertPolicyForAuthObject(EX_MANAGEMENT_CREDENTIAL_ID, pPolicyBuf + 1, policyHeader);

    pPolicyBuf += 9;

    /* Set common policies */
    *pPolicyBuf  = 8;
    policyHeader = POLICY_OBJ_ALLOW_READ;
    policyHeader |= POLICY_OBJ_ALLOW_SIGN;
    policyHeader |= POLICY_OBJ_ALLOW_VERIFY;

    insertPolicyForAuthObject(0, pPolicyBuf + 1, policyHeader);

    policy_for_ec_key->value = pPolicy, policy_for_ec_key->value_len = 18;
}

void getBinaryObjectPolicy(uint8_t *pPolicyBuf, Se05xPolicy_t *policy_for_bin_obj)
{
    uint32_t policyHeader = 0;
    uint8_t *pPolicy      = pPolicyBuf;
    /* EC Key policies for Qi credentials */
    policyHeader = POLICY_OBJ_ALLOW_WRITE;
    policyHeader |= POLICY_OBJ_ALLOW_DELETE;
    policyHeader |= POLICY_OBJ_ALLOW_READ;

    /* Size of each policy would be 8 (4-byte KeyID + 4-byte policy buffer) */
    *pPolicyBuf = 8;
    insertPolicyForAuthObject(EX_MANAGEMENT_CREDENTIAL_ID, pPolicyBuf + 1, policyHeader);

    pPolicyBuf += 9;

    /* Set common policies */
    *pPolicyBuf  = 8;
    policyHeader = POLICY_OBJ_ALLOW_READ;

    insertPolicyForAuthObject(0, pPolicyBuf + 1, policyHeader);

    policy_for_bin_obj->value = pPolicy, policy_for_bin_obj->value_len = 18;
}

uint8_t se05x_applet_session_value[8] = {
    0,
};

int set_qi_key_cert()
{
    smStatus_t status;
    uint32_t qi_key_id       = QI_SLOT_ID_TO_KEY_ID(QI_PROVISIONING_SLOT_ID);
    uint32_t qi_cert_id      = QI_SLOT_ID_TO_CERT_ID(QI_PROVISIONING_SLOT_ID);
    size_t offset            = 0;
    uint16_t fileSize        = 0;
    SE05x_ECCurve_t curve_id = kSE05x_ECCurve_NA;
    SE05x_Result_t result;
    uint8_t policyBuf[64] = {
        0,
    };
    size_t sessionIdLen                 = sizeof(se05x_applet_session_value);
    Se05xPolicy_t policy_for_ec_key     = {0};
    Se05xPolicy_t policy_for_cert_chain = {0};

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    status =
        Se05x_API_CreateSession(&se05x_session, EX_MANAGEMENT_CREDENTIAL_ID, se05x_applet_session_value, &sessionIdLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CreateSession \n");
        return 1;
    }

    memcpy(p_aes_session_ctx, p_base_session_ctx, sizeof(se05x_session));
    ex_set_aes_scp03_keys(p_aes_session_ctx);

    status = Se05x_API_SCP03_AESCreateSession(p_base_session_ctx);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SCP03_AESCreateSession \n");
        return 1;
    }

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists_AESAuth(p_base_session_ctx, qi_key_id, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }
    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists */
        SMLOG_I("Already Provisioned\n");
    }
    else {
        curve_id = kSE05x_ECCurve_NIST_P256;
    }

    status = Se05x_API_CheckObjectExists_AESAuth(p_base_session_ctx, qi_cert_id, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }
    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists */
        SMLOG_I("Already Provisioned\n");
        fileSize = 0;
    }
    else {
        fileSize = (uint16_t)qi_certificate_chain_len;
    }

    getEcKeyPolicy(policyBuf, &policy_for_ec_key);

    /* Set qi key pair */
    if (curve_id == kSE05x_ECCurve_NIST_P256) {
        status = Se05x_API_WriteECKey_AESAuth(p_base_session_ctx,
            &policy_for_ec_key,
            0,
            qi_key_id,
            curve_id,
            qi_ec_priv_key,
            qi_ec_priv_key_len,
            qi_ec_pub_key,
            qi_ec_pub_key_len,
            kSE05x_INS_NA,
            kSE05x_KeyPart_Pair);
    }
    else {
        status = Se05x_API_UpdateECKey_AESAuth(p_base_session_ctx,
            &policy_for_ec_key,
            0,
            qi_key_id,
            curve_id,
            qi_ec_priv_key,
            qi_ec_priv_key_len,
            qi_ec_pub_key,
            qi_ec_pub_key_len,
            kSE05x_INS_NA,
            kSE05x_KeyPart_Pair);
    }
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    /* Binary object policies for Qi credentials */
    getBinaryObjectPolicy(policyBuf, &policy_for_cert_chain);

    /* Set qi cert chain */
    while (qi_certificate_chain_len > 0) {
        uint16_t chunk = (qi_certificate_chain_len > SET_CHUNK_SIZE) ? SET_CHUNK_SIZE : qi_certificate_chain_len;
        qi_certificate_chain_len = qi_certificate_chain_len - chunk;

        /* Call APIs For SE050 */
        if (fileSize == 0) {
            status = Se05x_API_UpdateBinary_AESAuth(p_base_session_ctx,
                &policy_for_cert_chain,
                qi_cert_id,
                offset,
                (uint16_t)fileSize,
                (qi_certificate_chain + offset),
                chunk);
        }
        else {
            status = Se05x_API_WriteBinary_AESAuth(p_base_session_ctx,
                &policy_for_cert_chain,
                qi_cert_id,
                offset,
                (uint16_t)fileSize,
                (qi_certificate_chain + offset),
                chunk);
        }

        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_WriteBinary \n");
            goto exit;
        }

        fileSize = 0;
        offset   = offset + chunk;
    }

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    EX_PASS;

exit:

    EX_FAIL;
}
