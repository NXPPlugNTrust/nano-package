/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_qi_auth.h"

#define EX_SLOT_ID 0x00

static int sendCommandGetDigests_RetrieveHashForSlot(uint8_t *pHash);
static int sendCommandGetCertificate_RetrivePublicKeyVerifyHash(
    uint8_t *pPublicKey, size_t *pPublicKeyLen, uint8_t *pHash);
static int sendCommandChallenge_VerifySignature(
    uint8_t *pPublicKey, size_t publicKeyLen, uint8_t *pCertificateChainHash);

int ex_qi_entry()
{
    int ret = 1;

    uint8_t digest[DIGEST_SIZE_BYTES] = {0};
    uint8_t publicKey[80]             = {0};
    size_t publicKeyLen               = sizeof(publicKey);

    if (0 != sendCommandGetDigests_RetrieveHashForSlot(digest)) {
        LOG_E("GetDigests failed");
        goto exit;
    }
    LOG_MAU8_I("Retrieved digest", digest, sizeof(digest));
    if (0 != sendCommandGetCertificate_RetrivePublicKeyVerifyHash(publicKey, &publicKeyLen, digest)) {
        LOG_E("GetCertificate failed");
        goto exit;
    }
    LOG_MAU8_I("Retrieved PUC public key", publicKey, publicKeyLen);
    if (0 != sendCommandChallenge_VerifySignature(publicKey, publicKeyLen, digest)) {
        LOG_E("Challenge failed");
        goto exit;
    }

    ret = 0;
exit:
    return ret;
}

static int sendCommandGetDigests_RetrieveHashForSlot(uint8_t *pHash)
{
    uint8_t cmd_buffer[MAX_CMD_SIZE_GET_DIGESTS]      = {0};
    size_t cmd_size                                   = sizeof(cmd_buffer);
    uint8_t response_buffer[MAX_RSP_SIZE_GET_DIGESTS] = {0};
    size_t response_size                              = sizeof(response_buffer);
    uint8_t slot_id_mask                              = SLOT_ID_MASK_ALL_SLOTS;
    uint8_t slot_id                                   = EX_SLOT_ID;
    uint8_t required_slot_id_mask                     = (1 << EX_SLOT_ID);
    uint8_t hash_response_offset                      = 2;
    LOG_I("Send command GET_DIGESTS");

    /* Create command buffer for GET_DIGESTS command */
    cmd_buffer[0] = (AUTH_PROTOCOL_VERSION << 4) | kQiCommandGetDigests;
    cmd_buffer[1] = 0x00 | (slot_id_mask);

    /* Send GET_DIGESTS command */
    LOG_MAU8_D("GET_DIGESTS >", cmd_buffer, cmd_size);
    powerTransmitterSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("DIGESTS <", response_buffer, response_size);
    if (response_buffer[0] != ((AUTH_PROTOCOL_VERSION << 4) | kQiResponseDigest)) {
        LOG_E("sendCommandGetDigests Failed");
        return -1;
    }
    if ((required_slot_id_mask & ((response_buffer[1] & 0xF0) >> 4)) != required_slot_id_mask) {
        LOG_E("sendCommandGetDigests Failed: Required slot not populated");
        return -1;
    }
    for (uint8_t i = 0; i < slot_id; i++) {
        hash_response_offset += DIGEST_SIZE_BYTES;
    }
    memcpy(pHash, &response_buffer[hash_response_offset], DIGEST_SIZE_BYTES);
    return 0;
}

static int sendCommandGetCertificate_RetrivePublicKeyVerifyHash(
    uint8_t *pPublicKey, size_t *pPublicKeyLen, uint8_t *pHash)
{
    uint8_t cmd_buffer[MAX_CMD_SIZE_GET_CERTIFICATE] = {0};
    size_t cmd_size                                  = sizeof(cmd_buffer);
    uint8_t response_buffer[MAX_CERT_CHAIN_SIZE]     = {0};
    size_t response_size                             = sizeof(response_buffer);
    uint8_t calculated_digest[DIGEST_SIZE_BYTES]     = {0};
    uint8_t pucPublicKey[71]                         = {0};
    size_t pucPublicKeylen                           = sizeof(pucPublicKey);
    uint16_t offset                                  = 0;
    uint16_t length                                  = 0;
    uint8_t slot_id                                  = EX_SLOT_ID;
    uint16_t manufacturerCertLenOffset               = 2 + DIGEST_SIZE_BYTES + 1 + 1;
    uint16_t pucCertOffset                           = manufacturerCertLenOffset;
    uint16_t certificateChainLength                  = 0;
    LOG_I("Send command GET_CERTIFICATE");

    /* Create command buffer for GET_CERTIFICATE command */
    cmd_buffer[0] = (AUTH_PROTOCOL_VERSION << 4) | kQiCommandGetCertificate;
    cmd_buffer[1] = (uint8_t)((offset & 0x0700) >> 3) | (uint8_t)((length & 0x0700) >> 6) | slot_id;
    cmd_buffer[2] = (uint8_t)(offset & 0x00FF);
    cmd_buffer[3] = (uint8_t)(length & 0x00FF);

    /* Send GET_CERTIFICATE command */
    LOG_MAU8_D("GET_CERTIFICATE >", cmd_buffer, cmd_size);
    powerTransmitterSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("CERTIFICATE <", response_buffer, response_size);
    if (response_buffer[0] != ((AUTH_PROTOCOL_VERSION << 4) | kQiResponseCertificate)) {
        LOG_E("sendCommandGetCertificate Failed");
        return -1;
    }

    /* Extract PUC from certificate chain */
    if ((response_buffer[manufacturerCertLenOffset] & 0x80) == 0x80) {
        if ((response_buffer[manufacturerCertLenOffset] & 0x7F) == 0x01) {
            pucCertOffset += response_buffer[manufacturerCertLenOffset + 1] + 3;
        }
        else if ((response_buffer[manufacturerCertLenOffset] & 0x7F) == 0x02) {
            pucCertOffset += ((response_buffer[manufacturerCertLenOffset + 1] << 8) +
                                 response_buffer[manufacturerCertLenOffset + 2]) +
                             4;
        }
    }
    else {
        pucCertOffset += (response_buffer[manufacturerCertLenOffset]) + 2;
    }

    pucCertOffset -= 1;
    manufacturerCertLenOffset -= 1;

    certificateChainLength = pucCertOffset;
    if ((response_buffer[pucCertOffset + 1] & 0x80) == 0x80) {
        if ((response_buffer[pucCertOffset + 1] & 0x7F) == 0x01) {
            certificateChainLength += response_buffer[pucCertOffset + 1 + 1] + 3;
        }
        else if ((response_buffer[pucCertOffset + 1] & 0x7F) == 0x02) {
            certificateChainLength +=
                ((response_buffer[pucCertOffset + 1 + 1] << 8) + response_buffer[pucCertOffset + 1 + 2]) + 4;
        }
    }
    else {
        certificateChainLength += (response_buffer[pucCertOffset + 1]) + 2;
    }

    getDigestSHA256(&response_buffer[1], certificateChainLength - 1, calculated_digest);
    if (memcmp(calculated_digest, pHash, DIGEST_SIZE_BYTES)) {
        LOG_E("SHA256 of certificate chain mismatch");
        return -1;
    }
    else {
        LOG_I("Certificate chain digest successfully verified");
    }

    if (((size_t)pucCertOffset) > certificateChainLength) {
        LOG_E("Invalid offset");
        return -1;
    }

    LOG_MAU8_I("Retrieved PUC", (&response_buffer[pucCertOffset]), ((size_t)(certificateChainLength - pucCertOffset)));

    port_parseCertGetPublicKey(&response_buffer[pucCertOffset],
        (size_t)(certificateChainLength - pucCertOffset),
        pucPublicKey,
        &pucPublicKeylen);

    if (pucPublicKeylen > COMPRESSED_KEY_SIZE) {
        /* Uncompressed key */
        *pPublicKey = 0x04;
        memcpy(pPublicKey + 1, pucPublicKey, pucPublicKeylen);
        *pPublicKeyLen = pucPublicKeylen + 1;
    }
    else {
        /* Compressed key - compare with actual key stored on slot */
        getPublicKeyFromSlot(slot_id, pPublicKey, pPublicKeyLen);
        if (memcmp(pucPublicKey, pPublicKey + 1, COMPRESSED_KEY_SIZE)) {
            LOG_E("Public key mismatch");
            return -1;
        }
    }

    if (0 != port_hostVerifyCertificateChain(
                 response_buffer, certificateChainLength, pucCertOffset, manufacturerCertLenOffset)) {
        LOG_W("Certificate chain verification failed");
    }
    else {
        LOG_I("Certificate chain successfully verified");
    }

    return 0;
}

static int sendCommandChallenge_VerifySignature(
    uint8_t *pPublicKey, size_t publicKeyLen, uint8_t *pCertificateChainHash)
{
    uint8_t cmd_buffer[MAX_CMD_SIZE_CHALLENGE]      = {0};
    size_t cmd_size                                 = sizeof(cmd_buffer);
    uint8_t response_buffer[MAX_RSP_SIZE_CHALLENGE] = {0};
    size_t response_size                            = sizeof(response_buffer);
    uint8_t slot_id                                 = EX_SLOT_ID;
    uint8_t nonce[NONCE_LEN]                        = {0};
    size_t nonce_length                             = sizeof(nonce);
    LOG_I("Send command CHALLENGE");

    if (0 != port_getRandomNonce(nonce, &nonce_length)) {
        LOG_W("Could not generate random nonce on host");
        memset(nonce, 0, sizeof(nonce));
    }

    /* Create command buffer for CHALLENGE command */
    cmd_buffer[0] = (AUTH_PROTOCOL_VERSION << 4) | kQiCommandChallenge;
    cmd_buffer[1] = ((0x00) << 3) | ((0x0) << 2) | slot_id;
    memcpy(&cmd_buffer[2], nonce, sizeof(nonce));

    /* Send CHALLENGE command */
    LOG_MAU8_D("CHALLENGE >", cmd_buffer, cmd_size);
    powerTransmitterSendCommand(cmd_buffer, cmd_size, response_buffer, &response_size);
    LOG_MAU8_D("CHALLENGE_AUTH <", response_buffer, response_size);
    if (response_buffer[0] != ((AUTH_PROTOCOL_VERSION << 4) | kQiResponseChallengeAuth)) {
        LOG_E("sendCommandChallenge Failed");
        return -1;
    }

    LOG_MAU8_I("Challenge Signature", (&response_buffer[3]), (DIGEST_SIZE_BYTES * 2));

    if (0 != port_hostVerifyChallenge(pPublicKey, publicKeyLen, pCertificateChainHash, cmd_buffer, response_buffer)) {
        LOG_E("Failed to verify signature");
        return -1;
    }

    return 0;
}
