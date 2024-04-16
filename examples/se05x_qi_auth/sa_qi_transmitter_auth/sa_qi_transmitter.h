/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_TRANSMITTER__
#define __SA_QI_TRANSMITTER__

#include <stdint.h>
#include <stdlib.h>
#include "sa_qi_common.h"
#include "sa_qi_tx_port.h"

#define AUTH_PROTOCOL_VERSION 0x1
#define DIGEST_SIZE_BYTES 32

#define READ_ID_LIST_MAX_OBJECTS 256
#define READ_ID_LIST_SIZE READ_ID_LIST_MAX_OBJECTS * 4
#define SLOT_ID_MASK_ALL_SLOTS 0xF
#define MAXIMUM_CERT_OFFSET 0x600
#define QI_COMMAND_MASK 0x0F
#define TBSAUTH_MAX_SIZE 54
#define TBSAUTH_CHALLENGE_REQ_OFFSET 33
#define TBSAUTH_CHALLENGE_AUTH_RESP_OFFSET 51
#define CHALLENGE_AUTH_RESPONSE_PREFIX 0x41
#define MAX_SIGNATURE_LEN 80
#define CHALLENGE_AUTH_RESPONSE_LEN 67
#define GET_DIGESTS_CMD_LEN 2
#define GET_CERTIFICATE_CMD_LEN 4
#define CHALLENGE_CMD_LEN 18

typedef enum
{
    kQiCommandGetDigests     = 0x9,
    kQiCommandGetCertificate = 0xA,
    kQiCommandChallenge      = 0xB,
} qi_command_id_t;

typedef enum
{
    kQiResponseDigest        = 0x1,
    kQiResponseCertificate   = 0x2,
    kQiResponseChallengeAuth = 0x3,
    kQiResponseError         = 0x7,
} qi_response_id_t;

typedef enum
{
    kQiErrorNone = 0x0,
    kQiErrorInvalidRequest,
    kQiErrorUnsupportedProtocol,
    kQiErrorBusy,
    kQiErrorUnspecified,
} qi_error_code_t;

void powerTransmitterSendCommand(
    const uint8_t *pCmdBuffer, const size_t cmdBufferLen, uint8_t *pResponseBuffer, size_t *pResponseBufferLen);

void GetCertificateChainDigest(const uint8_t *pGetDigestRequest,
    const size_t getDigestRequestLen,
    uint8_t *pDigestResponse,
    size_t *pDigestResponseLen);

void ReadCertificates(const uint8_t *pGetCertificateRequest,
    const size_t getCertificateRequestLen,
    uint8_t *pCertificateResponse,
    size_t *pCertificateResponseLen);

void Authenticate(const uint8_t *pChallengeRequest,
    const size_t challengeRequestLen,
    uint8_t *pChallengeAuthResponse,
    size_t *pChallengeAuthResponseLen);

#endif // __SA_QI_TRANSMITTER__
