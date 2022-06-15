/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_PORT_H__
#define __SA_QI_PORT_H__

#include <nxLog_App.h>
#include "sm_port.h"

#include "se05x_APDU_apis.h"
#include <mbedtls/base64.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <random/rand32.h>

#define BEGIN_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
#define END_PUBLIC "\n-----END PUBLIC KEY-----"

int port_getRandomNonce(uint8_t *nonce, size_t *pNonceLen);
void port_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen);
int port_hostVerifyCertificateChain(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset);
int port_hostVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse);

#endif // __SA_QI_PORT_H__
