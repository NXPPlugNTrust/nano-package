/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_AUTH_H__
#define __SA_QI_AUTH_H__

#include "sa_qi_transmitter.h"
#include "sa_qi_transmitter_helpers.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(FLOW_VERBOSE)
#define NX_LOG_ENABLE_APP_DEBUG 1
#endif // FLOW_VERBOSE

#include "sa_qi_port.h"

#define MAX_CMD_SIZE_GET_DIGESTS 2
#define MAX_RSP_SIZE_GET_DIGESTS 2 + (32 /* Digest size */ * 4 /* Total slots */)

#define MAX_CMD_SIZE_GET_CERTIFICATE 4
#define MAX_CMD_SIZE_CHALLENGE 18
#define MAX_RSP_SIZE_CHALLENGE 67
#define TBS_AUTH_BUFFER_SIZE \
    1 + 32 /* Digest Size */ + MAX_CMD_SIZE_CHALLENGE + 3 /* First 3 bytes of Challenge response */

#define NONCE_LEN 16

#define UNCOMPRESSED_KEY_SIZE 64
#define COMPRESSED_KEY_SIZE 32
#define MAX_MANUFACTURER_CERT_SIZE 0x200
#define MAX_PROD_CERT_SIZE 0x200
#define ROOT_CERT_SIZE 32 /* Only hash of Root cert will be stored */
#define CERT_CHAIN_HASH_SIZE 32

#define MAX_CERT_CHAIN_SIZE MAX_MANUFACTURER_CERT_SIZE + MAX_PROD_CERT_SIZE + ROOT_CERT_SIZE + 2 + CERT_CHAIN_HASH_SIZE

extern pSe05xSession_t pgSe05xSessionctx;
extern uint8_t qi_rootca_cert[];
extern size_t qi_rootca_cert_len;

void getDigestSHA256(uint8_t *pInput, size_t inputLen, uint8_t *pOutput);
void getPublicKeyFromSlot(uint8_t slot_id, uint8_t *pPublicKey, size_t *pPublicKeyLen);

#endif // __SA_QI_AUTH_H__
