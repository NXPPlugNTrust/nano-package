/**
 * @file ecp_alt_se05x.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Implementation of ECP Sign ALT between NXP Secure Element and mbedTLS.
 *
 *****************************************************************************/

#include "common.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <sm_port.h>

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "bn_mul.h"
#include "ecp_invasive.h"

#include <string.h>

#if defined(MBEDTLS_ECDSA_SIGN_ALT)

#include "se05x_mbedtls.h"
#include "se05x_APDU_apis.h"

extern int mbedtls_ecdsa_sign_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);


int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    SMLOG_D("%s", __FUNCTION__);

    smStatus_t status = SM_NOT_OK;
    SE05x_Result_t result;
    uint32_t keyID          = 0;
    uint8_t magic_bytes[]   = ALT_KEYS_MAGIC;
    uint8_t buffer[150]     = {0};
    uint8_t signature[128]  = {0};
    size_t signature_len    = sizeof(signature);
    const unsigned char *end = NULL;
    unsigned char *p = NULL;
    size_t len = 0;
    size_t rawPrivatekeylen = d->n * sizeof(mbedtls_mpi_uint);

    int ret                 = mbedtls_mpi_write_binary(d, buffer, rawPrivatekeylen);
    if (ret != 0) {
        SMLOG_E("Error %d\r\n", ret);
        return -1;
    }

    if (0 != memcmp(&buffer[rawPrivatekeylen - sizeof(magic_bytes) - 2], magic_bytes, sizeof(magic_bytes))) {
        SMLOG_I("Other key found !! Fallback on mbedtls");
        return mbedtls_ecdsa_sign_o(grp, r, s, d, buf, blen, f_rng, p_rng);
    }

    keyID = (uint32_t)((buffer[rawPrivatekeylen - sizeof(magic_bytes) - 2 - 4] << (8 * 3)) +
                       (buffer[rawPrivatekeylen - sizeof(magic_bytes) - 2 - 3] << (8 * 2)) +
                       (buffer[rawPrivatekeylen - sizeof(magic_bytes) - 2 - 2] << (8 * 1)) +
                       (buffer[rawPrivatekeylen - sizeof(magic_bytes) - 2 - 1] << (8 * 0)));

    status = se05x_open_session();
    if (status != SM_OK) {
        SMLOG_E("Failed to initialize SE05x session\r\n");
        ret = -1;
        goto exit;
    }

    status = Se05x_API_CheckObjectExists(&pSession, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists\r\n");
        ret = -1;
        goto exit;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Object not provisioned\r\n");
        ret = -1;
        goto exit;
    }

    SMLOG_I("Using SE05x for ecdsa sign");
    status = Se05x_API_ECDSASign(
        &pSession, keyID, kSE05x_ECSignatureAlgo_SHA_256, (uint8_t *)buf, blen, signature, &signature_len);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        ret = -1;
        goto exit;
    }

    end = signature + signature_len;
    p = (unsigned char *) signature;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        SMLOG_E("Error in mbedtls_asn1_get_tag \n");
        goto exit;
    }

    if (p + len != end) {
        ret = -1;
        goto exit;
    }

    ret  = mbedtls_asn1_get_mpi(&p, end, r);
    if (ret != 0){
        SMLOG_E("Error in mbedtls_asn1_get_mpi \n");
        goto exit;
    }

    ret = mbedtls_asn1_get_mpi(&p, end, s);
    if (ret != 0){
        SMLOG_E("Error in mbedtls_asn1_get_mpi \n");
        goto exit;
    }

    ret = 0;
exit:
    se05x_close_session();
    return ret;
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#endif /* MBEDTLS_ECP_C */
