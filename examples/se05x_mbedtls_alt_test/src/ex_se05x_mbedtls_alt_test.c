/** @file ex_se05x_mbedtls_alt_test.c
 *  @brief se05x mbedtls alt example
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "stdio.h"
#include "stdlib.h"
#include "se05x_APDU_apis.h"
#include "sm_port.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

/* ********************** Defines ********************** */
#define EXAMPLE_LOOP_CNT 1

/* ********************** Global variables ********************** */

/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973

uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

/**** nist256 key pair ****/
/* clang-format off */
const uint8_t nist256PrivKey[] = {
    0xE4, 0xEE, 0x5F, 0x99, 0xD9, 0xD8, 0x37, 0x8F, 0x39, 0xC2, 0xC9, 0xFD, 0xA9, 0x12, 0x5E, 0xA7,
    0x3F, 0xB8, 0xFD, 0x00, 0xB5, 0x19, 0xE6, 0x94, 0x1E, 0xF1, 0x34, 0x75, 0x8D, 0x33, 0x59, 0x8A,
};
const uint8_t nist256PubKey[] = {
    0x04, 0xF2, 0x24, 0xBC, 0x5E, 0xEA, 0x74, 0x28, 0xA1, 0x20, 0xD3, 0xD2, 0x69, 0xFE, 0x22, 0xF3,
    0x59, 0x9C, 0x20, 0x33, 0xA2, 0xE0, 0xCB, 0x81, 0xC2, 0xCE, 0xA9, 0xD6, 0xD4, 0x66, 0xC3, 0x68,
    0xF8, 0xB6, 0xA8, 0x9C, 0xDE, 0x08, 0x88, 0xB5, 0x49, 0xCD, 0xED, 0x85, 0xD3, 0xB5, 0x88, 0x72,
    0x0A, 0xDC, 0x26, 0x32, 0xB0, 0x30, 0xBF, 0xB1, 0x67, 0xD0, 0xFD, 0xBC, 0x89, 0xE7, 0x2B, 0x9C,
    0xC1,
};
const uint8_t nist256ReferencePrivKey[] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0xA5, 0xA6, 0xB5, 0xB6, 0xA5, 0xA6, 0xB5, 0xB6,
    0x10, 0x00
};
/* clang-format on */

/* ********************** Functions ********************** */

int ex_set_nist256_key(pSe05xSession_t session_ctx)
{
    smStatus_t status;
    uint32_t keyID = 0x11223344;
    SE05x_Result_t result;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;

    /* Check if the object exists in se05x already */
    status = Se05x_API_CheckObjectExists(session_ctx, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        goto exit;
    }

    if (result == kSE05x_Result_SUCCESS) {
        /* If key already exists, set curveID = NA  */
        curveID = kSE05x_ECCurve_NA;
    }

    /* Set nist256 key pair */
    status = Se05x_API_WriteECKey(session_ctx,
        NULL,
        0,
        keyID,
        curveID,
        nist256PrivKey,
        sizeof(nist256PrivKey),
        nist256PubKey,
        sizeof(nist256PubKey),
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        goto exit;
    }

    return 0;
exit:
    return 1;
}

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

/* Dummy entropy function. */
int dummy_entropy(void *data, unsigned char *output, size_t len)
{
    size_t i;
    (void)data;

    for (i = 0; i < len; i++) {
        //replace result with pseudo random
        output[i] = (unsigned char)0x02;
    }
    return (0);
}

int ex_se05x_mbedtls_alt_test()
{
    smStatus_t status;
    Se05xSession_t se05x_session = {
        0,
    };

    ex_set_scp03_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    /* Inject the actual key in Secure Element */
    SMLOG_I("Inject the actual key in SE05x \n");
    if (ex_set_nist256_key(&se05x_session)) {
        SMLOG_E("Error in ex_set_get_nist256_key \n");
        return 1;
    }

    SMLOG_I("Close Session to SE05x \n");
    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    // Call mbedtls apis for sign and verify
    {
        int cnt                           = 0;
        mbedtls_entropy_context entropy   = {0};
        mbedtls_ctr_drbg_context ctr_drbg = {0};
        mbedtls_pk_context pk             = {0};
        uint8_t decorated_key[256]        = {0};
        /* clang-format off */
        uint8_t header1[]                 = {0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
            0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
            0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
            0x01, 0x01, 0x04, 0x20};
        uint8_t header2[]                 = {0xA1, 0x44, 0x03, 0x42, 0x00};
        /* clang-format on */
        size_t index           = 0;
        uint8_t digest[32]     = {1, 2, 3, 4};
        uint8_t signature[128] = {0};
        size_t signature_len   = sizeof(signature);

        memcpy(&decorated_key[index], header1, sizeof(header1));
        index += sizeof(header1);
        memcpy(&decorated_key[index], nist256ReferencePrivKey, sizeof(nist256ReferencePrivKey));
        index += sizeof(nist256ReferencePrivKey);
        memcpy(&decorated_key[index], header2, sizeof(header2));
        index += sizeof(header2);
        memcpy(&decorated_key[index], nist256PubKey, sizeof(nist256PubKey));
        index += sizeof(nist256PubKey);

        mbedtls_ctr_drbg_init((&ctr_drbg));
        mbedtls_entropy_init((&entropy));
        mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy, "mbedtls_session", 10);

        SMLOG_MAU8_D("key set in mbedtls is", decorated_key, index);
        int ret = mbedtls_pk_parse_key(&pk, decorated_key, index, NULL, 0, NULL, NULL);
        if (ret != 0) {
            SMLOG_E("Error in mbedtls_pk_parse_key. ret = %d \n", ret);
            return 1;
        }

        /* Loop added just for internal testing */
        while (cnt++ < EXAMPLE_LOOP_CNT) {
            //SMLOG_I("\n\nItteration count = %d \n", cnt);
            signature_len = sizeof(signature);
            ret           = mbedtls_pk_sign(&pk,
                MBEDTLS_MD_SHA256,
                digest,
                sizeof(digest),
                signature,
                signature_len,
                &signature_len,
                mbedtls_ctr_drbg_random,
                &ctr_drbg);
            if (ret != 0) {
                SMLOG_E("Error in mbedtls_pk_sign. ret = %d \n", ret);
                return 1;
            }

            SMLOG_MAU8_D("Signature is ==> \n", signature, signature_len);

            ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, signature_len);
            if (ret != 0) {
                SMLOG_E("Error in mbedtls_pk_verify. ret = %d \n", ret);
                return 1;
            }
            else {
                SMLOG_I("ecdsa verify using host (mbedtls) success.! \n");
            }
        }
    }

    return 0;
}
