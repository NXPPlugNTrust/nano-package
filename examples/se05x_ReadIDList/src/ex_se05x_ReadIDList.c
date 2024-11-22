/** @file ex_se05x_ReadIDList.c
 *  @brief se05x Read IDList example
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_APDU_apis.h"
#include "sm_port.h"

/* ********************** Global variables ********************** */
/**** SCP03 KEYS ****/
// The Default Platform SCP keys for ease of use configurations are present in
// SE050 Configuration: https://www.nxp.com/docs/en/application-note/AN12436.pdf
// SE051 Configuration: https://www.nxp.com/webapp/Download?colCode=AN12973
uint8_t scp03_enc_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01};
uint8_t scp03_mac_key[16] = {
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02};

/**** EC Auth Key ****/
/* clang-format off */
uint8_t ec_auth_key[] = {                                                 \
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,                   \
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,                   \
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,                   \
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,                   \
        0x01, 0x01, 0x04, 0x20,                                           \
        0x6D, 0x2F, 0x43, 0x2F, 0x8A, 0x2F, 0x45, 0xEC,                   \
        0xD5, 0x82, 0x84, 0x7E, 0xC0, 0x83, 0xBB, 0xEB,                   \
        0xC2, 0x3F, 0x1D, 0xF4, 0xF0, 0xDD, 0x2A, 0x6F,                   \
        0xB8, 0x1A, 0x24, 0xE7, 0xB6, 0xD5, 0x4C, 0x7F,                   \
        0xA1, 0x44, 0x03, 0x42, 0x00,                                     \
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,                   \
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,                   \
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,                   \
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,                   \
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,                   \
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,                   \
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,                   \
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,                   \
        0xC4                                                              \
    };
/* clang-format on */

Se05xSession_t se05x_session = {
    0,
};

/* ********************** Functions ********************** */

void ex_set_scp03_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pScp03_enc_key    = &scp03_enc_key[0];
    session_ctx->pScp03_mac_key    = &scp03_mac_key[0];
    session_ctx->pScp03_dek_key    = NULL; //DEK key is required only for key rotation example
    session_ctx->scp03_enc_key_len = 16;
    session_ctx->scp03_mac_key_len = 16;
    session_ctx->scp03_dek_key_len = 0;
    return;
}

void ex_set_ec_auth_keys(pSe05xSession_t session_ctx)
{
    session_ctx->pEc_auth_key    = &ec_auth_key[0];
    session_ctx->ec_auth_key_len = sizeof(ec_auth_key);
    return;
}

static const char *object_type_03_xx[] = {
    [kSE05x_SecObjTyp_EC_KEY_PAIR]               = "EC (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY]               = "EC (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY]                = "EC (Public Key)",
    [kSE05x_SecObjTyp_RSA_KEY_PAIR_CRT]          = "RSA_CRT (Key Pair)",
    [kSE05x_SecObjTyp_RSA_PRIV_KEY]              = "RSA (Private Key)",
    [kSE05x_SecObjTyp_RSA_PRIV_KEY_CRT]          = "RSA_CRT (Private Key)",
    [kSE05x_SecObjTyp_RSA_PUB_KEY]               = "RSA (Public Key)",
    [kSE05x_SecObjTyp_AES_KEY]                   = "AES",
    [kSE05x_SecObjTyp_DES_KEY]                   = "DES",
    [kSE05x_SecObjTyp_BINARY_FILE]               = "BINARY",
    [kSE05x_SecObjTyp_UserID]                    = "USER ID",
    [kSE05x_SecObjTyp_COUNTER]                   = "Counter",
    [kSE05x_SecObjTyp_PCR]                       = "PCR",
    [kSE05x_SecObjTyp_CURVE]                     = "CURVE",
    [kSE05x_SecObjTyp_HMAC_KEY]                  = "HMAC_KEY",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256]     = "NIST-P (Key Pair)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256]      = "NISP_P (Public key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519] = "MONTGOMERY (Key Pair)",
};

static const char *object_type_07_02[] = {
    [kSE05x_SecObjTyp_EC_KEY_PAIR]               = "EC (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY]               = "EC (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY]                = "EC (Public Key)",
    [kSE05x_SecObjTyp_RSA_KEY_PAIR_CRT]          = "RSA_CRT (Key Pair)",
    [kSE05x_SecObjTyp_RSA_PRIV_KEY]              = "RSA (Private Key)",
    [kSE05x_SecObjTyp_RSA_PRIV_KEY_CRT]          = "RSA_CRT (Private Key)",
    [kSE05x_SecObjTyp_RSA_PUB_KEY]               = "RSA (Public Key)",
    [kSE05x_SecObjTyp_AES_KEY]                   = "AES",
    [kSE05x_SecObjTyp_DES_KEY]                   = "DES",
    [kSE05x_SecObjTyp_BINARY_FILE]               = "BINARY",
    [kSE05x_SecObjTyp_UserID]                    = "USER ID",
    [kSE05x_SecObjTyp_COUNTER]                   = "Counter",
    [kSE05x_SecObjTyp_PCR]                       = "PCR",
    [kSE05x_SecObjTyp_CURVE]                     = "CURVE",
    [kSE05x_SecObjTyp_HMAC_KEY]                  = "HMAC_KEY",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P192]     = "NIST-P192 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P192]     = "NIST-P192 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P192]      = "NIST-P192 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224]     = "NIST-P224 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P224]     = "NIST-P224 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224]      = "NIST-P224 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256]     = "NIST-P256 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P256]     = "NIST-P256 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256]      = "NIST-P256 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384]     = "NIST-P384 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P384]     = "NIST-P384 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384]      = "NIST-P384 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P521]     = "NIST-P521 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P521]     = "NIST-P521 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P521]      = "NIST-P521 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool160]  = "Brainpool160 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool160]  = "Brainpool160 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool160]   = "Brainpool160 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool192]  = "Brainpool192 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool192]  = "Brainpool192 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool192]   = "Brainpool192 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool224]  = "Brainpool224 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool224]  = "Brainpool224 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool224]   = "Brainpool224 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool256]  = "Brainpool256 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool256]  = "Brainpool256 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool256]   = "Brainpool256 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool320]  = "Brainpool320 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool320]  = "Brainpool320 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool320]   = "Brainpool320 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool384]  = "Brainpool384 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool384]  = "Brainpool384 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool384]   = "Brainpool384 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool512]  = "Brainpool512 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool512]  = "Brainpool512 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool512]   = "Brainpool512 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Secp160k1]     = "Secp160k1 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Secp160k1]     = "Secp160k1 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Secp160k1]      = "Secp160k1 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Secp192k1]     = "Secp192k1 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Secp192k1]     = "Secp192k1 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Secp192k1]      = "Secp192k1 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Secp224k1]     = "Secp224k1 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Secp224k1]     = "Secp224k1 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Secp224k1]      = "Secp224k1 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_Secp256k1]     = "Secp256k1 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_Secp256k1]     = "Secp256k1 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_Secp256k1]      = "Secp256k1 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_BN_P256]       = "BN-P256 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_BN_P256]       = "BN-P256 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_BN_P256]        = "BN-P256 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_ED25519]       = "ED25519 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_ED25519]       = "ED25519 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_ED25519]        = "ED25519 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519] = "MONT-DH-25519 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_MONT_DH_25519] = "MONT-DH-25519 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_25519]  = "MONT-DH-25519 (Public Key)",
    [kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_448]   = "MONT-DH-448 (Key Pair)",
    [kSE05x_SecObjTyp_EC_PRIV_KEY_MONT_DH_448]   = "MONT-DH-448 (Private Key)",
    [kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_448]    = "MONT-DH-448 (Public Key)",
};

int ex_se05x_ReadIDList(void)
{
    smStatus_t status;
    uint8_t pmore = kSE05x_MoreIndicator_NA;
    SE05x_SecObjTyp_t retObjectType = 0;
    const char *Object_type         = NULL;
    uint8_t list[2048]              = {0 ,};
    size_t listlen                  = sizeof(list);
    uint16_t outputOffset           = 0;
    uint16_t size                   = 0;
    uint32_t key_len                = 0;
    uint8_t retTransientType        = 0;

    ex_set_scp03_keys(&se05x_session);
    ex_set_ec_auth_keys(&se05x_session);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }
    do {
        status = Se05x_API_ReadIDList(&se05x_session, outputOffset, 0xFF, &pmore, list, &listlen);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_ReadIDList \n");
            return 1;
        }
        outputOffset = (uint16_t)listlen;
        for (size_t i = 0; i < listlen; i += 4) {
            uint32_t id = 0 | ((uint32_t)list[i + 0] << (3 * 8)) |
                ((uint32_t)list[i + 1] << (2 * 8)) |
                ((uint32_t)list[i + 2] << (1 * 8)) |
                ((uint32_t)list[i + 3] << (0 * 8));

            status =
                Se05x_API_ReadType(&se05x_session, id, &retObjectType, &retTransientType, kSE05x_AttestationType_None);
            if (status == SM_ERR_ACCESS_DENIED_BASED_ON_POLICY) {
                status = SM_OK;
            }
            if (status != SM_OK) {
                SMLOG_E("Error in Se05x_API_ReadType \n");
            }
            if (se05x_session.applet_version >= 0x03050000) {
                Object_type = object_type_07_02[retObjectType];
            }
            else {
                Object_type = object_type_03_xx[retObjectType];
            }

            status = Se05x_API_ReadSize(&se05x_session, id, &size);
            if (status != SM_OK) {
                key_len = 0;
            }
            else {
                key_len = size * 8;
            }
            SMLOG_I("Key-ID: %08X  %-25s  size(BITS): %4d \n", id, Object_type, key_len);
        }
    } while (pmore == kSE05x_MoreIndicator_MORE);

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        SMLOG_I("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}
