/** @file se05x_types.h
 *  @brief .
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_TYPES_H_INC
#define SE05X_TYPES_H_INC

/* ********************** Include files ********************** */
#include <stdint.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ********************** Constants ********************** */

/** Plug and Trust Nano package version */
#define VERSION_MAJOR 1
#define VERSION_MINOR 5
#define VERSION_DEV 4

/**
* APDU buffer size.
* The stack is tested with Buffer size of 255 Bytes.
*/
#if defined(CONFIG_PLUGANDTRUST_APDU_BUFFER_SIZE) && CONFIG_PLUGANDTRUST_APDU_BUFFER_SIZE > 0
#define MAX_APDU_BUFFER CONFIG_PLUGANDTRUST_APDU_BUFFER_SIZE
#else
#define MAX_APDU_BUFFER 512
#endif

/** NXP reserved object id */
#define SE05X_OBJID_SE05X_APPLET_RES_START 0x7FFF0000u
#define SE05X_OBJID_SE05X_APPLET_RES_MASK(X) (0xFFFF0000u & (X))
#define SE05X_OBJID_SE05X_APPLET_RES_END 0x7FFFFFFFu

/* IoT Hub Access */
#define EX_SSS_OBJID_IOT_HUB_A_START 0xF0000000u
#define EX_SSS_OBJID_IOT_HUB_A_MASK(X) (0xF0000000u & (X))

/** When we want to read with attestation */
#define kSE05x_INS_READ_With_Attestation (kSE05x_INS_READ | kSE05x_INS_ATTEST)

/** Policy constants */
/* Access Rules for Object Policy*/
#define POLICY_OBJ_FORBID_ALL 0x20000000
#define POLICY_OBJ_ALLOW_SIGN 0x10000000
#define POLICY_OBJ_ALLOW_VERIFY 0x08000000
#define POLICY_OBJ_ALLOW_KA 0x04000000
#define POLICY_OBJ_ALLOW_ENC 0x02000000
#define POLICY_OBJ_ALLOW_DEC 0x01000000
#define POLICY_OBJ_ALLOW_KDF 0x00800000 // Only applicable for applet < 7.2
#define POLICY_OBJ_ALLOW_WRAP 0x00400000
#define POLICY_OBJ_ALLOW_READ 0x00200000
#define POLICY_OBJ_ALLOW_WRITE 0x00100000
#define POLICY_OBJ_ALLOW_GEN 0x00080000
#define POLICY_OBJ_ALLOW_DELETE 0x00040000
#define POLICY_OBJ_REQUIRE_SM 0x00020000
#define POLICY_OBJ_REQUIRE_PCR_VALUE 0x00010000
#define POLICY_OBJ_ALLOW_ATTESTATION 0x00008000
#define POLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION 0x00004000
#define POLICY_OBJ_ALLOW_DESFIRE_DUMP_SESSION_KEYS 0x00002000
#define POLICY_OBJ_ALLOW_IMPORT_EXPORT 0x00001000
#define POLICY_OBJ_FORBID_DERIVED_OUTPUT 0x00000800      // Only applicable for applet >= 6.0
#define POLICY_OBJ_ALLOW_KDF_EXT_RANDOM 0x00000400       // Only applicable for applet >= 6.0
#define POLICY_OBJ_ALLOW_TLS_KDF 0x80000000              // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_TLS_PMS 0x40000000              // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_HKDF 0x00800000                 // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_DESFIRE_CHANGEKEY 0x00000200    // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_DERIVED_INPUT 0x00000100        // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_PBKDF 0x00000080                // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_DESFIRE_KDF 0x00000040          // Only applicable for applet >= 7.2
#define POLICY_OBJ_FORBID_EXTERNAL_IV 0x00000020         // Only applicable for applet >= 7.2
#define POLICY_OBJ_ALLOW_USAGE_AS_HMAC_PEPPER 0x00000010 // Only applicable for applet >= 7.2

#define ENSURE_OR_GO_EXIT(CONDITION) \
    if (!(CONDITION)) {              \
        goto exit;                   \
    }

#define ENSURE_OR_GO_CLEANUP(CONDITION) \
    if (!(CONDITION)) {                 \
        goto cleanup;                   \
    }

#define ENSURE_OR_RETURN_ON_ERROR(CONDITION, RETURN_VALUE) \
    if (!(CONDITION)) {                                    \
        return RETURN_VALUE;                               \
    }

/* ********************** SE05x Types ********************** */

typedef uint16_t SE05x_MaxAttemps_t;

typedef struct
{
    /** ISO 7816 APDU Header */
    uint8_t hdr[0   /* For Indentation */
                + 1 /* CLA */
                + 1 /* INS */
                + 1 /* P1 */
                + 1 /* P2 */
    ];
} tlvHeader_t;

/** Se05x session context */
typedef struct
{
    /** I2C connection context */
    void *conn_context;
    /** Set skip_applet_select = 1, to skip the se05x applet selection.*/
    uint8_t skip_applet_select;
    /** Applet Version*/
    uint32_t applet_version;
    /** Apdu buffer used for Tx/Rx */
    uint8_t apdu_buffer[MAX_APDU_BUFFER];
    /** PlatformSCP03 ENC key. Set to NULL in case of plain session */
    uint8_t *pScp03_enc_key;
    /** PlatformSCP03 ENC key length. Set to 0 in case of plain session */
    size_t scp03_enc_key_len;
    /** PlatformSCP03 MAC key. Set to NULL in case of plain session */
    uint8_t *pScp03_mac_key;
    /** PlatformSCP03 MAC key length. Set to 0 in case of plain session */
    size_t scp03_mac_key_len;
    /** PlatformSCP03 DEK key. Set to NULL in case of plain session */
    uint8_t *pScp03_dek_key;
    /** PlatformSCP03 DEK key length. Set to 0 in case of plain session */
    size_t scp03_dek_key_len;
    /** EC Auth key */
    uint8_t *pEc_auth_key;
    /** EC Auth key length */
    size_t ec_auth_key_len;
    /** Set 1 to resume session */
    uint8_t session_resume;
    /** PlatformSCP03 session status */
    uint8_t scp03_session;
    /** Eckey session status*/
    uint8_t ecKey_session;

    /** PlatformSCP03 dynamic keys */
    uint8_t scp03_session_enc_Key[16];
    uint8_t scp03_session_mac_Key[16];
    uint8_t scp03_session_rmac_Key[16];
    uint8_t scp03_counter[16];
    uint8_t scp03_mcv[16];

    /** ECKeys dynamic keys */
    uint8_t eckey_session_enc_Key[16];
    uint8_t eckey_session_mac_Key[16];
    uint8_t eckey_session_rmac_Key[16];
    uint8_t eckey_counter[16];
    uint8_t eckey_mcv[16];
    uint8_t eckey_applet_session_value[8];

} Se05xSession_t;

typedef Se05xSession_t *pSe05xSession_t;

typedef struct
{
    uint8_t *value;
    size_t value_len;
} Se05xPolicy_t;
typedef Se05xPolicy_t *pSe05xPolicy_t;

/** Values for P1 in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kSE05x_P1_NA = 0,
    /** Highest bit not used */
    kSE05x_P1_UNUSED = 0x80,
    /** 2 MSBit for key type */
    kSE05x_P1_MASK_KEY_TYPE = 0x60,
    /** 5 LSBit for credential type */
    kSE05x_P1_MASK_CRED_TYPE = 0x1F,
    /** Key pair (private key + public key) */
    kSE05x_P1_KEY_PAIR = 0x60,
    /** Private key */
    kSE05x_P1_PRIVATE = 0x40,
    /** Public key */
    kSE05x_P1_PUBLIC    = 0x20,
    kSE05x_P1_DEFAULT   = 0x00,
    kSE05x_P1_EC        = 0x01,
    kSE05x_P1_AES       = 0x03,
    kSE05x_P1_DES       = 0x04,
    kSE05x_P1_HMAC      = 0x05,
    kSE05x_P1_BINARY    = 0x06,
    kSE05x_P1_UserID    = 0x07,
    kSE05x_P1_CURVE     = 0x0B,
    kSE05x_P1_SIGNATURE = 0x0C,
    kSE05x_P1_MAC       = 0x0D,
    kSE05x_P1_CIPHER    = 0x0E,
} SE05x_P1_t;

/** Values for P2 in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kSE05x_P2_DEFAULT         = 0x00,
    kSE05x_P2_GENERATE        = 0x03,
    kSE05x_P2_CREATE          = 0x04,
    kSE05x_P2_SIZE            = 0x07,
    kSE05x_P2_SIGN            = 0x09,
    kSE05x_P2_VERIFY          = 0x0A,
    kSE05x_P2_SESSION_CREATE  = 0x1B,
    kSE05x_P2_SESSION_CLOSE   = 0x1C,
    kSE05x_P2_VERSION         = 0x20,
    kSE05x_P2_LIST            = 0x25,
    kSE05x_P2_TYPE            = 0x26,
    kSE05x_P2_EXIST           = 0x27,
    kSE05x_P2_DELETE_OBJECT   = 0x28,
    kSE05x_P2_SESSION_UserID  = 0x2C,
    kSE05x_P2_DH              = 0x0F,
    kSE05x_P2_ENCRYPT_ONESHOT = 0x37,
    kSE05x_P2_DECRYPT_ONESHOT = 0x38,
    kSE05x_P2_SCP             = 0x52,
    kSE05x_P2_ONESHOT         = 0x0E,
    kSE05x_P2_ID              = 0x36,
    kSE05x_P2_PARAM           = 0x40,
} SE05x_P2_t;

/** ECC Curve Identifiers */
typedef enum
{
    /** Invalid */
    kSE05x_ECCurve_NA        = 0x00,
    kSE05x_ECCurve_NIST_P256 = 0x03,
    kSE05x_ECCurve_NIST_P384 = 0x04,
} SE05x_ECCurve_t;

typedef enum
{
    /** Invalid */
    kSE05x_SetIndicator_NA      = 0,
    kSE05x_SetIndicator_NOT_SET = 0x01,
    kSE05x_SetIndicator_SET     = 0x02,
} SE05x_SetIndicator_t;

/** Parameters while setting the curve */
typedef enum
{ /** Invalid */
    kSE05x_ECCurveParam_NA          = 0,
    kSE05x_ECCurveParam_PARAM_A     = 0x01,
    kSE05x_ECCurveParam_PARAM_B     = 0x02,
    kSE05x_ECCurveParam_PARAM_G     = 0x04,
    kSE05x_ECCurveParam_PARAM_N     = 0x08,
    kSE05x_ECCurveParam_PARAM_PRIME = 0x10,
} SE05x_ECCurveParam_t;

/** Values for INS in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kSE05x_INS_NA = 0,
    /** 3 MSBit for instruction characteristics. */
    kSE05x_INS_MASK_INS_CHAR = 0xE0,
    /** 5 LSBit for instruction */
    kSE05x_INS_MASK_INSTRUCTION = 0x1F,

    /** Mask for transient object creation, can only be combined with INS_WRITE. */
    kSE05x_INS_TRANSIENT = 0x80,
    /** Mask for authentication object creation, can only be combined with INS_WRITE */
    kSE05x_INS_AUTH_OBJECT = 0x40,
    /** Mask for getting attestation data. */
    kSE05x_INS_ATTEST = 0x20,

    /** Write or create a persistent object. */
    kSE05x_INS_WRITE = 0x01,
    /** Read the object */
    kSE05x_INS_READ = 0x02,
    /** Perform Security Operation */
    kSE05x_INS_CRYPTO = 0x03,
    /** General operation */
    kSE05x_INS_MGMT = 0x04,
    /** Process session command */
    kSE05x_INS_PROCESS = 0x05,
} SE05x_INS_t;

/** Part of the asymmetric key */
typedef enum
{
    kSE05x_KeyPart_NA = kSE05x_P1_DEFAULT,
    /** Key pair (private key + public key) */
    kSE05x_KeyPart_Pair = kSE05x_P1_KEY_PAIR,
    /** Private key */
    kSE05x_KeyPart_Private = kSE05x_P1_PRIVATE,
    /** Public key */
    kSE05x_KeyPart_Public = kSE05x_P1_PUBLIC,
} SE05x_KeyPart_t;

/** Different TAG Values to talk to SE05X IoT Applet */
typedef enum
{
    /** Invalid */
    kSE05x_TAG_NA                 = 0,
    kSE05x_TAG_SESSION_ID         = 0x10,
    kSE05x_TAG_POLICY             = 0x11,
    kSE05x_TAG_MAX_ATTEMPTS       = 0x12,
    kSE05x_TAG_IMPORT_AUTH_DATA   = 0x13,
    kSE05x_TAG_IMPORT_AUTH_KEY_ID = 0x14,
    kSE05x_TAG_POLICY_CHECK       = 0x15,
    kSE05x_TAG_1                  = 0x41,
    kSE05x_TAG_2                  = 0x42,
    kSE05x_TAG_3                  = 0x43,
    kSE05x_TAG_4                  = 0x44,
    kSE05x_TAG_5                  = 0x45,
    kSE05x_TAG_6                  = 0x46,
    kSE05x_TAG_7                  = 0x47,
    kSE05x_TAG_8                  = 0x48,
    kSE05x_TAG_9                  = 0x49,
    kSE05x_TAG_10                 = 0x4A,
    kSE05x_TAG_11                 = 0x4B,
    kSE05x_TAG_TIMESTAMP          = 0x4F,
    kSE05x_TAG_SIGNATURE          = 0x52,
} SE05x_TAG_t;

/** Different signature algorithms for EC */
typedef enum
{
    /** Invalid */
    kSE05x_ECSignatureAlgo_NA = 0,
    /** NOT SUPPORTED */
    kSE05x_ECSignatureAlgo_PLAIN   = 0x09,
    kSE05x_ECSignatureAlgo_SHA     = 0x11,
    kSE05x_ECSignatureAlgo_SHA_224 = 0x25,
    kSE05x_ECSignatureAlgo_SHA_256 = 0x21,
    kSE05x_ECSignatureAlgo_SHA_384 = 0x22,
    kSE05x_ECSignatureAlgo_SHA_512 = 0x26,
} SE05x_ECSignatureAlgo_t;

/** Different signature algorithms for ED */
typedef enum
{
    /** Invalid */
    kSE05x_EDSignatureAlgo_NA = 0,
    /** Message input must be plain Data. Pure EDDSA algorithm */
    kSE05x_EDSignatureAlgo_ED25519PURE_SHA_512 = 0xA3,
} SE05x_EDSignatureAlgo_t;

/** Result of operations */
typedef enum
{
    /** Invalid */
    kSE05x_Result_NA      = 0,
    kSE05x_Result_SUCCESS = 0x01,
    kSE05x_Result_FAILURE = 0x02,
} SE05x_Result_t;

/** Symmetric cipher modes */
typedef enum
{
    /** Invalid */
    kSE05x_CipherMode_NA = 0,
    /** Typically using AESKey identifiers */
    kSE05x_CipherMode_AES_CBC_NOPAD = 0x0D,
    /** Typically using AESKey identifiers */
    kSE05x_CipherMode_AES_ECB_NOPAD = 0x0E,
    /** Typically using AESKey identifiers */
    kSE05x_CipherMode_AES_CTR = 0xF0,
} SE05x_CipherMode_t;

/** One Shot operations helper */
typedef enum
{
    kSE05x_Cipher_Oper_OneShot_NA      = 0,
    kSE05x_Cipher_Oper_OneShot_Encrypt = kSE05x_P2_ENCRYPT_ONESHOT,
    kSE05x_Cipher_Oper_OneShot_Decrypt = kSE05x_P2_DECRYPT_ONESHOT,
} SE05x_Cipher_Oper_OneShot_t;

/** SE05X's key IDs */
typedef uint32_t SE05x_KeyID_t;
/** Case when there is no KEK */
#define SE05x_KeyID_KEK_NONE 0

/** Symmetric keys */
typedef enum
{
    kSE05x_SymmKeyType_NA   = 0,
    kSE05x_SymmKeyType_AES  = kSE05x_P1_AES,
    kSE05x_SymmKeyType_DES  = kSE05x_P1_DES,
    kSE05x_SymmKeyType_HMAC = kSE05x_P1_HMAC,
    kSE05x_SymmKeyType_CMAC = kSE05x_P1_AES,
} SE05x_SymmKeyType_t;

/** Mandate platform SCP or not */
typedef enum
{
    /** Invalid */
    kSE05x_PlatformSCPRequest_NA = 0,
    /** Platform SCP is required (full enc & MAC) */
    kSE05x_PlatformSCPRequest_REQUIRED = 0x01,
    /** No platform SCP required. */
    kSE05x_PlatformSCPRequest_NOT_REQUIRED = 0x02,
} SE05x_PlatformSCPRequest_t;

/** In case the read is attested */
typedef enum
{
    kSE05x_AttestationType_None = 0,
    kSE05x_AttestationType_AUTH = kSE05x_INS_AUTH_OBJECT,
} SE05x_AttestationType_t;

/** When there are more entries yet to be fetched from the APIs */
typedef enum
{
    /** Invalid */
    kSE05x_MoreIndicator_NA = 0,
    /** No more data available */
    kSE05x_MoreIndicator_NO_MORE = 0x01,
    /** More data available */
    kSE05x_MoreIndicator_MORE = 0x02,
} SE05x_MoreIndicator_t;

/** Type of Object */
typedef enum
{
    kSE05x_SecObjTyp_NA                        = 0x00,
    kSE05x_SecObjTyp_EC_KEY_PAIR               = 0x01,
    kSE05x_SecObjTyp_EC_PRIV_KEY               = 0x02,
    kSE05x_SecObjTyp_EC_PUB_KEY                = 0x03,
    kSE05x_SecObjTyp_RSA_KEY_PAIR              = 0x04,
    kSE05x_SecObjTyp_RSA_KEY_PAIR_CRT          = 0x05,
    kSE05x_SecObjTyp_RSA_PRIV_KEY              = 0x06,
    kSE05x_SecObjTyp_RSA_PRIV_KEY_CRT          = 0x07,
    kSE05x_SecObjTyp_RSA_PUB_KEY               = 0x08,
    kSE05x_SecObjTyp_AES_KEY                   = 0x09,
    kSE05x_SecObjTyp_DES_KEY                   = 0x0A,
    kSE05x_SecObjTyp_BINARY_FILE               = 0x0B,
    kSE05x_SecObjTyp_UserID                    = 0x0C,
    kSE05x_SecObjTyp_COUNTER                   = 0x0D,
    kSE05x_SecObjTyp_PCR                       = 0x0F,
    kSE05x_SecObjTyp_CURVE                     = 0x10,
    kSE05x_SecObjTyp_HMAC_KEY                  = 0x11,
    kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P192     = 0x21,
    kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P192     = 0x22,
    kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P192      = 0x23,
    kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224     = 0x25,
    kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P224     = 0x26,
    kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224      = 0x27,
    kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256     = 0x29,
    kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P256     = 0x2A,
    kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256      = 0x2B,
    kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384     = 0x2D,
    kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P384     = 0x2E,
    kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384      = 0x2F,
    kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P521     = 0x31,
    kSE05x_SecObjTyp_EC_PRIV_KEY_NIST_P521     = 0x32,
    kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P521      = 0x33,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool160  = 0x35,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool160  = 0x36,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool160   = 0x37,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool192  = 0x39,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool192  = 0x3A,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool192   = 0x3B,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool224  = 0x3D,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool224  = 0x3E,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool224   = 0x3F,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool256  = 0x41,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool256  = 0x42,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool256   = 0x43,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool320  = 0x45,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool320  = 0x46,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool320   = 0x47,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool384  = 0x49,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool384  = 0x4A,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool384   = 0x4B,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Brainpool512  = 0x4D,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Brainpool512  = 0x4E,
    kSE05x_SecObjTyp_EC_PUB_KEY_Brainpool512   = 0x4F,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Secp160k1     = 0x51,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Secp160k1     = 0x52,
    kSE05x_SecObjTyp_EC_PUB_KEY_Secp160k1      = 0x53,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Secp192k1     = 0x55,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Secp192k1     = 0x56,
    kSE05x_SecObjTyp_EC_PUB_KEY_Secp192k1      = 0x57,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Secp224k1     = 0x59,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Secp224k1     = 0x5A,
    kSE05x_SecObjTyp_EC_PUB_KEY_Secp224k1      = 0x5B,
    kSE05x_SecObjTyp_EC_KEY_PAIR_Secp256k1     = 0x5D,
    kSE05x_SecObjTyp_EC_PRIV_KEY_Secp256k1     = 0x5E,
    kSE05x_SecObjTyp_EC_PUB_KEY_Secp256k1      = 0x5F,
    kSE05x_SecObjTyp_EC_KEY_PAIR_BN_P256       = 0x61,
    kSE05x_SecObjTyp_EC_PRIV_KEY_BN_P256       = 0x62,
    kSE05x_SecObjTyp_EC_PUB_KEY_BN_P256        = 0x63,
    kSE05x_SecObjTyp_EC_KEY_PAIR_ED25519       = 0x65,
    kSE05x_SecObjTyp_EC_PRIV_KEY_ED25519       = 0x66,
    kSE05x_SecObjTyp_EC_PUB_KEY_ED25519        = 0x67,
    kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519 = 0x69,
    kSE05x_SecObjTyp_EC_PRIV_KEY_MONT_DH_25519 = 0x6A,
    kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_25519  = 0x6B,
    kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_448   = 0x71,
    kSE05x_SecObjTyp_EC_PRIV_KEY_MONT_DH_448   = 0x72,
    kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_448    = 0x73,
} SE05x_SecObjTyp_t;

/** @copydoc SE05x_SecObjTyp_t */
typedef SE05x_SecObjTyp_t SE05x_SecureObjectType_t;

/** Attestation */
typedef enum
{
    kSE05x_AttestationAlgo_NA                  = 0,
    kSE05x_AttestationAlgo_EC_PLAIN            = kSE05x_ECSignatureAlgo_PLAIN,
    kSE05x_AttestationAlgo_EC_SHA              = kSE05x_ECSignatureAlgo_SHA,
    kSE05x_AttestationAlgo_EC_SHA_224          = kSE05x_ECSignatureAlgo_SHA_224,
    kSE05x_AttestationAlgo_EC_SHA_256          = kSE05x_ECSignatureAlgo_SHA_256,
    kSE05x_AttestationAlgo_EC_SHA_384          = kSE05x_ECSignatureAlgo_SHA_384,
    kSE05x_AttestationAlgo_EC_SHA_512          = kSE05x_ECSignatureAlgo_SHA_512,
    kSE05x_AttestationAlgo_ED25519PURE_SHA_512 = kSE05x_EDSignatureAlgo_ED25519PURE_SHA_512,
} SE05x_AttestationAlgo_t;

#endif //#ifndef SE05X_TYPES_H_INC
