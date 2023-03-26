/*
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EX_SE05X_GETINFO_H
#define EX_SE05X_GETINFO_H

#include <string.h>
#include "se05x_APDU_apis.h"
#include "sm_port.h"
#include "smCom.h"

/* ********************** Defines ********************** */
//#define SEMS_LITE_AGENT_CHANNEL_1

#define CHECK_FEATURE_PRESENT(AppletConfig, ITEM)                                            \
    if (((kSE05x_AppletConfig_##ITEM) == ((AppletConfig) & (kSE05x_AppletConfig_##ITEM)))) { \
        SMLOG_I("With    " #ITEM);                                                           \
        SMLOG_I(" \n");                                                                      \
    }                                                                                        \
    else {                                                                                   \
        SMLOG_I("WithOut " #ITEM);                                                           \
        SMLOG_I(" \n");                                                                      \
    }

#define SEMS_LITE_GETDATA_UUID_TAG (0xFE)
#define SE050_MODULE_UNIQUE_ID_LEN (18)
#define APPLET_NAME_LEN (16)
#define CLA_ISO7816 (0x00)   //!< ISO7816-4 defined CLA byte
#define INS_GP_SELECT (0xA4) //!< Global platform defined instruction
#define KSE05X_APPLETRESID_UNIQUE_ID \
    (0x7FFF0206) //A BinaryFile Secure Object which holds the device unique ID. This file cannot be overwritten or deleted.

#define APPLET_NAME                                                                                    \
    {                                                                                                  \
        0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 \
    }

#define SSD_NAME                                                         \
    {                                                                    \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03 \
    }

/* ********************** Enums ********************** */
/** Features which are available / enabled in the Applet */
typedef enum
{
    /** Invalid */
    kSE05x_AppletConfig_NA = 0,
    /** Use of curve TPM_ECC_BN_P256 */
    kSE05x_AppletConfig_ECDAA = 0x0001,
    /** EC DSA and DH support */
    kSE05x_AppletConfig_ECDSA_ECDH_ECDHE = 0x0002,
    /** Use of curve RESERVED_ID_ECC_ED_25519 */
    kSE05x_AppletConfig_EDDSA = 0x0004,
    /** Use of curve RESERVED_ID_ECC_MONT_DH_25519 */
    kSE05x_AppletConfig_DH_MONT = 0x0008,
    /** Writing HMACKey objects */
    kSE05x_AppletConfig_HMAC = 0x0010,
    /** Writing RSAKey objects */
    kSE05x_AppletConfig_RSA_PLAIN = 0x0020,
    /** Writing RSAKey objects */
    kSE05x_AppletConfig_RSA_CRT = 0x0040,
    /** Writing AESKey objects */
    kSE05x_AppletConfig_AES = 0x0080,
    /** Writing DESKey objects */
    kSE05x_AppletConfig_DES = 0x0100,
    /** PBKDF2 */
    kSE05x_AppletConfig_PBKDF = 0x0200,
    /** TLS Handshake support commands (see 4.16) in APDU Spec*/
    kSE05x_AppletConfig_TLS = 0x0400,
    /** Mifare DESFire support (see 4.15)  in APDU Spec*/
    kSE05x_AppletConfig_MIFARE = 0x0800,
    /** RFU1 */
    kSE05x_AppletConfig_RFU1 = 0x1000,
    /** I2C Master support (see 4.17)  in APDU Spec*/
    kSE05x_AppletConfig_I2CM = 0x2000,
    /** RFU2 */
    kSE05x_AppletConfig_RFU2 = 0x4000,
} SE05x_AppletConfig_t;

#endif /* EX_SE05X_GETINFO_H */
