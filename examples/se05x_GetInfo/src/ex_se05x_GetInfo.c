/** @file ex_se05x_GetInfo.c
 *  @brief se05x get info example
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "ex_se05x_GetInfo.h"
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

Se05xSession_t se05x_session = {
    0,
};

/* ********************** Declarations ********************** */
int JCOP4_GetDataIdentify(pSe05xSession_t p_session_ctx);
int JCOP4_GetCPLCData(pSe05xSession_t p_session_ctx);
int SemsLite_Applet_Identify(pSe05xSession_t p_session_ctx);
int Iot_Applet_Identify(pSe05xSession_t session_ctx, int getUid);
int sems_lite_session_open(pSe05xSession_t p_session_ctx);
int iot_applet_session_open(pSe05xSession_t session_ctx);
smStatus_t GP_Select(pSe05xSession_t session_ctx,
    const uint8_t *appletName,
    uint16_t appletNameLen,
    uint8_t *responseData,
    uint16_t *responseDataLen);

/* ********************** Functions ********************** */

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

int ex_se05x_GetInfo()
{
    smStatus_t status             = SM_NOT_OK;
    pSe05xSession_t p_session_ctx = &se05x_session;
    int ret                       = 1;

    ex_set_scp03_keys(p_session_ctx);

    p_session_ctx->skip_applet_select = 1;

    status = Se05x_API_SessionOpen(p_session_ctx);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        return 1;
    }

    ret = sems_lite_session_open(p_session_ctx);
    if (ret == 0) {
        /* Get UID from semslite */
        ret = SemsLite_Applet_Identify(p_session_ctx);
        if (ret != 0) {
            SMLOG_E("Error in SemsLite_Applet_Identify\n");
            return 1;
        }

        ret = iot_applet_session_open(p_session_ctx);
        if (ret != 0) {
            SMLOG_I("No IoT applet found \n");
        }
        else {
            /* Get applet version and config details */
            ret = Iot_Applet_Identify(p_session_ctx, 0);
            if (ret != 0) {
                SMLOG_I("Error in Iot_Applet_Identify \n");
            }
        }
    }
    else {
        SMLOG_W("No SemsLite Applet Available. \n");
        /* Try connecting to iot applet */
        ret = iot_applet_session_open(p_session_ctx);
        if (ret != 0) {
            SMLOG_I("No IoT applet found \n");
        }
        else {
            /* Get applet version and config details */
            ret = Iot_Applet_Identify(p_session_ctx, 1);
            if (ret != 0) {
                SMLOG_I("Error in Iot_Applet_Identify \n");
            }
        }
    }

    ret = JCOP4_GetDataIdentify(p_session_ctx);
    if (ret != 0) {
        SMLOG_E("Error in JCOP4_GetDataIdentify \n");
        return 1;
    }

    ret = JCOP4_GetCPLCData(p_session_ctx);
    if (ret != 0) {
        SMLOG_E("Error in JCOP4_GetCPLCData \n");
        return 1;
    }

    status = Se05x_API_SessionClose(p_session_ctx);
    if (status != SM_OK) {
        SMLOG_I("Error in Se05x_API_SessionClose \n");
        return 1;
    }

    return 0;
}

int iot_applet_session_open(pSe05xSession_t session_ctx)
{
    int result = 1;
    smStatus_t status;

    status = Se05x_API_SessionClose(session_ctx);
    if (status != SM_OK) {
        SMLOG_I("Error in Se05x_API_SessionClose \n");
        goto exit;
    }

    session_ctx->skip_applet_select = 0;

    status = Se05x_API_SessionOpen(session_ctx);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
        goto exit;
    }

    result = 0;
exit:
    return result;
}

int sems_lite_session_open(pSe05xSession_t p_session_ctx)
{
    uint32_t ret         = 0;
    smStatus_t retStatus = SM_NOT_OK;
    void *conn_ctx       = p_session_ctx->conn_context;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    const uint8_t openCmd[5] = {0x00, 0x70, 0x00, 0x00, 0x01};
    uint16_t openCmdLen     = sizeof(openCmd);
#endif

    /* clang-format off */
    const uint8_t selectCmd[32] = {
#ifdef SEMS_LITE_AGENT_CHANNEL_1
        0x01, 0xA4, 0x04, 0x00,     0x10, 0xA0, 0x00, 0x00,
#else
        0x00, 0xA4, 0x04, 0x00,     0x10, 0xA0, 0x00, 0x00,
#endif
        0x03, 0x96, 0x54, 0x53,     0x00, 0x00, 0x00, 0x01,
        0x03, 0x30, 0x00, 0x00,     0x00, 0x00,
    };
    /* clang-format on */
    uint16_t selectCmdLen = 22;
    uint8_t *resp         = &(p_session_ctx->apdu_buffer[0]);
    size_t respLen        = sizeof(p_session_ctx->apdu_buffer);

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    ret = smComT1oI2C_TransceiveRaw(conn_ctx, (uint8_t *)openCmd, openCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(ret == SM_OK);
#endif

    respLen = sizeof(p_session_ctx->apdu_buffer);
    ret     = smComT1oI2C_TransceiveRaw(conn_ctx, (uint8_t *)selectCmd, selectCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(ret == SM_OK);
    retStatus = (smStatus_t)((resp[respLen - 2] << 8) | (resp[respLen - 1]));
    if (retStatus != SM_OK) {
        goto exit;
    }

    return 0;
exit:
    return 1;
}

int sems_lite_verify_GetDataResponse(uint8_t tag_P2, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    int result           = 1;
    size_t getDataRspLen = 0;
    smStatus_t retStatus = SM_NOT_OK;
    if (*pRspBufLen >= 4) { // Response should include Tag + Len + Data + SW1 + SW2.
        getDataRspLen = *pRspBufLen;

        retStatus = (smStatus_t)((pRspBuf[getDataRspLen - 2] << 8) | (pRspBuf[getDataRspLen - 1]));
        if (retStatus == SM_OK) {
            if (pRspBuf[0] == tag_P2) {
                // pRspBuf[1] is data length. It should be less than response buffer - tag - lenght - SW1SW2 field.
                if (pRspBuf[1] <= getDataRspLen - 4) {
                    *pRspBufLen = (size_t)(pRspBuf[1]);
                    memmove(pRspBuf, pRspBuf + 2, pRspBuf[1]);
                    result = 0;
                }
                else {
                    memset(pRspBuf, 0, *pRspBufLen);
                    *pRspBufLen = 0;
                }
            }
        }
    }
    return result;
}

int SemsLite_Applet_Identify(pSe05xSession_t p_session_ctx)
{
    uint32_t ret   = 0;
    void *conn_ctx = p_session_ctx->conn_context;
    uint8_t *uid   = &(p_session_ctx->apdu_buffer[0]);
    size_t uidLen  = sizeof(p_session_ctx->apdu_buffer);
    uint8_t tag_P1 = 0x00;
    uint8_t tag_P2 = SEMS_LITE_GETDATA_UUID_TAG;

    uint8_t getDataCmd[5] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS 'CA' GET DATA(IDENTIFY)
        0x00, // P1 '00' High order tag value
        0x00, // P2  - proprietary data coming from respective function
        0x00, // Lc is Le'00' Case 2 command
    };
    uint16_t getDataCmdLen = sizeof(getDataCmd);

    getDataCmd[2] = tag_P1;
    getDataCmd[3] = tag_P2;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    getDataCmd[0] = getDataCmd[0] | SEMS_LITE_AGENT_CHANNEL_1;
#endif

    ret = smComT1oI2C_TransceiveRaw(conn_ctx, (uint8_t *)getDataCmd, getDataCmdLen, uid, &uidLen);
    if (ret != SM_OK) {
        SMLOG_E("Could not get requested Data!!! \n");
        goto cleanup;
    }

    if (0 != sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_UUID_TAG, uid, &uidLen)) {
        goto cleanup;
    }

    SMLOG_W("##################################################### \n");
    SMLOG_MAU8_D("uid", uid, uidLen);

    return 0;
cleanup:
    return 1;
}

int Iot_Applet_Identify(pSe05xSession_t session_ctx, int getUid)
{
    int ret = 1;
    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;
    uint8_t uid[SE050_MODULE_UNIQUE_ID_LEN];
    size_t uidLen = sizeof(uid);
    uint8_t applet_version[7];
    size_t applet_versionLen = sizeof(applet_version);

    if (getUid == 1) {
        sw_status = Se05x_API_CheckObjectExists(session_ctx, KSE05X_APPLETRESID_UNIQUE_ID, &result);
        if (SM_OK != sw_status) {
            SMLOG_E("Failed Se05x_API_CheckObjectExists \n");
        }
        else {
            sw_status =
                Se05x_API_ReadObject(session_ctx, KSE05X_APPLETRESID_UNIQUE_ID, 0, (uint16_t)uidLen, uid, &uidLen);
            if (SM_OK != sw_status) {
                SMLOG_E("Failed Se05x_API_CheckObjectExists \n");
                goto cleanup;
            }
            SMLOG_W("##################################################### \n");
            SMLOG_MAU8_D("uid", uid, uidLen);
        }
    }

    // VersionInfo is a 7 - byte value consisting of :
    // - 1 - byte Major applet version
    // - 1 - byte Minor applet version
    // - 1 - byte patch applet version
    // - 2 - byte AppletConfig, indicating the supported applet features
    // - 2-byte Secure Box version: major version (MSB) concatenated with minor version (LSB).

    sw_status = Se05x_API_GetVersion(session_ctx, applet_version, &applet_versionLen);
    if (SM_OK != sw_status) {
        SMLOG_E("Failed Se05x_API_GetVersion \n");
        {
            /* In case of FIPS, if the example is not built for PlatSCP, try getting version by applet select again */
            unsigned char appletName[]     = APPLET_NAME;
            uint8_t selectResponseData[32] = {0};
            uint16_t selectResponseDataLen = sizeof(selectResponseData);
            sw_status                      = (smStatus_t)GP_Select(
                session_ctx, (uint8_t *)&appletName, APPLET_NAME_LEN, selectResponseData, &selectResponseDataLen);
            if (sw_status != SM_OK) {
                SMLOG_E("Could not select applet. \n");
                goto cleanup;
            }
            if (selectResponseDataLen != applet_versionLen) {
                goto cleanup;
            }
            if (selectResponseDataLen > sizeof(applet_version)) {
                goto cleanup;
            }
            memcpy(applet_version, selectResponseData, selectResponseDataLen);
        }
    }
    SMLOG_W("##################################################### \n");
    SMLOG_I("Applet Major = %d \n", applet_version[0]);
    SMLOG_I("Applet Minor = %d \n", applet_version[1]);
    SMLOG_I("Applet patch = %d \n", applet_version[2]);
    SMLOG_I("AppletConfig = %02X%02X \n", applet_version[3], applet_version[4]);
    {
        uint16_t AppletConfig = applet_version[3] << 8 | applet_version[4];
        CHECK_FEATURE_PRESENT(AppletConfig, ECDSA_ECDH_ECDHE);
        CHECK_FEATURE_PRESENT(AppletConfig, EDDSA);
        CHECK_FEATURE_PRESENT(AppletConfig, DH_MONT);
        CHECK_FEATURE_PRESENT(AppletConfig, HMAC);
        CHECK_FEATURE_PRESENT(AppletConfig, RSA_PLAIN);
        CHECK_FEATURE_PRESENT(AppletConfig, RSA_CRT);
        CHECK_FEATURE_PRESENT(AppletConfig, AES);
        CHECK_FEATURE_PRESENT(AppletConfig, DES);
        CHECK_FEATURE_PRESENT(AppletConfig, PBKDF);
        CHECK_FEATURE_PRESENT(AppletConfig, TLS);
        CHECK_FEATURE_PRESENT(AppletConfig, MIFARE);
        CHECK_FEATURE_PRESENT(AppletConfig, I2CM);
    }
    //SMLOG_I("Internal = %02X%02X \n", applet_version[5], applet_version[6]);

    ret = 0;
cleanup:
    return ret;
}

/* Execute and decode GET DATA IDENTIFY as specified for SE05x JCOP
*
* @warn After this call, the applet is deselected and applet commands won't work.
*       The applet session needs to be re-established
*       (select applet, establish optional session,
*/
int JCOP4_GetDataIdentify(pSe05xSession_t p_session_ctx)
{
    int ret = 1;
    smStatus_t rxStatus;
    void *conn_ctx            = p_session_ctx->conn_context;
    char jcop_platform_id[17] = {0};
    uint8_t *resp             = &(p_session_ctx->apdu_buffer[0]);
    size_t respLen            = sizeof(p_session_ctx->apdu_buffer);

    /* Must be packed */
    typedef struct
    {
        //0xFE Tag value - proprietary data Only present if class byte is 0x80
        uint8_t vTag_value_proprietary_data;
        //0x49 / 0x45 Length of following data Only present if class byte is 0x80
        uint8_t vLength_of_following_data;
        //0xDF28 Tag card identification data Only present if class byte is 0x80
        uint8_t vTag_card_identification_data[0x02];
        //0x46 Length of card identification data Only present if class byte is 0x80
        uint8_t vLength_of_card_identification_data;
        //0x01 Tag configuration ID Identifies the configuration content
        uint8_t vTag_configuration_ID;
        uint8_t vLength_configuration_ID; //0x0C Length configuration ID
        uint8_t vConfiguration_ID[0x0C];  //var Configuration ID
        uint8_t vTag_patch_ID;            //0x02 Tag patch ID Identifies the patch level
        uint8_t vLength_patch_ID;         //0x08 Length patch ID
        uint8_t vPatch_ID[0x08];          //var Patch ID
                                          //0x03 Tag platform build ID1 Identifies the JCOP platform
        uint8_t vTag_platform_build_ID1;
        uint8_t vLength_platform_build_ID; //0x18 Length platform build ID
        uint8_t vPlatform_build_ID[0x18];  //var Platform build ID
        uint8_t vTag_FIPS_mode;            //0x052 Tag FIPS mode FIPS mode active
        uint8_t vLength_FIPS_mode;         //0x01 Length FIPS mode
                                           //var FIPS mode 0x00 - FIPS mode not active, 0x01 - FIPS mode active
        uint8_t vFIPS_mode;

        //0x07 Tag pre-perso state Lists pre-perso state
        uint8_t vTag_pre_perso_state;

        //0x01 Length pre-perso state
        uint8_t vLength_pre_perso_state;

        //var Bit mask of pre-perso state bit0 = 1 = config module available,
        //  bit1 = 1 = transport state is active.
        //  Unused bits are set to 0x0.
        uint8_t vBit_mask_of_pre_perso_state;
        uint8_t vTag_ROM_ID;            //'08' Tag ROM ID Indentifies the ROM content
        uint8_t vLength_ROM_ID;         //'08' Length ROM ID Normal ending
        uint8_t vROM_ID[0x08];          //var ROM ID
        uint8_t vStatus_Word_SW_[0x02]; //9000h Status Word (SW)
    } identifyRsp_t;

    const uint8_t cmd[] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS 'CA' GET DATA(IDENTIFY)
        0x00, // P1 '00' High order tag value
        0xFE, // P2 'FE' Low order tag value - proprietary data
        0x02, // Lc '02' Length of data field
        0xDF,
        0x28, // Data 'DF28' Card identification data
        0x00  // Le '00' Length of response data
    };

    identifyRsp_t identifyrsp = {0};
    uint16_t dummyResponse16  = sizeof(identifyRsp_t);

    /* Select card manager / ISD
    * (ReUsing same dummy buffers) */
    rxStatus = (smStatus_t)GP_Select(
        p_session_ctx, (uint8_t *)&identifyrsp /* dummy */, 0, (uint8_t *)&identifyrsp, &dummyResponse16);
    if (rxStatus != SM_OK) {
        SMLOG_E("Could not select ISD.\n");
        goto cleanup;
    }

    rxStatus = (smStatus_t)smComT1oI2C_TransceiveRaw(conn_ctx, (uint8_t *)cmd, sizeof(cmd), resp, &respLen);
    if (rxStatus == SM_OK) {
        identifyRsp_t *identifyRsp = (identifyRsp_t *)resp;
        SMLOG_W("##################################################### \n");
        SMLOG_I("%s = 0x%02X\n", "Tag value - proprietary data 0xFE", identifyRsp->vTag_value_proprietary_data);
        SMLOG_I("%s = 0x%02X\n", "Length of following data 0x45", identifyRsp->vLength_of_following_data);
        SMLOG_MAU8_D("Tag card identification data",
            identifyRsp->vTag_card_identification_data,
            sizeof(identifyRsp->vTag_card_identification_data));
        SMLOG_I("%s = 0x%02X\n",
            "Length of card identification data", // 0x46
            identifyRsp->vLength_of_card_identification_data);
        SMLOG_I("%s = 0x%02X\n", "Tag configuration ID (Must be 0x01)", identifyRsp->vTag_configuration_ID);
        SMLOG_D("%s = 0x%02X\n", "Length configuration ID 0x0C", identifyRsp->vLength_configuration_ID);
        SMLOG_MAU8_D("Configuration ID", identifyRsp->vConfiguration_ID, sizeof(identifyRsp->vConfiguration_ID));

        //Third and fourth Byte of vConfiguration_ID is the OEF ID
        SMLOG_I("%s = 0x%02X 0x%02X\n", "OEF ID", identifyRsp->vConfiguration_ID[2], identifyRsp->vConfiguration_ID[3]);
        SMLOG_I("%s = 0x%02X\n", "Tag patch ID (Must be 0x02)", identifyRsp->vTag_patch_ID);
        SMLOG_D("%s = 0x%02X\n", "Length patch ID 0x08", identifyRsp->vLength_patch_ID);
        SMLOG_MAU8_D("Patch ID", identifyRsp->vPatch_ID, sizeof(identifyRsp->vPatch_ID));
        SMLOG_I("%s = 0x%02X\n", "Tag platform build ID1 (Must be 0x03)", identifyRsp->vTag_platform_build_ID1);
        SMLOG_D("%s = 0x%02X\n", "Length platform build ID 0x18", identifyRsp->vLength_platform_build_ID);
        SMLOG_MAU8_D("Platform build ID", identifyRsp->vPlatform_build_ID, sizeof(identifyRsp->vPlatform_build_ID));
        memcpy(jcop_platform_id, identifyRsp->vPlatform_build_ID, 16);

        SMLOG_I("%s = %s \n", "JCOP Platform ID", jcop_platform_id);
        SMLOG_I("%s = 0x%02X \n", "Tag FIPS mode (Must be 0x05)", identifyRsp->vTag_FIPS_mode);
        SMLOG_D("%s = 0x%02X \n", "Length FIPS mode 0x01", identifyRsp->vLength_FIPS_mode);
        SMLOG_I("%s = 0x%02X \n", "FIPS mode var", identifyRsp->vFIPS_mode);
        SMLOG_I("%s = 0x%02X \n", "Tag pre-perso state (Must be 0x07)", identifyRsp->vTag_pre_perso_state);
        SMLOG_D("%s = 0x%02X \n", "Length pre-perso state 0x01", identifyRsp->vLength_pre_perso_state);
        SMLOG_I("%s = 0x%02X \n", "Bit mask of pre-perso state var", identifyRsp->vBit_mask_of_pre_perso_state);

        SMLOG_I("%s = 0x%02X \n", "Tag ROM ID (Must be 0x08)", identifyRsp->vTag_ROM_ID);
        SMLOG_D("%s = 0x%02X \n", "Length ROM ID 0x08", identifyRsp->vLength_ROM_ID);
        SMLOG_MAU8_D("ROM ID", identifyRsp->vROM_ID, sizeof(identifyRsp->vROM_ID));
        SMLOG_MAU8_D("Status Word (SW)", identifyRsp->vStatus_Word_SW_, sizeof(identifyRsp->vStatus_Word_SW_));
    }
    else {
        SMLOG_E("Error in retreiving the JCOP Identifier. Response is as follows \n");
        SMLOG_AU8_D(resp, sizeof(resp));
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (ret == 0) {
        SMLOG_I("se05x_GetInfoPlainApplet Example Success !!!... \n");
    }
    else {
        SMLOG_E("se05x_GetInfoPlainApplet Example Failed !!!... \n");
    }
    return ret;
}

/* See 5.1.1.2 Get CPLC data
*   This command returns the Card Production Life Cycle (CPLC) data. The APDU can be sent without prior authentication.
*
*
* The Card Production Life Cycle data as defined in VISA GlobalPlatform Card Specification 2.1.1 are coded in 42
* bytes. The CPLC format and the default values are shown below
*
*/
int JCOP4_GetCPLCData(pSe05xSession_t p_session_ctx)
{
    smStatus_t rxStatus;
    void *conn_ctx = p_session_ctx->conn_context;
    uint8_t *resp  = &(p_session_ctx->apdu_buffer[0]);
    size_t respLen = sizeof(p_session_ctx->apdu_buffer);

    /* Must be packed */
    typedef struct
    {
        uint8_t p9F7F[2];
        uint8_t pLen[1];                            // = 2A
        uint8_t IC_fabricator[2];                   // 2 '4790' NXP
        uint8_t IC_type1[2];                        // 2 'D321' NXP
        uint8_t Operating_system_identifier[2];     //  2 '47' SS NXP
        uint8_t Operating_system_release_date[2];   //  2 SS SS NXP
        uint8_t Operating_system_release_level[2];  //  2 <Mask ID> <Patch ID> NXP
        uint8_t IC_fabrication_date[2];             //  tt NXP
        uint8_t IC_Serial_number[4];                //  4 nnnb NXP
        uint8_t IC_Batch_identifier[2];             //  2 bb NXP
        uint8_t IC_module_fabricator[2];            //  2 '00' '00' Customer
        uint8_t IC_module_packaging_date[2];        //  2 '00' '00' Customer
        uint8_t ICC_manufacturer[2];                // 2 '00' '00' Customer
        uint8_t IC_embedding_date[2];               //  2 '00' '00' Customer
        uint8_t IC_OS_initializer[2];               //  2 WX Customer
        uint8_t IC_OS_initialization_date[2];       // 2 YN Customer
        uint8_t IC_OS_initialization_equipment[4];  // ID 4 NNNN Customer
        uint8_t IC_personalizer[2];                 // 2 '00' '00' Customer
        uint8_t IC_personalization_date[2];         //  2 '00' '00' Customer
        uint8_t IC_personalization_equipment_ID[4]; //  4 '00'. . . '00' Customer
        uint8_t SW[2];
    } cplcRsp_t;

    const uint8_t cmd[] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS
        0x9F, // P1
        0x7F, // P2
        0x00, // Lc
    };

    ENSURE_OR_GO_CLEANUP(sizeof(cplcRsp_t) == 47);

    rxStatus = (smStatus_t)smComT1oI2C_TransceiveRaw(conn_ctx, (uint8_t *)cmd, sizeof(cmd), resp, &respLen);
    if (rxStatus == SM_OK && respLen == sizeof(cplcRsp_t)) {
        cplcRsp_t *cplc_data = (cplcRsp_t *)resp;
        SMLOG_W("##################################################### \n");
        SMLOG_MAU8_D("cplc_data IC_fabricator", cplc_data->IC_fabricator, sizeof(cplc_data->IC_fabricator));
        SMLOG_MAU8_D("cplc_data IC_type1", cplc_data->IC_type1, sizeof(cplc_data->IC_type1));
        SMLOG_MAU8_D("cplc_data Operating_system_identifier",
            cplc_data->Operating_system_identifier,
            sizeof(cplc_data->Operating_system_identifier));
        SMLOG_MAU8_D("cplc_data Operating_system_release_date",
            cplc_data->Operating_system_release_date,
            sizeof(cplc_data->Operating_system_release_date));
        SMLOG_MAU8_D("cplc_data Operating_system_release_level",
            cplc_data->Operating_system_release_level,
            sizeof(cplc_data->Operating_system_release_level));
        SMLOG_MAU8_D(
            "cplc_data IC_fabrication_date", cplc_data->IC_fabrication_date, sizeof(cplc_data->IC_fabrication_date));
        SMLOG_MAU8_D("cplc_data IC_Serial_number", cplc_data->IC_Serial_number, sizeof(cplc_data->IC_Serial_number));
        SMLOG_MAU8_D(
            "cplc_data IC_Batch_identifier", cplc_data->IC_Batch_identifier, sizeof(cplc_data->IC_Batch_identifier));
        SMLOG_MAU8_D(
            "cplc_data IC_module_fabricator", cplc_data->IC_module_fabricator, sizeof(cplc_data->IC_module_fabricator));
        SMLOG_MAU8_D("cplc_data IC_module_packaging_date",
            cplc_data->IC_module_packaging_date,
            sizeof(cplc_data->IC_module_packaging_date));
        SMLOG_MAU8_D("cplc_data ICC_manufacturer", cplc_data->ICC_manufacturer, sizeof(cplc_data->ICC_manufacturer));
        SMLOG_MAU8_D("cplc_data IC_embedding_date", cplc_data->IC_embedding_date, sizeof(cplc_data->IC_embedding_date));
        SMLOG_MAU8_D("cplc_data IC_OS_initializer", cplc_data->IC_OS_initializer, sizeof(cplc_data->IC_OS_initializer));
        SMLOG_MAU8_D("cplc_data IC_OS_initialization_date",
            cplc_data->IC_OS_initialization_date,
            sizeof(cplc_data->IC_OS_initialization_date));
        SMLOG_MAU8_D("cplc_data IC_OS_initialization_equipment",
            cplc_data->IC_OS_initialization_equipment,
            sizeof(cplc_data->IC_OS_initialization_equipment));
        SMLOG_MAU8_D("cplc_data IC_personalizer", cplc_data->IC_personalizer, sizeof(cplc_data->IC_personalizer));
        SMLOG_MAU8_D("cplc_data IC_personalization_date",
            cplc_data->IC_personalization_date,
            sizeof(cplc_data->IC_personalization_date));
        SMLOG_MAU8_D("cplc_data IC_personalization_equipment_ID",
            cplc_data->IC_personalization_equipment_ID,
            sizeof(cplc_data->IC_personalization_equipment_ID));
        SMLOG_MAU8_D("cplc_data SW", cplc_data->SW, sizeof(cplc_data->SW));
    }
    else {
        SMLOG_E("Error in retreiving the CPLC Data. Response is as follows \n");
        SMLOG_AU8_D(resp, sizeof(resp));
        goto cleanup;
    }

    return 0;
cleanup:
    return 1;
}

smStatus_t GP_Select(pSe05xSession_t p_session_ctx,
    const uint8_t *appletName,
    uint16_t appletNameLen,
    uint8_t *responseData,
    uint16_t *responseDataLen)
{
    uint16_t rv     = SM_NOT_OK;
    size_t u32RXLen = *responseDataLen;
    void *conn_ctx  = p_session_ctx->conn_context;
    uint8_t *tx_buf = &(p_session_ctx->apdu_buffer[0]);
    uint16_t tx_len = sizeof(p_session_ctx->apdu_buffer);

    ENSURE_OR_GO_CLEANUP(NULL != responseData);
    ENSURE_OR_GO_CLEANUP(0 != responseDataLen);
    ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
    /* cla+ins+p1+p2+lc+appletNameLen+le */
    ENSURE_OR_GO_CLEANUP(tx_len > (6u + appletNameLen));

    tx_buf[0] = CLA_ISO7816;
    tx_buf[1] = INS_GP_SELECT;
    tx_buf[2] = 4;
    tx_buf[3] = 0;

    tx_len = 0   /* for indentation */
             + 1 /* CLA */
             + 1 /* INS */
             + 1 /* P1 */
             + 1 /* P2 */;
    if (appletNameLen > 0) {
        tx_buf[4] = (uint8_t)appletNameLen; // We have done ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
        tx_len    = tx_len + 1              /* Lc */
                 + appletNameLen            /* Payload */
                 + 1 /* Le */;
        memcpy(&tx_buf[5], appletName, appletNameLen);
    }
    else {
        tx_len = tx_len /* for indentation */
                 + 0    /* No Lc */
                 + 1 /* Le */;
    }
    tx_buf[tx_len - 1] = 0; /* Le */

    rv = smComT1oI2C_TransceiveRaw(conn_ctx, tx_buf, tx_len, responseData, &u32RXLen);
    if (rv == SM_OK && u32RXLen >= 2) {
        *responseDataLen = u32RXLen - 2;
        rv               = responseData[u32RXLen - 2];
        rv <<= 8;
        rv |= responseData[u32RXLen - 1];
    }

cleanup:
    return rv;
}
