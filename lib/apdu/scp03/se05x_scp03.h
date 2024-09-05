/** @file se05x_scp03.h
 *  @brief Se05x SCP03 utils.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_SCP03_H_INC
#define SE05X_SCP03_H_INC

/* ********************** Include files ********************** */
#include <stdint.h>

/* ********************** Function Prototypes ********************** */

/** Se05x_API_SCP03_Encrypt
 *
 * SCP03 Encryption of commands.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_Encrypt(pSe05xSession_t session_ctx,
    const tlvHeader_t *inhdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t hasle,
    uint8_t *encCmdBuf,
    size_t *encCmdBufLen);

/** Se05x_API_SCP03_Decrypt
 *
 * SCP03 Decryption of commands.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_Decrypt(pSe05xSession_t session_ctx,
    size_t cmdBufLen,
    uint8_t *encBuf,
    size_t encBufLen,
    uint8_t *decCmdBuf,
    size_t *decCmdBufLen);

/** Se05x_API_ECKeyAuth_Encrypt
 *
 * EcKey Auth Encryption of commands.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ECKeyAuth_Encrypt(pSe05xSession_t session_ctx,
    const tlvHeader_t *inhdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t hasle,
    tlvHeader_t *outhdr,
    uint8_t *encCmdBuf,
    size_t *encCmdBufLen);

/** Se05x_API_ECKeyAuth_Decrypt
 *
 * EcKey Auth Decryption of commands.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ECKeyAuth_Decrypt(
    pSe05xSession_t session_ctx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *decCmdBuf, size_t *decCmdBufLen);

/** Se05x_API_SCP03_GetSessionKeys
 *
 * Get SCP03 session keys.
 *
 * @param[in]      session_ctx  The session context
 * @param[in,out]  encKey       Enc key buffer
 * @param[in,out]  encKey_len   Enc key buffer length
 * @param[in,out]  macKey       Mac key buffer
 * @param[in,out]  macKey_len   Mac key buffer length
 * @param[in,out]  rMacKey      Rmac key buffer
 * @param[in,out]  rMacKey_len  Rmac key buffer length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_GetSessionKeys(pSe05xSession_t session_ctx,
    uint8_t *encKey,
    size_t *encKey_len,
    uint8_t *macKey,
    size_t *macKey_len,
    uint8_t *rMacKey,
    size_t *rMacKey_len);

/** Se05x_API_SCP03_GetMcvCounter
 *
 * Get SCP03 MCV and Counter values.
 *
 * @param[in]      session_ctx   The session context
 * @param[in,out]  pCounter      SCP03 Counter
 * @param[in,out]  pCounterLen   SCP03 Counter length
 * @param[in,out]  pMcv          SCP03 MCV
 * @param[in,out]  pMcvLen       SCP03 MCV length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_GetMcvCounter(
    pSe05xSession_t pSessionCtx, uint8_t *pCounter, size_t *pCounterLen, uint8_t *pMcv, size_t *pMcvLen);

/** Se05x_API_SCP03_SetSessionKeys
 *
 * Set SCP03 session keys (Used during session resume).
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  encKey       Enc key buffer
 * @param[in]  encKey_len   Enc key buffer length
 * @param[in]  macKey       Mac key buffer
 * @param[in]  macKey_len   Mac key buffer length
 * @param[in]  rMacKey      Rmac key buffer
 * @param[in]  rMacKey_len  Rmac key buffer length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_SetSessionKeys(pSe05xSession_t session_ctx,
    const uint8_t *encKey,
    const size_t encKey_len,
    const uint8_t *macKey,
    const size_t macKey_len,
    const uint8_t *rMacKey,
    const size_t rMacKey_len);

/** Se05x_API_SCP03_SetMcvCounter
 *
 * Set SCP03 MCV and Counter values.
 *
 * @param[in]  session_ctx   The session context
 * @param[in]  pCounter      SCP03 Counter
 * @param[in]  pCounterLen   SCP03 Counter length
 * @param[in]  pMcv          SCP03 MCV
 * @param[in]  pMcvLen       SCP03 MCV length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_SCP03_SetMcvCounter(pSe05xSession_t pSessionCtx,
    const uint8_t *pCounter,
    const size_t counterLen,
    const uint8_t *pMcv,
    const size_t mcvLen);

/*! \cond PRIVATE */

/** Se05x_API_Auth_CalculateMacCmdApdu
 *
 * Calculate MAC for command APDU using MAC keys.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_CalculateMacCmdApdu(uint8_t *sessionMacKey,
    uint8_t *mcv,
    uint8_t *inData,
    size_t inDataLen,
    uint8_t *outSignature,
    size_t *outSignatureLen);

/** Se05x_API_Auth_CalculateMacRspApdu
 *
 * Calculate MAC for response APDU using RMAC keys.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_CalculateMacRspApdu(uint8_t *sessionRmacKey,
    uint8_t *mcv,
    uint8_t *inData,
    size_t inDataLen,
    uint8_t *outSignature,
    size_t *outSignatureLen);

/** Se05x_API_Auth_PadCommandAPDU
 *
 * Pad command APDU.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_PadCommandAPDU(uint8_t *cmdBuf, size_t *pCmdBufLen);

/** Se05x_API_Auth_CalculateCommandICV
 *
 * Calculate command ICV.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_CalculateCommandICV(uint8_t *sessionEncKey, uint8_t *cCounter, uint8_t *pIcv);

/** Se05x_API_Auth_GetResponseICV
 *
 * Get Response ICV.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_GetResponseICV(bool hasCmd, uint8_t *cCounter, uint8_t *sessionEncKey, uint8_t *pIcv);

/** Se05x_API_Auth_RestoreSwRAPDU
 *
 * Restore Sw Response APDU.
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_Auth_RestoreSwRAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen, uint8_t *sw);

/** Se05x_API_Auth_IncCommandCounter
 *
 * Increment commnd counter.
 * @param[in,out]  se05x_cCounter       Counter
 *
 * @return     void.
 */
void Se05x_API_Auth_IncCommandCounter(uint8_t *se05x_cCounter);

/*! \endcond */

/*! \cond PRIVATE */
/* ********************** Constants ********************** */

/** SCP03 initial host challange */
#define INITIAL_HOST_CHALLANGE                         \
    {                                                  \
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 \
    }

#define SCP_GP_IU_KEY_DIV_DATA_LEN 10   //!< SCP GP Init Update key Div length
#define SCP_GP_IU_KEY_INFO_LEN 3        //!< SCP GP Init Update key info length
#define SCP_GP_CARD_CHALLENGE_LEN 8     //!< SCP GP Card Challenge length
#define SCP_GP_HOST_CHALLENGE_LEN 8     //!< SCP GP Host Challenge length
#define SCP_GP_IU_CARD_CRYPTOGRAM_LEN 8 //!< SCP GP Card Cryptogram length
#define SCP_GP_IU_SEQ_COUNTER_LEN 3     //!< SCP GP Init Update Sequence Counter length
#define SCP_GP_SW_LEN 2                 //!< SCP Status Word length
#define CRYPTO_KEY_CHECK_LEN (3)        //!< SCP key check length

#define ASN_ECC_NIST_256_HEADER_LEN 26
#define ASN_ECC_NIST_384_HEADER_LEN 23

#define KEY_PARAMETER_CURVE_IDENTIFIER_TAG 0xF0
#define KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_LEN 0x01
#define KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_NIST256 0x03 // key parameter value for Nist256
#define KEY_PARAMETER_CURVE_IDENTIFIER_VALUE_NIST384 0x04 // key parameter value for Nist384

#define GPCS_KEY_TYPE_ECC_PUB_KEY 0xB0
#define GPCS_KEY_TYPE_AES 0x88
#define GPCS_KEY_LEN_AES 16

#define SCP_ID 0xAB
#define SCP_CONFIG 0x01

#define SCP_MCV_LEN 16 // MAC Chaining Length

#define CLA_ISO7816 (0x00)         //!< ISO7816-4 defined CLA byte
#define CLA_GP_7816 (0x80)         //!< GP 7816-4 defined CLA byte
#define CLA_GP_SECURITY_BIT (0x04) //!< GP CLA Security bit

#define INS_GP_INITIALIZE_UPDATE (0x50)     //!< Global platform defined instruction
#define INS_GP_EXTERNAL_AUTHENTICATE (0x82) //!< Global platform defined instruction
#define INS_GP_SELECT (0xA4)                //!< Global platform defined instruction
#define INS_GP_PUT_KEY (0xD8)               //!< Global platform defined instruction
#define INS_GP_INTERNAL_AUTHENTICATE (0x88) //!< Global platform defined instruction
#define INS_GP_GET_DATA (0xCA)              //!< Global platform defined instruction
#define P1_GP_GET_DATA (0xBF)               //!< Global platform defined instruction
#define P2_GP_GET_DATA (0x21)               //!< Global platform defined instruction

/* Sizes used in SCP */
#define AES_KEY_LEN_nBYTE (16) //!< AES key length

#define SCP_KEY_SIZE (16)
#define SCP_CMAC_SIZE (16)       // length of the CMAC calculated (and used as MAC chaining value)
#define SCP_IV_SIZE (16)         // length of the Inital Vector
#define SCP_COMMAND_MAC_SIZE (8) // length of the MAC appended in the APDU payload (8 'MSB's)

#define DATA_CARD_CRYPTOGRAM (0x00)        //!< Data card cryptogram
#define DATA_HOST_CRYPTOGRAM (0x01)        //!< Data host cryptogram
#define DATA_DERIVATION_SENC (0x04)        //!< Data Derivation to generate Sess ENC Key
#define DATA_DERIVATION_SMAC (0x06)        //!< Data Derivation to generate Sess MAC Key
#define DATA_DERIVATION_SRMAC (0x07)       //!< Data Derivation to generate Sess RMAC Key
#define DATA_DERIVATION_INITIAL_MCV (0x08) //!< Data Derivation to generate Initial MCV
#define DATA_DERIVATION_L_64BIT (0x0040)   //!< Data Derivation length
#define DATA_DERIVATION_L_128BIT (0x0080)  //!< Data Derivation length
#define DATA_DERIVATION_KDF_CTR (0x01)     //!< Data Derivation counter

#define DD_LABEL_LEN 12 //!< Data Derivation length

/* defines used to indicate the command type */
#define C_MAC (0x01) //!< C MAC security
#define C_ENC (0x02) //!< C ENC security
#define R_MAC (0x10) //!< R MAC security
#define R_ENC (0x20) //!< R ENC security

#define SECLVL_CDEC_RENC_CMAC_RMAC (0x33) //!< Full security

#define SCP_DATA_PAD_BYTE 0x80 //!< Data Pad Byte

#define CMAC_SIZE (8) //!< CMAC Compare size

#define SCP_OK (SW_OK)
#define SCP_UNDEFINED_CHANNEL_ID (0x7041)            //!< Undefined SCP channel identifier
#define SCP_FAIL (0x7042)                            //!< Undefined SCP channel identifier
#define SCP_CARD_CRYPTOGRAM_FAILS_TO_VERIFY (0x7043) //!< Undefined SCP channel identifier
#define SCP_PARAMETER_ERROR (0x7044)                 //!< Undefined SCP channel identifier

#define NO_C_MAC_NO_C_ENC_NO_R_MAC_NO_R_ENC 0                   //!< No security requested
#define C_MAC_NO_C_ENC_R_MAC_NO_R_ENC (C_MAC | R_MAC)           //!< One apply MAC'ing (Not implemented)
#define C_MAC_C_ENC_R_MAC_R_ENC (C_MAC | C_ENC | R_MAC | R_ENC) //!< Apply full security
#define SECURITY_LEVEL C_MAC_C_ENC_R_MAC_R_ENC

#define APPLET_SCP_INIT_UPDATE_LEN 0x0D //!< Applet SCP Initialize Update Length
#define APPLET_SCP_EXT_AUTH_LEN 0x15    //!< Applet SCP External Authenticate Length

#define CONTEXT_LENGTH (SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN)
#define DAA_BUFFER_LEN (CONTEXT_LENGTH + DD_LABEL_LEN + 16)
/*! \endcond */

#endif //#ifndef SE05X_SCP03_H_INC
