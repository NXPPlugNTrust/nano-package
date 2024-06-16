/*
 * Copyright 2012-2014,2018-2020,2022 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <phEseTypes.h>
#include <phNxpEseProto7816_3.h>
#include <phNxpEsePal_i2c.h>
#include "sm_timer.h"
#include "se05x_tlv.h"
#include "sm_port.h"
#include <limits.h>

#define RECIEVE_PACKET_SOF 0xA5
#define CHAINED_PACKET_WITHSEQN 0x60
#define CHAINED_PACKET_WITHOUTSEQN 0x20
#define WTX_REQ_ID 0xC3
static int phNxpEse_readPacket(void *conn_ctx, void *pDevHandle, uint8_t *pBuffer, int nNbBytesToRead);
static int poll_sof_chained_delay = 0;

/* Duration for which session open should wait for previous transaction to complete */
#define T1OI2C_WAIT_FOR_PREV_TXN 40

/*********************** Global Variables *************************************/

/* ESE Context structure */
phNxpEse_Context_t gnxpese_ctxt;

/******************************************************************************
 * Function         phNxpEse_init
 *
 * Description      This function is called by smCom during the
 *                  initialization of the ESE. It initializes protocol stack instance variable
 *
 * param[in]        connection context
 * param[in]        phNxpEse_initParams: ESE communication mode
 * param[out]       phNxpEse_data: ATR Response from ESE
 *
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_init(void *conn_ctx, phNxpEse_initParams initParams, phNxpEse_data *AtrRsp)
{
    ESESTATUS wConfigStatus         = ESESTATUS_SUCCESS;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;
    bool_t status                   = FALSE;
    phNxpEseProto7816InitParam_t protoInitParam;
    phNxpEse_memset(&protoInitParam, 0x00, sizeof(phNxpEseProto7816InitParam_t));
    protoInitParam.rnack_retry_limit = MAX_RNACK_RETRY_LIMIT;
    protoInitParam.wtx_counter_limit = PH_PROTO_WTX_DEFAULT_COUNT;

    if (ESE_MODE_NORMAL == initParams.initMode) /* TZ/Normal wired mode should come here*/
    {
        protoInitParam.interfaceReset = TRUE;
    }
    else if (ESE_MODE_RESUME == initParams.initMode) {
        /* To skip GetAtr command */
        protoInitParam.interfaceReset = FALSE;
    }
    else {
        protoInitParam.interfaceReset = FALSE;
        /*RFU*/
    }

    /* T=1 Protocol layer open */
    status = phNxpEseProto7816_Open((void *)nxpese_ctxt, protoInitParam, AtrRsp);
    if (FALSE == status) {
        wConfigStatus = ESESTATUS_FAILED;
        T_SMLOG_E("phNxpEseProto7816_Open failed ");
    }
    return wConfigStatus;
}

/******************************************************************************
 * Function         phNxpEse_open
 *
 * Description      This function is called by smCom during the
 *                  initialization of the ESE. It opens the physical connection
 *                  with ESE and initializes the protocol stack
 *
 * param[in]        Pointer to connection context
 * param[in]        phNxpEse_initParams: ESE communication mode
 *
 * Returns          This function return ESESTATUS_SUCCES (0) in case of success
 *                  In case of failure returns other failure value.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_open(void **conn_ctx, phNxpEse_initParams initParams, const char *pConnString)
{
    phPalEse_Config_t tPalConfig;
    phNxpEse_Context_t *pnxpese_ctxt = NULL;
    ESESTATUS wConfigStatus          = ESESTATUS_SUCCESS;

    pnxpese_ctxt = &gnxpese_ctxt;
    phNxpEse_memset(pnxpese_ctxt, 0, sizeof(phNxpEse_Context_t));
    if (conn_ctx != NULL) {
        *conn_ctx = pnxpese_ctxt;
    }

    /*When I2C channel is already opened return status as FAILED*/
    if (pnxpese_ctxt->EseLibStatus != ESE_STATUS_CLOSE) {
        T_SMLOG_E(" Session already opened");
        return ESESTATUS_BUSY;
    }

    phNxpEse_memset(pnxpese_ctxt, 0x00, sizeof(phNxpEse_Context_t));
    phNxpEse_memset(&tPalConfig, 0x00, sizeof(tPalConfig));

    tPalConfig.pDevName = (int8_t *)pConnString; //"/dev/p73"; /*RFU*/
    /* Initialize PAL layer */
    wConfigStatus = phPalEse_i2c_open_and_configure(&tPalConfig);
    if (wConfigStatus != ESESTATUS_SUCCESS) {
        T_SMLOG_E("phPalEse_Init Failed");
        goto clean_and_return;
    }
    /* Copying device handle to ESE Lib context*/
    pnxpese_ctxt->pDevHandle = tPalConfig.pDevHandle;
    /* STATUS_OPEN */
    pnxpese_ctxt->EseLibStatus = ESE_STATUS_OPEN;
    phNxpEse_memcpy(&pnxpese_ctxt->initParams, &initParams, sizeof(phNxpEse_initParams));
    return wConfigStatus;

clean_and_return:
    if (NULL != pnxpese_ctxt->pDevHandle) {
        phPalEse_i2c_close(pnxpese_ctxt->pDevHandle);
        phNxpEse_memset(pnxpese_ctxt, 0x00, sizeof(phNxpEse_Context_t));
    }
    pnxpese_ctxt->EseLibStatus = ESE_STATUS_CLOSE;
    return ESESTATUS_FAILED;
}

/******************************************************************************
 * Function         phNxpEse_Transceive
 *
 * Description      This function validate ESE state & C-APDU data before sending
 *                  it to 7816 protocol
 *
 * param[in]       connection context
 * param[in]       phNxpEse_data: Command to ESE C-APDU
 * param[out]      phNxpEse_data: Response from ESE R-APDU
 *
 * Returns          On Success ESESTATUS_SUCCESS else proper error code
 *
 ******************************************************************************/
ESESTATUS phNxpEse_Transceive(void *conn_ctx, phNxpEse_data *pCmd, phNxpEse_data *pRsp)
{
    ESESTATUS status                = ESESTATUS_FAILED;
    bool_t bStatus                  = FALSE;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    if ((NULL == pCmd) || (NULL == pRsp)) {
        return ESESTATUS_INVALID_PARAMETER;
    }

    if ((pCmd->len == 0) || pCmd->p_data == NULL) {
        T_SMLOG_E(" phNxpEse_Transceive - Invalid Parameter no data");
        return ESESTATUS_INVALID_PARAMETER;
    }
    else if ((ESE_STATUS_CLOSE == nxpese_ctxt->EseLibStatus)) {
        T_SMLOG_E(" %s ESE Not Initialized ", __FUNCTION__);
        return ESESTATUS_NOT_INITIALISED;
    }
    else if ((ESE_STATUS_BUSY == nxpese_ctxt->EseLibStatus)) {
        T_SMLOG_E(" %s ESE - BUSY ", __FUNCTION__);
        return ESESTATUS_BUSY;
    }
    else {
        nxpese_ctxt->EseLibStatus = ESE_STATUS_BUSY;
        bStatus                   = phNxpEseProto7816_Transceive((void *)nxpese_ctxt, pCmd, pRsp);
        if (TRUE == bStatus) {
            status = ESESTATUS_SUCCESS;
        }
        else {
            status = ESESTATUS_FAILED;
        }

        if (ESESTATUS_SUCCESS != status) {
            T_SMLOG_E(" %s phNxpEseProto7816_Transceive- Failed ", __FUNCTION__);
        }
        if (nxpese_ctxt->EseLibStatus != ESE_STATUS_CLOSE) {
            nxpese_ctxt->EseLibStatus = ESE_STATUS_IDLE;
        }

        T_SMLOG_D(" %s Exit status 0x%x ", __FUNCTION__, status);
        return status;
    }
}

/******************************************************************************
 * Function         phNxpEse_reset
 *
 * Description      This function reset the ESE interface and free all
 *
 * param[in]        connection context
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is successful else
 *                  ESESTATUS_FAILED(1)
 ******************************************************************************/
ESESTATUS phNxpEse_reset(void *conn_ctx)
{
    ESESTATUS status                = ESESTATUS_FAILED;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;
    //bool_t bStatus = phNxpEseProto7816_IntfReset(&AtrRsp);
    status = phNxpEse_chipReset((void *)nxpese_ctxt);
    if (status != ESESTATUS_SUCCESS) {
        T_SMLOG_E("phNxpEse_reset Failed");
    }
    return status;
}

/******************************************************************************
 * Function         phNxpEse_EndOfApdu
 *
 * Description      This function is used to send S-frame to indicate END_OF_APDU
 *
 * param[in]        connection context
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if the operation is successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_EndOfApdu(void *conn_ctx)
{
    ESESTATUS status                = ESESTATUS_SUCCESS;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;
    bool_t bStatus                  = phNxpEseProto7816_Close((void *)nxpese_ctxt);
    if (!bStatus) {
        status = ESESTATUS_FAILED;
    }
    return status;
}

/******************************************************************************
 * Function         phNxpEse_chipReset
 *
 * Description      This function is used to reset the ESE.
 *
 * param[in]        connection context
 *
 * Returns          On Success ESESTATUS_SUCCESS (0) else ESESTATUS_FAILED (1).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_chipReset(void *conn_ctx)
{
    ESESTATUS status                = ESESTATUS_SUCCESS;
    bool_t bStatus                  = FALSE;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;
    bStatus                         = phNxpEseProto7816_Reset();
    if (!bStatus) {
        status = ESESTATUS_FAILED;
        T_SMLOG_E("phNxpEseProto7816_Reset Failed");
    }
#if defined(T1oI2C_UM11225)
    bStatus = phNxpEseProto7816_ChipReset((void *)nxpese_ctxt);
#elif defined(T1oI2C_GP1_0)
    bStatus = phNxpEseProto7816_ColdReset((void *)nxpese_ctxt);
#endif
    if (bStatus != TRUE) {
        T_SMLOG_E("phNxpEse_chipReset  Failed");
    }
    return status;
}

/******************************************************************************
 * Function         phNxpEse_deInit
 *
 * Description      This function de-initializes all the ESE protocol params
 *
 * param[in]        connection context
 *
 * Returns          On Success ESESTATUS_SUCCESS (0) else ESESTATUS_FAILED (1).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_deInit(void *conn_ctx)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    //bool_t bStatus = FALSE;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;
    /*bStatus = phNxpEseProto7816_ResetProtoParams();
    if(!bStatus)
    {
        status = ESESTATUS_FAILED;
    }*/
    phPalEse_i2c_close(nxpese_ctxt->pDevHandle);
    phNxpEse_memset(nxpese_ctxt, 0x00, sizeof(*nxpese_ctxt));
    //status= phNxpEse_close();
    return status;
}

/******************************************************************************
 * Function         phNxpEse_close
 *
 * Description      This function close the ESE interface and free all
 *                  resources.
 *
 * param[in]        connection context
 *
 * Returns          On Success ESESTATUS_SUCCESS else proper error code.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_close(void *conn_ctx)
{
    ESESTATUS status                = ESESTATUS_SUCCESS;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    if ((ESE_STATUS_CLOSE == nxpese_ctxt->EseLibStatus)) {
        T_SMLOG_E(" %s ESE Not Initialized previously ", __FUNCTION__);
        return ESESTATUS_NOT_INITIALISED;
    }

    phPalEse_i2c_close(nxpese_ctxt->pDevHandle);
    phNxpEse_memset(nxpese_ctxt, 0x00, sizeof(*nxpese_ctxt));
    T_SMLOG_D("phNxpEse_close - ESE Context deinit completed");
    /* Return success always */
    return status;
}

/******************************************************************************
 * Function         phNxpEse_waitWTX
 *
 * Description      This function read out any wtx requests received from the previous
 *                  session and send wtx response.
 *                  Additionally read any response at end of WTX and ignore it.
 *                  Just to make sure that if host was not able to finish previous operation,
 *                  the response of that must not cause an error in current session.
 *
 * param[in]        void*: connection context
 *
 * Returns          void
 *
 ******************************************************************************/
void phNxpEse_waitForWTX(void *conn_ctx)
{
    int ret     = -1;
    int loopcnt = 0;
    //int wtx_cnt = 0;
    //uint8_t readBuf[MAX_APDU_BUFFER] = {0};
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    T_SMLOG_D("%s Enter ..", __FUNCTION__);

    /* Send Rsync - To check if there is a pending operation (by checking for WTX) */
    if (!phNxpEseProto7816_SendRSync(conn_ctx)) {
        T_SMLOG_E(" %s - Error in phNxpEseProto7816_SendRSync ", __FUNCTION__);
        return;
    }

    //ret = phPalEse_i2c_read(nxpese_ctxt->pDevHandle, readBuf, MAX_APDU_BUFFER);
    ret = phPalEse_i2c_read(nxpese_ctxt->pDevHandle, nxpese_ctxt->p_read_buff, MAX_APDU_BUFFER);

    if (ret < 0) {
        return;
    }
    else {
        //if (readBuf[0] == RECIEVE_PACKET_SOF && readBuf[1] == WTX_REQ_ID)
        if (nxpese_ctxt->p_read_buff[0] == RECIEVE_PACKET_SOF && nxpese_ctxt->p_read_buff[1] == WTX_REQ_ID) {
            /** 0xC3 corresponds to WTX request. Send WTX response. */
            T_SMLOG_D(" %s - Received WTX Request", __FUNCTION__);
            if (!phNxpEseProto7816_WTXRsp(conn_ctx)) {
                T_SMLOG_E(" %s - Error in phNxpEseProto7816_WTXRsp ", __FUNCTION__);
                return;
            }
            T_SMLOG_D("Wait till previous transaction is complete");
        }
        else {
            T_SMLOG_D("No WTX request received. Continue with session open");
            return;
        }
    }

    while (loopcnt < T1OI2C_WAIT_FOR_PREV_TXN) {
        sm_sleep(1000); /* WTX is expected every 1 sec */
        //ret = phPalEse_i2c_read(nxpese_ctxt->pDevHandle, readBuf, MAX_APDU_BUFFER);
        ret = phPalEse_i2c_read(nxpese_ctxt->pDevHandle, nxpese_ctxt->p_read_buff, MAX_APDU_BUFFER);
        if (ret < 0) {
            T_SMLOG_E(" %s - Error in phPalEse_i2c_read ", __FUNCTION__);
        }
        else
        {
            T_SMLOG_MAU8_D("Previous RAW Rx < ",nxpese_ctxt->p_read_buff,ret );
            //if (readBuf[0] == RECIEVE_PACKET_SOF && readBuf[1] == WTX_REQ_ID)
            if (nxpese_ctxt->p_read_buff[0] == RECIEVE_PACKET_SOF && nxpese_ctxt->p_read_buff[1] == WTX_REQ_ID) {
                /** 0xC3 corresponds to WTX request. Send WTX response. */
                T_SMLOG_D(" %s - Received WTX Request", __FUNCTION__);
                //LOG_I("WTX REQ received  (CNT = %d).. Send WTX Resp \n", ++wtx_cnt);
                if (!phNxpEseProto7816_WTXRsp(conn_ctx)) {
                    T_SMLOG_E(" %s - Error in phNxpEseProto7816_WTXRsp ", __FUNCTION__);
                    return;
                }
            }
            else {
                T_SMLOG_D("Ignoring response other than WTX Request. Continue with session open");
                return;
            }
        }
        loopcnt++;
    }
    T_SMLOG_W("Last operation took more time than expected");
    T_SMLOG_W("Either increase waiting time (T1OI2C_WAIT_FOR_PREV_TXN) or do a physical reset of IC");
    return;
}

/******************************************************************************
 * Function         phNxpEse_clearReadBuffer
 *
 * Description      This function read out complete data from  SE FIFO read buffer
 *                  interface (e.g. I2C) using the  driver interface.
 *                  Just to make sure that if host is unable to read complete data
 *                  during previous transaction
 *
 * param[in]        void*: connection context
 *
 * Returns          void
 *
 ******************************************************************************/
void phNxpEse_clearReadBuffer(void *conn_ctx)
{
    int ret = -1;
    //uint8_t readBuf[MAX_APDU_BUFFER];
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    T_SMLOG_D("%s Enter ..", __FUNCTION__);

    ret = phPalEse_i2c_read(nxpese_ctxt->pDevHandle, nxpese_ctxt->p_read_buff, MAX_APDU_BUFFER);
    if (ret < 0) {
        /* Do nothing as nothing to read*/
    }
    else {
        T_SMLOG_W("Previous transaction buffer is now cleard");
        T_SMLOG_MAU8_D("RAW Rx<", nxpese_ctxt->p_read_buff, ret);
    }
    return;
}

/******************************************************************************
 * Function         phNxpEse_read
 *
 * Description      This function read the data from ESE through physical
 *                  interface (e.g. I2C) using the  driver interface.
 *
 * param[in]        void*: connection context
 * param[out]       uint32_t: number of bytes read
 * param[out]       uint8_t : Read data from ESE
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if read successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_read(void *conn_ctx, uint32_t *data_len, uint8_t **pp_data)
{
    ESESTATUS status                = ESESTATUS_FAILED;
    int ret                         = -1;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    T_SMLOG_D("%s Enter ..", __FUNCTION__);

    ENSURE_OR_GO_EXIT(data_len != NULL);
    ENSURE_OR_GO_EXIT(pp_data != NULL);

    ret = phNxpEse_readPacket((void *)nxpese_ctxt, nxpese_ctxt->pDevHandle, nxpese_ctxt->p_read_buff, MAX_APDU_BUFFER);
    if (ret < 0) {
        T_SMLOG_E("PAL Read status error status = %x", status);
        status = ESESTATUS_FAILED;
    }
    else {
        T_SMLOG_MAU8_D("RAW Rx<", nxpese_ctxt->p_read_buff, ret);
        *data_len = ret;
        *pp_data  = nxpese_ctxt->p_read_buff;
        status    = ESESTATUS_SUCCESS;
    }
exit:
    return status;
}

/******************************************************************************
 * Function         phNxpEse_readPacket
 *
 * Description      This function Reads requested number of bytes from
 *                  ESE device into given buffer.
 *
 * param[in]        void*: connection context
 * param[in]        void: ESE Context
 * param[in]        uint8_t: pointer to read buffer
 * param[in]        int : MAX bytes to read
 *
 * Returns          ret - number of successfully read bytes
 *                  -1  - read operation failure
 *
 ******************************************************************************/
static int phNxpEse_readPacket(void *conn_ctx, void *pDevHandle, uint8_t *pBuffer, int nNbBytesToRead)
{
    int ret         = -1;
    int sof_counter = 0; /* one read may take 1 ms*/
    int total_count = 0, numBytesToRead = 0, headerIndex = 0;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    ENSURE_OR_GO_EXIT(pBuffer != NULL);
    memset(pBuffer, 0, nNbBytesToRead);
    do {
        sof_counter++;
        ret = -1;
        sm_sleep(ESE_POLL_DELAY_MS);                     /* 1ms delay to give ESE polling delay */
        ret = phPalEse_i2c_read(pDevHandle, pBuffer, 2); /*read NAD PCB byte first*/
        if (ret < 0) {
            /*Polling for read on i2c, hence Debug log*/
            T_SMLOG_D("_i2c_read() ret : %X", ret);
        }
        if (pBuffer[0] == RECIEVE_PACKET_SOF) {
            /* Read the HEADR of Two bytes*/
            T_SMLOG_D("%s Read HDR", __FUNCTION__);
            pBuffer[0] = RECIEVE_PACKET_SOF;
#if defined(T1oI2C_UM11225)
            numBytesToRead = 1;
#elif defined(T1oI2C_GP1_0)
            numBytesToRead = 2;
#endif
            headerIndex = 1;
            break;
        }
        if (pBuffer[1] == RECIEVE_PACKET_SOF) {
            /* Read the HEADR of Two bytes*/
            T_SMLOG_D("%s Read HDR", __FUNCTION__);
            pBuffer[0] = RECIEVE_PACKET_SOF;
#if defined(T1oI2C_UM11225)
            numBytesToRead = 2;
#elif defined(T1oI2C_GP1_0)
            numBytesToRead = 3;
#endif
            headerIndex = 0;
            break;
        }
        /*if host writes invalid frame and host and SE are out of sync*/
        if ((pBuffer[0] == 0x00) && ((pBuffer[1] == 0x82) || (pBuffer[1] == 0x92))) {
            T_SMLOG_W("%s Recieved NAD byte 0x%x ", __FUNCTION__, pBuffer[0]);
            T_SMLOG_W("%s NAD error, clearing the read buffer ", __FUNCTION__);
            /*retry to get all data*/
#if defined(T1oI2C_UM11225)
            numBytesToRead = 1;
#elif defined(T1oI2C_GP1_0)
            numBytesToRead = 2;
#endif
            headerIndex = 1;
            ret         = phPalEse_i2c_read(pDevHandle, &pBuffer[1 + headerIndex], numBytesToRead);
#if defined(T1oI2C_UM11225)
            total_count    = 3;
            nNbBytesToRead = pBuffer[2];
#elif defined(T1oI2C_GP1_0)
            total_count    = 4;
            nNbBytesToRead = (pBuffer[2] << 8 & 0xFF) | (pBuffer[3] & 0xFF);
#endif
            /* Read the Complete data + two byte CRC*/
            ret = phPalEse_i2c_read(
                pDevHandle, &pBuffer[PH_PROTO_7816_HEADER_LEN], (nNbBytesToRead + PH_PROTO_7816_CRC_LEN));
            if (ret < 0) {
                T_SMLOG_D("_i2c_read() ret : %X", ret);
                ret = -1;
            }
            else {
                ret = (total_count + (nNbBytesToRead + PH_PROTO_7816_CRC_LEN));
            }
            break;
        }
        /*If it is Chained packet wait for 1 ms*/
        if (poll_sof_chained_delay == 1) {
            T_SMLOG_D("%s Chained Pkt, delay read %dms", __FUNCTION__, ESE_POLL_DELAY_MS * CHAINED_PKT_SCALER);
            sm_sleep(ESE_POLL_DELAY_MS);
        }
        else {
            T_SMLOG_D("%s Normal Pkt, delay read %dms", __FUNCTION__, ESE_POLL_DELAY_MS * NAD_POLLING_SCALER);
            sm_sleep(ESE_POLL_DELAY_MS);
        }
    } while ((sof_counter < ESE_NAD_POLLING_MAX) && (nxpese_ctxt->EseLibStatus != ESE_STATUS_CLOSE));
    if ((pBuffer[0] == RECIEVE_PACKET_SOF) && (ret > 0)) {
        T_SMLOG_D("%s SOF FOUND", __FUNCTION__);
        /* Read the HEADR of one/Two bytes based on how two bytes read A5 PCB or 00 A5*/
        ret = phPalEse_i2c_read(pDevHandle, &pBuffer[1 + headerIndex], numBytesToRead);
        if (ret < 0) {
            T_SMLOG_D("_i2c_read() ret: %X", ret);
        }
        if ((pBuffer[1] == CHAINED_PACKET_WITHOUTSEQN) || (pBuffer[1] == CHAINED_PACKET_WITHSEQN)) {
            poll_sof_chained_delay = 1;
            T_SMLOG_D("poll_sof_chained_delay value is %d ", poll_sof_chained_delay);
        }
        else {
            poll_sof_chained_delay = 0;
            T_SMLOG_D("poll_sof_chained_delay value is %d ", poll_sof_chained_delay);
        }
#if defined(T1oI2C_UM11225)
        total_count    = 3;
        nNbBytesToRead = pBuffer[2];
#elif defined(T1oI2C_GP1_0)
        total_count    = 4;
        nNbBytesToRead = (pBuffer[2] << 8 & 0xFF00) | (pBuffer[3] & 0xFF);
#endif
        /* Read the Complete data + two byte CRC*/
        ret =
            phPalEse_i2c_read(pDevHandle, &pBuffer[PH_PROTO_7816_HEADER_LEN], (nNbBytesToRead + PH_PROTO_7816_CRC_LEN));
        if (ret < 0) {
            T_SMLOG_D("_i2c_read() ret : %X", ret);
            ret = -1;
        }
        else {
            ret = (total_count + (nNbBytesToRead + PH_PROTO_7816_CRC_LEN));
        }
    }
    else {
        ret = -1;
    }
exit:
    return ret;
}
/******************************************************************************
 * Function         phNxpEse_WriteFrame
 *
 * Description      This function writes the data to ESE.
 *                  It waits till write callback provide the result of write
 *                  process.
 *
 * param[in]        void*: connection context
 * param[in]        uint32_t: number of bytes to be written
 * param[in]        uint8_t : data buffer
 *
 * Returns          It returns ESESTATUS_SUCCESS (0) if write successful else
 *                  ESESTATUS_FAILED(1)
 *
 ******************************************************************************/
ESESTATUS phNxpEse_WriteFrame(void *conn_ctx, uint32_t data_len, const uint8_t *p_data)
{
    ESESTATUS status                = ESESTATUS_INVALID_PARAMETER;
    int32_t dwNoBytesWrRd           = 0;
    phNxpEse_Context_t *nxpese_ctxt = (conn_ctx == NULL) ? &gnxpese_ctxt : (phNxpEse_Context_t *)conn_ctx;

    /* Create local copy of cmd_data */
    T_SMLOG_D("%s Enter ..", __FUNCTION__);

    if (data_len > MAX_APDU_BUFFER) {
        return ESESTATUS_FAILED;
    }

    //phNxpEse_memcpy(nxpese_ctxt->p_cmd_data, p_data, data_len);
    //nxpese_ctxt->cmd_len = data_len;

    if (nxpese_ctxt->EseLibStatus != ESE_STATUS_CLOSE) {
        dwNoBytesWrRd = phPalEse_i2c_write(nxpese_ctxt->pDevHandle,
            /*nxpese_ctxt->p_cmd_data*/ (uint8_t *)p_data,
            /*nxpese_ctxt->cmd_len*/ data_len);
        if (-1 == dwNoBytesWrRd) {
            T_SMLOG_E(" - Error in I2C Write.....");
            status = ESESTATUS_FAILED;
        }
        else if (-2 == dwNoBytesWrRd) {
            status = ESESTATUS_INVALID_STATE;
        }
        else {
            status = ESESTATUS_SUCCESS;
            //T_SMLOG_MAU8_D("RAW Tx>", nxpese_ctxt->p_cmd_data, nxpese_ctxt->cmd_len);
            T_SMLOG_MAU8_D("RAW Tx>", p_data, data_len);
        }
    }
    else
        status = ESESTATUS_INVALID_STATE;
    return status;
}

/******************************************************************************
 * Function         phNxpEse_setIfsc
 *
 * Description      This function sets the IFSC size to 240/254 support JCOP OS Update.
 *
 * param[in]        uint16_t IFSC_Size
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
ESESTATUS phNxpEse_setIfsc(uint16_t IFSC_Size)
{
    /*SET the IFSC size to 240 bytes*/
    phNxpEseProto7816_SetIfscSize(IFSC_Size);
    return ESESTATUS_SUCCESS;
}

/******************************************************************************
 * Function         phNxpEse_memset
 *
 * Description      This function updates destination buffer with val
 *                  data in len size
 *
 * param[in]        buff - Array to be udpated
 * param[in]        val  - value to be updated
 * param[in]        len  - length of array to be updated
 *
 * Returns          Always return ESESTATUS_SUCCESS (0).
 *
 ******************************************************************************/
void *phNxpEse_memset(void *buff, int val, size_t len)
{
    return memset(buff, val, len);
}

/******************************************************************************
 * Function         phNxpEse_memcpy
 *
 * Description      This function copies source buffer to  destination buffer
 *                  data in len size
 *
 * param[in]        dest - Destination array to be updated
 * param[in]        src  - Source array to be updated
 * param[in]        len  - length of array to be updated
 *
 * Returns          Return pointer to allocated memory location.
 *
 ******************************************************************************/
void *phNxpEse_memcpy(void *dest, const void *src, size_t len)
{
    return memcpy(dest, src, len);
}

/******************************************************************************
 * Function         phNxpEse_Memalloc
 *
 * Description      This function allocation memory
 *
 * param[in]        uint32_t size
 *
 * Returns          Return pointer to allocated memory or NULL.
 *
 ******************************************************************************/
void *phNxpEse_memalloc(uint32_t size)
{
    return sm_malloc(size);
}

/******************************************************************************
 * Function         phNxpEse_free
 *
 * Description      This function de-allocation memory
 *
 * param[in]        ptr - Address pointer to previous allocation
 *
 * Returns          void.
 *
 ******************************************************************************/
void phNxpEse_free(void *ptr)
{
    ENSURE_OR_GO_EXIT(ptr != NULL);
    sm_free(ptr);
exit:
    return;
}

#if defined(T1oI2C_UM11225)
/******************************************************************************
 * Function         phNxpEse_getAtr
 *
 * Description      This function get ATR from ESE.
 *
 * param[out]       phNxpEse_data: Response from ESE
 *
 * Returns          On Success ESESTATUS_SUCCESS else ESESTATUS_FAILED.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_getAtr(void *conn_ctx, phNxpEse_data *pRsp)
{
    bool_t status = FALSE;
    status        = phNxpEseProto7816_GetAtr(conn_ctx, pRsp);
    if (status == FALSE) {
        T_SMLOG_E("%s Get ATR Failed ", __FUNCTION__);
        return ESESTATUS_FAILED;
    }
    return ESESTATUS_SUCCESS;
}
#endif

#if defined(T1oI2C_GP1_0)
/******************************************************************************
 * Function         phNxpEse_getCip
 *
 * Description      This function get CIP from ESE.
 *
 * param[out]       phNxpEse_data: Response from ESE
 *
 * Returns          On Success ESESTATUS_SUCCESS else ESESTATUS_FAILED.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_getCip(void *conn_ctx, phNxpEse_data *pRsp)
{
    bool_t status = FALSE;
    status        = phNxpEseProto7816_GetCip(conn_ctx, pRsp);
    if (status == FALSE) {
        T_SMLOG_E("%s Get CIP Failed ", __FUNCTION__);
        return ESESTATUS_FAILED;
    }
    return ESESTATUS_SUCCESS;
}
#endif

/******************************************************************************
 * Function         phNxpEse_deepPwrDown
 *
 * Description      This function is used to send deep power down command
 *
 * param[out]
 *
 * Returns          On Success ESESTATUS_SUCCESS else ESESTATUS_FAILED.
 *
 ******************************************************************************/
ESESTATUS phNxpEse_deepPwrDown(void *conn_ctx)
{
    bool_t status = FALSE;
    status        = phNxpEseProto7816_Deep_Pwr_Down(conn_ctx);
    if (status == FALSE) {
        T_SMLOG_E("%s Deep Pwr Down Failed ", __FUNCTION__);
        return ESESTATUS_FAILED;
    }
    return ESESTATUS_SUCCESS;
}
