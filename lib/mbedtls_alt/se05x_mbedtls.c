/*
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

#include "se05x_mbedtls.h"
#include <sm_port.h>
#include "se05x_APDU_apis.h"

Se05xSession_t pSession;

smStatus_t se05x_open_session(void)
{
    if (pSession.conn_context != NULL) {
        return SM_OK;
    }

    SMLOG_I("Open Session to SE05x \n");
    smStatus_t status = Se05x_API_SessionOpen(&pSession);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionOpen \n");
    }
    return status;
}

smStatus_t se05x_close_session(void)
{
    if (pSession.conn_context == NULL) {
        return SM_OK;
    }

    SMLOG_I("Close Session to SE05x \n");
    smStatus_t status = Se05x_API_SessionClose(&pSession);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_SessionClose \n");
    }
    memset(&pSession, 0, sizeof(Se05xSession_t));
    return status;
}
