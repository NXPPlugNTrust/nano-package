/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include "se05x_tlv.h"
#include "se05x_APDU_apis.h"
#include "sa_qi_port.h"

/* ********************** Extern functions ********************** */
extern int ex_qi_entry(void);

Se05xSession_t se05x_session      = {0};
pSe05xSession_t pgSe05xSessionctx = &se05x_session;

int main(void)
{
    smStatus_t status = SM_NOT_OK;
    printk("Se05x Qi Auth Example ! %s\n", CONFIG_BOARD);

    status = Se05x_API_SessionOpen(&se05x_session);
    if (status != SM_OK) {
        LOG_E("Error in Se05x_API_SessionOpen");
        return 0;
    }

    if (ex_qi_entry() != 0) {
        printk("SE05x Qi Auth Example Failed !\n");
    }
    else {
        printk("SE05x Qi Auth Example Success ! \n");
    }

    status = Se05x_API_SessionClose(&se05x_session);
    if (status != SM_OK) {
        LOG_E("Error in Se05x_API_SessionClose");
        return 0;
    }

    return 0;
}
