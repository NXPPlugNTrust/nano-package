/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include "fsl_debug_console.h"

/* ********************** Extern functions ********************** */
extern int se05x_eckey_session_provision();
extern void platformInit();

int main()
{
    platformInit();
    if (se05x_eckey_session_provision() != 0) {
        PRINTF("SE05x EC-Key Provision Example Failed !\r\n");
    }
    else {
        PRINTF("SE05x EC-Key Provision Example Success ! \r\n");
    }
    return 0;
}
