/** @file main.c
 *  @brief .
 *
 * Copyright 2021-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include "fsl_debug_console.h"

/* ********************** Extern functions ********************** */
extern int ex_se05x_mandate_scp03();
extern void platformInit();

int main()
{
    platformInit();
    if (ex_se05x_mandate_scp03() != 0) {
        PRINTF("SE05x Mandate SCP Example Failed !\r\n");
    }
    else {
        PRINTF("SE05x Mandate SCP Example Success ! \r\n");
    }
    return 0;
}
