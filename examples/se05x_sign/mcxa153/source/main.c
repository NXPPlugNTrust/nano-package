/** @file main.c
 *  @brief .
 *
 * Copyright 2021-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include "fsl_debug_console.h"

/* ********************** Extern functions ********************** */
extern int ex_se05x_sign();
extern void platformInit();

int main()
{
    platformInit();
    if (ex_se05x_sign() != 0) {
        PRINTF("SE05x Sign Example Failed !\n");
    }
    else {
        PRINTF("SE05x Sign Example Success ! \n");
    }
    return 0;
}
