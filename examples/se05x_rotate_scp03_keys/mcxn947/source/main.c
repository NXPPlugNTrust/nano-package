/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include "fsl_debug_console.h"

/* ********************** Extern functions ********************** */
extern int ex_se05x_rotate_scp03_keys();
extern void platformInit();

int main()
{
    platformInit();
    if (ex_se05x_rotate_scp03_keys() != 0) {
    	PRINTF("SE05x Rotate SCP03 keys Example Failed !\r\n");
    }
    else {
    	PRINTF("SE05x Rotate SCP03 keys Example Success ! \r\n");
    }
    return 0;
}
