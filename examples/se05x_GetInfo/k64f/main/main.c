/** @file main.c
 *  @brief .
 *
 * Copyright 2021-2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_GetInfo();
extern void platformInit();

int main()
{
    platformInit();
    if (ex_se05x_GetInfo() != 0) {
        printf("SE05x GetInfo Example Failed !\n");
    }
    else {
        printf("SE05x GetInfo Example Success ! \n");
    }
    return 0;
}
