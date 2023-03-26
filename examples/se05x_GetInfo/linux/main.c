/** @file main.c
 *  @brief .
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_GetInfo(void);

void main(void)
{
    printf("Se05x Getinfo Example !\n");
    if (ex_se05x_GetInfo() != 0) {
        printf("SE05x Getinfo Example Failed !\n");
    }
    else {
        printf("SE05x Getinfo Example Success ! \n");
    }
    return;
}