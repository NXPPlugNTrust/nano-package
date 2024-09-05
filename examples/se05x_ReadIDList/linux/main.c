/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_ReadIDList(void);

void main(void)
{
    printf("Se05x ReadIDList Example !\n");
    if (ex_se05x_ReadIDList() != 0) {
        printf("SE05x ReadIDList Example Failed !\n");
    }
    else {
        printf("SE05x ReadIDList Example Success ! \n");
    }
    return;
}