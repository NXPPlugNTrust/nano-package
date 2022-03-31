/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_sign(void);

void main(void)
{
    printf("Se05x Sign Example !\n");
    if (ex_se05x_sign() != 0) {
        printf("SE05x Sign Example Failed !\n");
    }
    else {
        printf("SE05x Sign Example Success ! \n");
    }
    return;
}