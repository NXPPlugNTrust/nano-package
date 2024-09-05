/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int se05x_eckey_session_provision(void);

void main(void)
{
    printf("SE05x EC-Key Provision Example !\n");
    if (se05x_eckey_session_provision() != 0) {
        printf("SE05x EC-Key Provision Example Failed !\n");
    }
    else {
        printf("SE05x EC-Key Provision Example Success ! \n");
    }
    return;
}