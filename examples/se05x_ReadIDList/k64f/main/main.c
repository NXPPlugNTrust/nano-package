/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_ReadIDList();
extern void platformInit();

int main()
{
    platformInit();
    if (ex_se05x_ReadIDList() != 0) {
        printf("SE05x Read IDList Example Failed !\n");
    }
    else {
        printf("SE05x Read IDList Example Success ! \n");
    }
    return 0;
}
