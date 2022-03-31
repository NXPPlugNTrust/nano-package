/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_mandate_scp03();

int main()
{
    if (ex_se05x_mandate_scp03() != 0) {
        printf("SE05x Mandate SCP03 Example Failed !\n");
    }
    else {
        printf("SE05x Mandate SCP03 Example Success ! \n");
    }

    return 0;
}