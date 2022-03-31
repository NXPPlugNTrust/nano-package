/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_rotate_scp03_keys();

int main()
{
    if (ex_se05x_rotate_scp03_keys() != 0) {
        printf("SE05x Rotate SCP03 keys Example Failed !\n");
    }
    else {
        printf("SE05x Rotate SCP03 keys Example Success ! \n");
    }
    return 0;
}