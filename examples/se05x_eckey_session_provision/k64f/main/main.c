/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int se05x_eckey_session_provision();
extern void platformInit();

int main()
{
    platformInit();
    if (se05x_eckey_session_provision() != 0) {
        printf("se05x_eckey_session_provision Failed !\n");
    }
    else {
        printf("se05x_eckey_session_provision Success ! \n");
    }
    return 0;
}
