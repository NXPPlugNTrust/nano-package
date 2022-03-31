/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>

/* ********************** Extern functions ********************** */
extern int ex_establish_scp03(void);
extern int ex_resume_scp03(void);

void main(void)
{
    printf("SE05x SCP03 Establish !\n");
    if (ex_establish_scp03() != 0) {
        printf("SE05x SCP03 Establish Failed !\n");
    }
    else {
        printf("SE05x SCP03 Establish Success ! \n");
    }
    return;
}