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
    printf("SE05x SCP03 Resume Example !\n");
    if (ex_resume_scp03() != 0) {
        printf("SE05x SCP03 Resume Failed !\n");
    }
    else {
        printf("SE05x SCP03 Resume Success ! \n");
    }
    return;
}