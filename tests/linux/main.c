/** @file main.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include <stdint.h>

/* ********************** Extern functions ********************** */
extern void test_se05x(uint8_t *pass, uint8_t *fail, uint8_t *ignore);

void main()
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x(&pass, &fail, &ignore);
    printf("*** Test Complete *** \n");
    printf("Result - \n");
    printf("Pass = %d \n", pass);
    printf("Fail = %d \n", fail);
    printf("Ignore = %d \n", ignore);
    return;
}