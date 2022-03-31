/** @file main.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr.h>
#include <sys/printk.h>

/* ********************** Extern functions ********************** */
extern void test_se05x(uint8_t *pass, uint8_t *fail, uint8_t *ignore);

void main()
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    printk("Starting se05x unit tests \n");
    test_se05x(&pass, &fail, &ignore);
    printk("*** Test Complete *** \n");
    printk("Result - \n");
    printk("Pass = %d \n", pass);
    printk("Fail = %d \n", fail);
    printk("Ignore = %d \n", ignore);
    return;
}