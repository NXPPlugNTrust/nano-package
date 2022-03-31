/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr.h>
#include <sys/printk.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_crypto();

void main(void)
{
    printk("Se05x Crypto Example ! %s\n", CONFIG_BOARD);
    ex_se05x_crypto();
    return;
}
