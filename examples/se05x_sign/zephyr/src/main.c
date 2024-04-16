/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_sign(void);

int main(void)
{
    printk("Se05x Sign Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_sign() != 0) {
        printk("SE05x Sign Example Failed !\n");
    }
    else {
        printk("SE05x Sign Example Success ! \n");
    }
    return 0;
}
