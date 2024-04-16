/** @file main.c
 *  @brief .
 *
 * Copyright 2023,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_GetInfo(void);

int main(void)
{
    printk("Se05x GetInfo Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_GetInfo() != 0) {
        printk("SE05x GetInfo Example Failed !\n");
    }
    else {
        printk("SE05x GetInfo Example Success ! \n");
    }
    return 0;
}
