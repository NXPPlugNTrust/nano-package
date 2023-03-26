/** @file main.c
 *  @brief .
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr.h>
#include <sys/printk.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_GetInfo(void);

void main(void)
{
    printk("Se05x GetInfo Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_GetInfo() != 0) {
        printk("SE05x GetInfo Example Failed !\n");
    }
    else {
        printk("SE05x GetInfo Example Success ! \n");
    }
    return;
}
