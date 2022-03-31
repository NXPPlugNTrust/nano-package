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
extern int ex_se05x_rotate_scp03_keys();

void main(void)
{
    printk("Se05x Rotate SCP03 keys Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_rotate_scp03_keys() != 0) {
        printk("SE05x Rotate SCP03 keys Example Failed !\n");
    }
    else {
        printk("SE05x Rotate SCP03 keys Example Success ! \n");
    }
    return;
}
