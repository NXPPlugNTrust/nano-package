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
extern int ex_se05x_rotate_scp03_keys();

int main(void)
{
    printk("Se05x Rotate SCP03 keys Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_rotate_scp03_keys() != 0) {
        printk("SE05x Rotate SCP03 keys Example Failed !\n");
    }
    else {
        printk("SE05x Rotate SCP03 keys Example Success ! \n");
    }
    return 0;
}
