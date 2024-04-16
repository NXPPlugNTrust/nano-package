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
extern int ex_se05x_mandate_scp03();

int main(void)
{
    printk("Se05x Mandate SCP03 Example ! %s\n", CONFIG_BOARD);
    if (ex_se05x_mandate_scp03() != 0) {
        printk("SE05x Mandate SCP03 Example Failed !\n");
    }
    else {
        printk("SE05x Mandate SCP03 Example Success ! \n");
    }
    return 0;
}
